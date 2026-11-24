use super::*;
use crate::auth::authenticate;
use axum::extract::Path;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewMessage {
    encoded_text: String,
    additional_encryption: String,
    recipient: Option<String>,
    expiration_time_sec: i64,
    single_use: bool,
}

fn validate_encrypted_message(p: &NewMessage) -> Result<(), ApiError> {
    if !(60..=604800).contains(&p.expiration_time_sec) || p.encoded_text.len() > 1_000_000 {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Expiration time must be 60–604800 seconds; text limit 1000000 bytes",
        ));
    }

    if STANDARD.decode(&p.additional_encryption).map(|v| v.len()).ok() != Some(12)
        || !STANDARD.decode(&p.encoded_text).is_ok_and(|v| v.len() >= 16)
    {
        return Err(error(StatusCode::BAD_REQUEST, "Invalid AES-GCM envelope"));
    }
    Ok(())
}

pub(crate) async fn save_message(
    State(s): State<Shared>,
    h: HeaderMap,
    Json(p): Json<NewMessage>,
) -> ApiResult {
    let user = authenticate(&s, &h).await?;

    validate_encrypted_message(&p)?;

    let recipient = match p.recipient.filter(|s| !s.trim().is_empty()) {
        None => None,
        Some(name) => {
            let name = name.trim().to_ascii_lowercase();
            validation::validate_email(&name).map_err(|m| error(StatusCode::BAD_REQUEST, m))?;
            Some(
                sqlx::query_scalar::<_, i64>("SELECT id FROM users WHERE email=$1")
                    .bind(name)
                    .fetch_optional(&s.pool)
                    .await
                    .map_err(unavailable)?
                    .ok_or_else(|| error(StatusCode::BAD_REQUEST, "Recipient unavailable"))?,
            )
        }
    };

    // lock before checking quota, to avoid timing attacks
    let mut tx = s
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(unavailable)?;
    sqlx::query("DELETE FROM secrets WHERE expires_at<=unixepoch()")
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM secrets WHERE owner_id=$1")
        .bind(user)
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
    let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM secrets")
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
    if count >= 20 || total >= 200 {
        return Err(error(StatusCode::CONFLICT, "Demo storage quota reached"));
    }
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO secrets (owner_id, recipient_id, ciphertext, nonce, expires_at, one_time)
         VALUES ($1, $2, $3, $4, unixepoch() + $5, $6)
         RETURNING id",
    )
    .bind(user)
    .bind(recipient)
    .bind(p.encoded_text)
    .bind(p.additional_encryption)
    .bind(p.expiration_time_sec)
    .bind(p.single_use)
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(serde_json::json!({"id":id})))
}

#[derive(Serialize, sqlx::FromRow)]
struct Summary {
    id: i64,
    owner_id: i64,
    recipient_id: Option<i64>,
    owner_email: String,
    recipient_email: Option<String>,
    expires_at: String,
    single_use: bool,
}

pub(crate) async fn get_avaliable_messages(State(s): State<Shared>, h: HeaderMap) -> ApiResult {
    let user = authenticate(&s, &h).await?;
    let rows = sqlx::query_as::<_, Summary>(
        "SELECT s.id, s.owner_id, s.recipient_id, owner.email AS owner_email,
                recipient.email AS recipient_email,
                strftime('%Y-%m-%dT%H:%M:%SZ', s.expires_at, 'unixepoch') AS expires_at,
                s.one_time FROM secrets s
         JOIN users owner ON owner.id=s.owner_id
         LEFT JOIN users recipient ON recipient.id=s.recipient_id
         WHERE (s.owner_id=$1 OR s.recipient_id=$1) AND NOT s.consumed AND s.expires_at>unixepoch()
         ORDER BY s.id DESC LIMIT 200",
    )
    .bind(user)
    .fetch_all(&s.pool)
    .await
    .map_err(unavailable)?;
    Ok(Json(serde_json::json!({"secrets":rows})))
}

pub(crate) async fn read_message(State(s): State<Shared>, h: HeaderMap, Path(id): Path<i64>) -> ApiResult {
    let user = authenticate(&s, &h).await?;

    // lock before reading
    // no concurrent request can also consume this secret
    let mut tx = s
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(unavailable)?;
    let row = sqlx::query_as::<_, (String, String, bool)>(
        "SELECT ciphertext, nonce, one_time FROM secrets
         WHERE id=$1 AND (owner_id=$2 OR recipient_id=$2)
           AND NOT consumed AND expires_at>unixepoch()",
    )
    .bind(id)
    .bind(user)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    let Some((ciphertext, nonce, one_time)) = row else {
        return Err(error(StatusCode::NOT_FOUND, "Secret unavailable"));
    };
    if one_time {
        sqlx::query("UPDATE secrets SET consumed=1, ciphertext='', nonce='' WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
    }

    // do not send the message unless the transaction is committed
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(
        serde_json::json!({"ciphertext":ciphertext,"nonce":nonce}),
    ))
}

pub(crate) async fn remove_message(
    State(s): State<Shared>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    let user = authenticate(&s, &h).await?;
    let n = sqlx::query("DELETE FROM secrets WHERE id=$1 AND owner_id=$2")
        .bind(id)
        .bind(user)
        .execute(&s.pool)
        .await
        .map_err(unavailable)?;
    if n.rows_affected() == 0 {
        return Err(error(StatusCode::NOT_FOUND, "Secret unavailable"));
    }
    Ok(Json(serde_json::json!({"message":"Deleted"})))
}
