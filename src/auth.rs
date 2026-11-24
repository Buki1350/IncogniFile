use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};

//
// login, registration and email verification handlers
//

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Credentials {
    email: String,
    password: String,
}

// validate email and password, return normalized email
fn validate_credentials(p: &Credentials) -> Result<String, ApiError> {
    let name = p.email.trim().to_ascii_lowercase();
    validation::validate_email(&name).map_err(|m| error(StatusCode::BAD_REQUEST, m))?;
    validation::validate_password_strength(&p.password)
        .map_err(|m| error(StatusCode::BAD_REQUEST, &m))?;
    Ok(name)
}

pub(crate) async fn register(State(s): State<Shared>, Json(p): Json<Credentials>) -> ApiResult {
    if !s.limiter.allow("", true) {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "Registration limit: retry after 15 minutes",
        ));
    }

    let name = validate_credentials(&p)?;

    let permit = s
        .password_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::TOO_MANY_REQUESTS, "Authentication busy"))?;

    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        password::PasswordService::hash_password(&p.password)
    })
    .await
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Password service unavailable",
        )
    })?
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Password service unavailable",
        )
    })?;

    let row = sqlx::query_scalar::<_, i64>(
        "INSERT INTO users (email,password_hash) VALUES ($1,$2) RETURNING id",
    )
    .bind(&name)
    .bind(hash)
    .fetch_one(&s.pool)
    .await;

    match row {
        Ok(user_id) => {
            if s.require_verification {
                send_verification(&s, user_id, &name).await?;
            }
            Ok(Json(
                serde_json::json!({"message": if s.require_verification { "Konto utworzone. Potwierdź adres linkiem z wiadomości weryfikacyjnej." } else { "Konto utworzone. Możesz się zalogować." }, "user_id":user_id,"verification_required":s.require_verification}),
            ))
        }
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => Err(error(
            StatusCode::CONFLICT,
            "Ten adres e-mail jest już zajęty.",
        )),
        Err(e) => Err(unavailable(e)),
    }
}

async fn check_credentials(s: &AppState, p: Credentials) -> Result<(i64, bool), ApiError> {
    let name = p.email.trim().to_ascii_lowercase();

    if !s.limiter.allow(&name, false) {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "Login limit: retry after 15 minutes",
        ));
    }

    let name = validate_credentials(&p)?;
    let row = sqlx::query_as::<_, (i64, String, bool)>(
        "SELECT id,password_hash,email_verified FROM users WHERE email=$1",
    )
    .bind(name)
    .fetch_optional(&s.pool)
    .await
    .map_err(unavailable)?;
    let hash = row
        .as_ref()
        .map(|r| r.1.clone())
        .unwrap_or_else(|| s.dummy_hash.clone());
    let permit = s
        .password_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::TOO_MANY_REQUESTS, "Authentication busy"))?;
    let ok = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        password::PasswordService::verify_password(&p.password, &hash).unwrap_or(false)
    })
    .await
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Password service unavailable",
        )
    })?;
    let Some((user_id, _, verified)) = row.filter(|_| ok) else {
        return Err(error(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    };
    Ok((user_id, verified))
}

pub(crate) async fn login(State(s): State<Shared>, Json(p): Json<Credentials>) -> ApiResult {
    let (user_id, verified) = check_credentials(&s, p).await?;
    if s.require_verification && !verified {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"message":"Potwierdź adres e-mail przed zalogowaniem.","verification_required":true}),
            ),
        ));
    }
    sqlx::query("DELETE FROM sessions WHERE expires_at <= unixepoch()")
        .execute(&s.pool)
        .await
        .map_err(unavailable)?;
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let token = URL_SAFE_NO_PAD.encode(random);
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, expires_at)
         VALUES ($1, $2, unixepoch() + 3600)",
    )
    .bind(token_hash(&token))
    .bind(user_id)
    .execute(&s.pool)
    .await
    .map_err(unavailable)?;
    Ok(Json(serde_json::json!({"token":token,"user_id":user_id})))
}

fn token(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|t| t.len() == 43)
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "Missing or invalid session"))
}

fn token_hash(t: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(t.as_bytes()))
}
pub(crate) async fn authenticate(s: &AppState, h: &HeaderMap) -> Result<i64, ApiError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT s.user_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>unixepoch() AND ($2=0 OR u.email_verified=1)",
    )
    .bind(token_hash(token(h)?))
    .bind(s.require_verification)
    .fetch_optional(&s.pool)
    .await
    .map_err(unavailable)?
    .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "Invalid or expired session"))
}
pub(crate) async fn logout(State(s): State<Shared>, h: HeaderMap) -> ApiResult {
    authenticate(&s, &h).await?;
    sqlx::query("DELETE FROM sessions WHERE token_hash=$1")
        .bind(token_hash(token(&h)?))
        .execute(&s.pool)
        .await
        .map_err(unavailable)?;
    Ok(Json(serde_json::json!({"message":"Logged out"})))
}

async fn send_verification(s: &AppState, user_id: i64, email: &str) -> Result<(), ApiError> {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);

    let token = URL_SAFE_NO_PAD.encode(bytes);
    sqlx::query("INSERT INTO email_verifications (token_hash,user_id,expires_at) VALUES ($1,$2,unixepoch()+1800) ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,expires_at=excluded.expires_at")
        .bind(token_hash(&token)).bind(user_id).execute(&s.pool).await.map_err(unavailable)?;

    let mailer = s.mailer.as_ref().ok_or_else(|| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Weryfikacja e-mail nie jest skonfigurowana.",
        )
    })?;
    mailer.send(user_id,email,&format!("{}/#verify={token}",s.origin)).await.map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE,"Konto istnieje, ale nie udało się wysłać linku. Spróbuj przycisku „Wyślij ponownie link”."))
}

pub(crate) async fn resend_verification(
    State(s): State<Shared>,
    Json(p): Json<Credentials>,
) -> ApiResult {
    if !s.require_verification {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Weryfikacja e-mail jest wyłączona.",
        ));
    }
    let email = p.email.trim().to_ascii_lowercase();
    let (id, verified) = check_credentials(&s, p).await?;
    if !verified {
        send_verification(&s, id, &email).await?;
    }
    Ok(Json(
        serde_json::json!({"message":"Jeśli adres wymaga potwierdzenia, przygotowano nowy link. Poprzedni link jest nieważny."}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifyRequest {
    token: String,
}
pub(crate) async fn verify_email(
    State(s): State<Shared>,
    Json(p): Json<VerifyRequest>,
) -> ApiResult {
    if p.token.len() != 43 {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Nieprawidłowy lub wygasły link.",
        ));
    }
    let mut tx = s
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(unavailable)?;
    let user = sqlx::query_scalar::<_,i64>("DELETE FROM email_verifications WHERE token_hash=$1 AND expires_at>unixepoch() RETURNING user_id")
        .bind(token_hash(&p.token)).fetch_optional(&mut *tx).await.map_err(unavailable)?;
    let Some(id) = user else {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Nieprawidłowy, wygasły lub wykorzystany link.",
        ));
    };
    sqlx::query("UPDATE users SET email_verified=1 WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(
        serde_json::json!({"message":"Adres e-mail potwierdzony. Możesz się zalogować."}),
    ))
}
