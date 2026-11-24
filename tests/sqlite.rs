use incognifile::db;

#[tokio::test]
async fn foreign_keys_are_enforced_and_deleted_ids_are_not_reused() {
    let pool = db::connect("sqlite::memory:").await.unwrap();
    let invalid_session = sqlx::query(
        "INSERT INTO sessions (token_hash,user_id,expires_at) VALUES ('fake',999,unixepoch()+60)",
    )
    .execute(&pool)
    .await;
    assert!(invalid_session
        .unwrap_err()
        .as_database_error()
        .unwrap()
        .is_foreign_key_violation());

    let owner = sqlx::query_scalar::<_, i64>(
        "INSERT INTO users (email,password_hash) VALUES ('owner@example.com','test-only') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let insert = "INSERT INTO secrets (owner_id,ciphertext,nonce,expires_at)
                  VALUES ($1,'test-only','test-only',unixepoch()+60) RETURNING id";
    let first = sqlx::query_scalar::<_, i64>(insert)
        .bind(owner)
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM secrets WHERE id=$1")
        .bind(first)
        .execute(&pool)
        .await
        .unwrap();
    let second = sqlx::query_scalar::<_, i64>(insert)
        .bind(owner)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        second > first,
        "An old secret ID must not point to a new secret"
    );
}
