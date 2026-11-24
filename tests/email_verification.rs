use incognifile::{db, router, AppState};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Arc;

async fn serve(pool: sqlx::SqlitePool) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = router(Arc::new(AppState::new(pool).unwrap()));
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), handle)
}
async fn post(client: &Client, base: &str, path: &str, body: Value) -> reqwest::Response {
    client
        .post(format!("{base}/api/{path}"))
        .json(&body)
        .send()
        .await
        .unwrap()
}
async fn token(directory: &std::path::Path, id: i64) -> String {
    tokio::fs::read_to_string(directory.join(format!("{id}.eml")))
        .await
        .unwrap()
        .split("#verify=")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn verification_expiry_replay_resend_and_both_flag_modes() {
    // One test owns its environment; integration test files run in separate processes.
    let directory =
        std::env::temp_dir().join(format!("incognifile-mail-{}", rand::random::<u64>()));
    std::env::set_var("APP_ORIGIN", "http://localhost:8080");
    std::env::set_var("MAIL_DELIVERY", "local");
    std::env::set_var("MAIL_OUTBOX_DIR", &directory);
    std::env::set_var("REQUIRE_EMAIL_VERIFICATION", "true");
    let pool = db::connect("sqlite::memory:").await.unwrap();
    let (base, handle) = serve(pool.clone()).await;
    let client = Client::new();
    let credentials = json!({"email":" Alice+demo@Example.com ","password":"Test-password-47"});
    let registration = post(&client, &base, "register", credentials.clone()).await;
    assert_eq!(registration.status(), 200);
    let registration: Value = registration.json().await.unwrap();
    assert_eq!(registration["verification_required"], true);
    assert!(registration.get("token").is_none());
    let id = registration["user_id"].as_i64().unwrap();
    let first = token(&directory, id).await;
    let stored: String =
        sqlx::query_scalar("SELECT token_hash FROM email_verifications WHERE user_id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_ne!(stored, first);
    assert_eq!(
        post(&client, &base, "login", credentials.clone())
            .await
            .status(),
        403
    );
    assert_eq!(
        post(
            &client,
            &base,
            "verify-email",
            json!({"token":"x".repeat(43)})
        )
        .await
        .status(),
        400
    );
    assert_eq!(
        post(&client, &base, "resend-verification", credentials.clone())
            .await
            .status(),
        200
    );
    let second = token(&directory, id).await;
    assert_ne!(first, second);
    assert_eq!(
        post(&client, &base, "verify-email", json!({"token":first}))
            .await
            .status(),
        400
    );
    sqlx::query("UPDATE email_verifications SET expires_at=unixepoch()-1")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        post(&client, &base, "verify-email", json!({"token":second}))
            .await
            .status(),
        400
    );
    assert_eq!(
        post(&client, &base, "resend-verification", credentials.clone())
            .await
            .status(),
        200
    );
    let third = token(&directory, id).await;
    let (a, b) = tokio::join!(
        post(&client, &base, "verify-email", json!({"token":third})),
        post(&client, &base, "verify-email", json!({"token":third}))
    );
    let mut codes = [a.status().as_u16(), b.status().as_u16()];
    codes.sort();
    assert_eq!(codes, [200, 400]);
    let login = post(&client, &base, "login", credentials.clone()).await;
    assert_eq!(login.status(), 200);
    let session: Value = login.json().await.unwrap();
    sqlx::query("UPDATE users SET email_verified=0 WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        client
            .get(format!("{base}/api/secrets"))
            .bearer_auth(session["token"].as_str().unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(post(&client,&base,"register",json!({"email":"b@example.com","password":"Test-password-47","verification_required":false})).await.status(),422);
    assert_eq!(
        client
            .get(format!("{base}/.mail/{id}.eml"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    handle.abort();

    std::env::set_var("REQUIRE_EMAIL_VERIFICATION", "false");
    let (base, handle) = serve(pool.clone()).await;
    let credentials = json!({"email":"bob@example.com","password":"Test-password-47"});
    let registration: Value = post(&client, &base, "register", credentials.clone())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(registration["verification_required"], false);
    assert_eq!(
        post(&client, &base, "login", credentials).await.status(),
        200
    );
    handle.abort();

    std::env::set_var("REQUIRE_EMAIL_VERIFICATION", "true");
    // Delivery failure leaves the account unverified and cannot grant access.
    let bad_path = directory.join("not-a-directory");
    tokio::fs::write(&bad_path, "test").await.unwrap();
    std::env::set_var("MAIL_OUTBOX_DIR", &bad_path);
    let (base, handle) = serve(pool.clone()).await;
    let credentials = json!({"email":"failure@example.com","password":"Test-password-47"});
    assert_eq!(
        post(&client, &base, "register", credentials.clone())
            .await
            .status(),
        503
    );
    assert_eq!(
        post(&client, &base, "login", credentials).await.status(),
        403
    );
    handle.abort();
    std::env::set_var("APP_ORIGIN", "https://public.example.com");
    assert!(
        AppState::new(pool.clone()).is_err(),
        "Public local-outbox verification must fail closed"
    );
    std::env::set_var("REQUIRE_EMAIL_VERIFICATION", "typo");
    assert!(AppState::new(pool.clone()).is_err());
    pool.close().await;
    tokio::fs::remove_dir_all(directory).await.unwrap();
}
