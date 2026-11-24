use incognifile::{router, AppState};
use std::sync::Arc;

#[tokio::test]
async fn unavailable_database_never_grants_access() {
    std::env::set_var("APP_ORIGIN", "http://127.0.0.1:8080");
    let pool = incognifile::db::connect("sqlite::memory:").await.unwrap();
    pool.close().await;
    let app = router(Arc::new(AppState::new(pool).unwrap()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/secrets/1/read");
    let no_session = client.post(&url).send().await.unwrap();
    assert_eq!(no_session.status(), 401);
    let with_session = client
        .post(&url)
        .bearer_auth("x".repeat(43))
        .send()
        .await
        .unwrap();
    assert_eq!(with_session.status(), 503);
    assert!(!with_session.text().await.unwrap().contains("ciphertext"));
    handle.abort();
}
