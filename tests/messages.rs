use base64::{engine::general_purpose::STANDARD, Engine};
use incognifile::{db, router, AppState};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Arc;

// Exercise the public JSON contract, not just SQL or the Rust request structs.
#[tokio::test]
async fn message_contract_listing_permissions_expiry_and_single_use() {
    std::env::set_var("APP_ORIGIN", "http://localhost:8080");
    std::env::set_var("REQUIRE_EMAIL_VERIFICATION", "false");
    let pool = db::connect("sqlite::memory:").await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router(Arc::new(AppState::new(pool.clone()).unwrap()));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = Client::new();
    let mut sessions = Vec::new();
    for email in ["alice@example.com", "bob@example.com", "eve@example.com"] {
        let credentials = json!({"email":email, "password":"Test-password-42"});
        assert_eq!(
            client
                .post(format!("{base}/api/register"))
                .json(&credentials)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        let login = client
            .post(format!("{base}/api/login"))
            .json(&credentials)
            .send()
            .await
            .unwrap();
        assert_eq!(login.status(), 200);
        let login: Value = login.json().await.unwrap();
        sessions.push(login["token"].as_str().unwrap().to_owned());
    }
    let [alice, bob, eve] = sessions.as_slice() else {
        unreachable!()
    };
    // Valid envelope shape only; actual AES round trips run in the Node tests.
    let mut payload = json!({
        "ciphertext": STANDARD.encode([7u8; 32]),
        "nonce": STANDARD.encode([3u8; 12]),
        "recipient":"bob@example.com", "ttl_seconds":3600, "one_time":true
    });
    let created = client
        .post(format!("{base}/api/secrets"))
        .bearer_auth(alice)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 200);
    let id = created.json::<Value>().await.unwrap()["id"]
        .as_i64()
        .unwrap();
    for session in [alice, bob] {
        let list = client
            .get(format!("{base}/api/secrets"))
            .bearer_auth(session)
            .send()
            .await
            .unwrap();
        assert_eq!(list.status(), 200);
        let list: Value = list.json().await.unwrap();
        let row = &list["secrets"][0];
        assert_eq!(row["id"], id);
        assert_eq!(row["one_time"], true);
        assert_eq!(row["owner_email"], "alice@example.com");
        assert_eq!(row["recipient_email"], "bob@example.com");
        assert!(row.get("ciphertext").is_none());
        assert!(row.get("single_use").is_none());
    }
    let read_url = format!("{base}/api/secrets/{id}/read");
    assert_eq!(
        client
            .post(&read_url)
            .bearer_auth(eve)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .delete(format!("{base}/api/secrets/{id}"))
            .bearer_auth(bob)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let (first, second) = tokio::join!(
        client.post(&read_url).bearer_auth(bob).send(),
        client.post(&read_url).bearer_auth(alice).send()
    );
    let mut responses = vec![first.unwrap(), second.unwrap()];
    responses.sort_by_key(|r| r.status().as_u16());
    assert_eq!(responses[0].status(), 200);
    assert_eq!(responses[1].status(), 404);
    let read: Value = responses.remove(0).json().await.unwrap();
    assert_eq!(read["ciphertext"], payload["ciphertext"]);
    assert_eq!(read["nonce"], payload["nonce"]);
    let cleared: (String, String, bool) =
        sqlx::query_as("SELECT ciphertext,nonce,consumed FROM secrets WHERE id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cleared, (String::new(), String::new(), true));

    payload["one_time"] = json!(false);
    let created = client
        .post(format!("{base}/api/secrets"))
        .bearer_auth(alice)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 200);
    let id = created.json::<Value>().await.unwrap()["id"]
        .as_i64()
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            client
                .post(format!("{base}/api/secrets/{id}/read"))
                .bearer_auth(bob)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    sqlx::query("UPDATE secrets SET expires_at=unixepoch()-1 WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        client
            .post(format!("{base}/api/secrets/{id}/read"))
            .bearer_auth(bob)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let list: Value = client
        .get(format!("{base}/api/secrets"))
        .bearer_auth(bob)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["secrets"], json!([]));
    // Reject unrecognized fields rather than silently ignoring the requested policy.
    payload["single_use"] = json!(true);
    assert_eq!(
        client
            .post(format!("{base}/api/secrets"))
            .bearer_auth(alice)
            .json(&payload)
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
    server.abort();
}
