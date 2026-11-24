use incognifile::{db, router, AppState};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    tracing_subscriber::fmt()
        .with_env_filter("incognifile=info")
        .init();

    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:incognifile.db".into());
    let pool = db::connect(&url).await?;
    let state = Arc::new(AppState::new(pool)?);
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;

    tracing::info!(%port, "IncogniFile started");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
