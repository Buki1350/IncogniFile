mod auth;
pub mod config;
pub mod db;
mod verification_email;
pub mod limiter;
pub mod password;
mod messages;
pub mod validation;
use auth::{login, logout, register, resend_verification, verify_email};
use messages::{save_message, get_avaliable_messages, read_message, remove_message};

use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Semaphore;

type ApiError = (StatusCode, Json<serde_json::Value>);
type ApiResult = Result<Json<serde_json::Value>, ApiError>;
type Shared = Arc<AppState>;

pub struct AppState {
    pub pool: SqlitePool,
    limiter: limiter::Limiter,
    password_slots: Arc<Semaphore>,
    dummy_hash: String,
    origin: String,
    require_verification: bool,
    mailer: Option<verification_email::VerificationMailer>,
}

impl AppState {
    pub fn new(pool: SqlitePool) -> Result<Self, String> {
        let origin = std::env::var("APP_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".into());
        if !(origin.starts_with("https://")
            || origin.starts_with("http://localhost:")
            || origin.starts_with("http://127.0.0.1:"))
            || origin.ends_with('/')
        {
            return Err(
                "APP_ORIGIN must be an HTTPS origin (or localhost HTTP), without trailing slash"
                    .into(),
            );
        }
        let require_verification = config::verification_required()?;
        let mailer = if require_verification {
            Some(verification_email::VerificationMailer::from_env(&origin)?)
        } else {
            None
        };
        Ok(Self {
            pool,
            limiter: Default::default(),
            password_slots: Arc::new(Semaphore::new(2)),
            dummy_hash: password::PasswordService::hash_password("dummy-password-not-a-session")?,
            origin,
            require_verification,
            mailer,
        })
    }
}
fn error(status: StatusCode, message: &str) -> ApiError {
    (status, Json(serde_json::json!({"message": message})))
}
fn unavailable(e: sqlx::Error) -> ApiError {
    // Do not log query parameters, tokens, keys or ciphertext.
    tracing::warn!(kind = %e.as_database_error().map(|d| d.code().unwrap_or_default().into_owned()).unwrap_or_else(|| "connection".into()), "database operation failed");
    error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}
pub fn router(state: Shared) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    include_str!("../frontend/index.html"),
                )
            }),
        )
        .route(
            "/styles.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../frontend/styles.css"),
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript")],
                    include_str!("../frontend/app.js"),
                )
            }),
        )
        .route(
            "/crypto.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript")],
                    include_str!("../frontend/crypto.js"),
                )
            }),
        )
        .route("/health", get(health))
        .route(
            "/api/register",
            post(register).layer(DefaultBodyLimit::max(1024)),
        )
        .route("/api/login", post(login).layer(DefaultBodyLimit::max(1024)))
        .route(
            "/api/verify-email",
            post(verify_email).layer(DefaultBodyLimit::max(1024)),
        )
        .route(
            "/api/resend-verification",
            post(resend_verification).layer(DefaultBodyLimit::max(1024)),
        )
        .route("/api/logout", post(logout))
        .route("/api/secrets", get(get_avaliable_messages).post(save_message))
        .route("/api/secrets/{id}", axum::routing::delete(remove_message))
        .route("/api/secrets/{id}/read", post(read_message))
        .layer(DefaultBodyLimit::max(1_100_000))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state)
}

async fn security_headers(State(state): State<Shared>, req: Request, next: Next) -> Response {
    let origin_ok = req
        .headers()
        .get(header::ORIGIN)
        .map(|v| v.to_str().ok() == Some(state.origin.as_str()))
        .unwrap_or(true);
    let mut response = if !origin_ok {
        error(StatusCode::FORBIDDEN, "Origin denied").into_response()
    } else {
        next.run(req).await
    };
    let h = response.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if state.origin.starts_with("https://") {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    response
}
async fn health(State(s): State<Shared>) -> ApiResult {
    sqlx::query("SELECT 1")
        .execute(&s.pool)
        .await
        .map_err(unavailable)?;
    Ok(Json(serde_json::json!({"status":"ok"})))
}
