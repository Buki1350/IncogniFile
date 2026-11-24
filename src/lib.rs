mod auth;
pub mod config;
pub mod db;
pub mod limiter;
mod messages;
pub mod password;
pub mod validation;
mod verification_email;
use auth::{login, logout, register, resend_verification, verify_email};
use messages::{get_available_messages, read_message, remove_message, save_message};

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
        let origin = std::env::var("APP_ORIGIN")
            .or_else(|_| std::env::var("RENDER_EXTERNAL_URL"))
            .unwrap_or_else(|_| "http://localhost:8080".into());
        validate_origin(&origin)?;
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
    let kind = match &e {
        sqlx::Error::Database(d) => d.code().unwrap_or_default().into_owned(),
        sqlx::Error::ColumnNotFound(_) => "column_not_found".into(),
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => "decode".into(),
        sqlx::Error::PoolClosed => "pool_closed".into(),
        sqlx::Error::PoolTimedOut => "pool_timeout".into(),
        _ => "database_error".into(),
    };
    tracing::warn!(%kind, "database operation failed");
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
        .route(
            "/api/secrets",
            get(get_available_messages).post(save_message),
        )
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

// An origin cannot contain credentials, a path, query or fragment.
fn validate_origin(origin: &str) -> Result<(), String> {
    let valid = origin.parse::<axum::http::Uri>().ok().is_some_and(|uri| {
        let Some(authority) = uri.authority() else {
            return false;
        };
        let Some(scheme) = uri.scheme_str() else {
            return false;
        };
        let secure = scheme == "https";
        let local =
            scheme == "http" && matches!(uri.host(), Some("localhost" | "127.0.0.1" | "[::1]"));
        (secure || local)
            && !authority.as_str().contains('@')
            && !authority.host().is_empty()
            && authority
                .as_str()
                .strip_prefix(authority.host())
                .is_some_and(|suffix| {
                    suffix.is_empty()
                        || suffix
                            .strip_prefix(':')
                            .is_some_and(|port| port.parse::<u16>().is_ok())
                })
            && origin == format!("{scheme}://{authority}")
    });
    if valid {
        Ok(())
    } else {
        Err("APP_ORIGIN must be an HTTPS origin (or localhost HTTP), without credentials, path, query, fragment or trailing slash".into())
    }
}

#[cfg(test)]
mod tests {
    use super::validate_origin;

    #[test]
    fn origin_must_be_a_complete_origin_not_a_url_or_prefix() {
        for origin in [
            "https://example.com",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(validate_origin(origin).is_ok(), "{origin}");
        }
        for origin in [
            "https://",
            "https://example.com/",
            "https://example.com/path",
            "https://example.com?x=1",
            "https://example.com#x",
            "https://user:pass@example.com",
            "http://localhost:8080@evil.example",
            "http://example.com",
            "https://example.com:99999",
            "https://example.com:abc",
        ] {
            assert!(validate_origin(origin).is_err(), "{origin}");
        }
    }
}
