use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde_json::json;

// ============================================================
// The Rejection — unified error for all extractors
// ============================================================
#[derive(Debug)]
pub enum AuthRejection {
    MissingToken,
    InvalidToken(String),
    ClaimsFailed(String),
    UserNotFound,
    AccountInactive,
    Forbidden(String),
    CustomFailed(String),
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let (status, msg): (StatusCode, String) = match self {
            Self::MissingToken         => (StatusCode::UNAUTHORIZED, "missing token".to_string()),
            Self::InvalidToken(m)      => (StatusCode::UNAUTHORIZED, m),
            Self::ClaimsFailed(m)      => (StatusCode::UNAUTHORIZED, m),
            Self::UserNotFound         => (StatusCode::UNAUTHORIZED, "user not found".to_string()),
            Self::AccountInactive      => (StatusCode::FORBIDDEN,    "account inactive".to_string()),
            Self::Forbidden(m)         => (StatusCode::FORBIDDEN,    m),
            Self::CustomFailed(m)      => (StatusCode::FORBIDDEN,    m),
        };

        (status, Json(json!({ "error": msg }))).into_response()
    }
}


pub mod token_claims;
pub mod auth_user;
pub mod protected;

pub use token_claims::TokenClaims;
pub use auth_user::AuthUser;
pub use protected::Protected;
