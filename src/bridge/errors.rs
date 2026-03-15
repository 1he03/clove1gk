use axum::{response::Response, http::StatusCode, Json};
use serde_json::json;
use axum::response::IntoResponse;

use crate::{
    token::validator::ValidationError,
    loader::LoaderError,
    validation::ValidationError as CustomValidationError,
    guard::GuardError,
};

pub fn unauthorized(msg: &str) -> Response {
    error_response(StatusCode::UNAUTHORIZED, msg)
}

pub fn map_validation_err(e: ValidationError) -> Response {
    match e {
        ValidationError::Expired          => error_response(StatusCode::UNAUTHORIZED, "token expired"),
        ValidationError::InvalidSignature => error_response(StatusCode::UNAUTHORIZED, "invalid signature"),
        ValidationError::UuidInvalid      => error_response(StatusCode::UNAUTHORIZED, "invalid token format"),
        ValidationError::Malformed        => error_response(StatusCode::BAD_REQUEST,  "malformed token"),
        ValidationError::Custom(m)        => error_response(StatusCode::UNAUTHORIZED, &m),
    }
}

pub fn map_loader_err(e: LoaderError) -> Response {
    match e {
        LoaderError::NotFound    => error_response(StatusCode::UNAUTHORIZED,  "user not found"),
        LoaderError::Inactive    => error_response(StatusCode::FORBIDDEN,     "account inactive"),
        LoaderError::Unauthorized => error_response(StatusCode::FORBIDDEN,    "unauthorized"),
        LoaderError::Custom(m)   => error_response(StatusCode::FORBIDDEN,     &m),
    }
}

pub fn map_custom_err(e: CustomValidationError) -> Response {
    match e {
        CustomValidationError::Forbidden(m) => error_response(StatusCode::FORBIDDEN,   &m),
        CustomValidationError::Invalid(m)   => error_response(StatusCode::BAD_REQUEST,  &m),
        CustomValidationError::Custom(m)    => error_response(StatusCode::FORBIDDEN,    &m),
    }
}

pub fn map_guard_err(e: GuardError) -> Response {
    match e {
        GuardError::AccountInactive       => error_response(StatusCode::FORBIDDEN, "account inactive"),
        GuardError::MissingRole(r)        => error_response(StatusCode::FORBIDDEN, &format!("missing role: {}", r)),
        GuardError::MissingPermission(p)  => error_response(StatusCode::FORBIDDEN, &format!("missing permission: {}", p)),
    }
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}
