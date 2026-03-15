use std::future::Future;
use std::pin::Pin;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use crate::token::extractor::RawToken;

#[derive(Debug, Clone)]
pub enum ValidatedClaims {
    Jwt(JwtClaims),
    LegacyUuid(String),
}

// Standard JWT Claims — Provided by the framework
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,       // subject — usually user_id
    pub exp: u64,          // expiry
    pub iat: u64,          // issued at
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>, // any extra fields
}

#[derive(Debug)]
pub enum ValidationError {
    Expired,
    InvalidSignature,
    Malformed,
    UuidInvalid,
    Custom(String),
}

// from jsonwebtoken::errors map to our ValidationError
impl From<jsonwebtoken::errors::Error> for ValidationError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match e.kind() {
            ErrorKind::ExpiredSignature => Self::Expired,
            ErrorKind::InvalidSignature => Self::InvalidSignature,
            _ => Self::Malformed,
        }
    }
}

// ========================================
// The Trait
// ========================================
pub trait TokenValidator: Send + Sync + 'static {
    type Future: Future<Output = Result<ValidatedClaims, ValidationError>> + Send;
    fn validate(&self, token: &RawToken) -> Self::Future;
}

// ========================================
// Default JWT Validator
// ========================================
#[derive(Clone)]
pub struct JwtValidator {
    secret: String,
    algorithm: Algorithm,
}

impl JwtValidator {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            algorithm: Algorithm::HS256, // default
        }
    }

    // If the developer wants a different algorithm — e.g. RS256
    pub fn change_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }
}

impl TokenValidator for JwtValidator {
    type Future = Pin<Box<dyn Future<Output = Result<ValidatedClaims, ValidationError>> + Send>>;

    fn validate(&self, token: &RawToken) -> Self::Future {
        let secret = self.secret.clone();
        let algorithm = self.algorithm;
        let token = token.clone();

        Box::pin(async move {
            match &token {
                RawToken::Jwt(raw) => {
                    let key = DecodingKey::from_secret(secret.as_bytes());
                    let mut validation = Validation::new(algorithm);
                    validation.validate_exp = true;

                    let data = decode::<JwtClaims>(raw, &key, &validation)?;
                    Ok(ValidatedClaims::Jwt(data.claims))
                }

                RawToken::LegacyUuid(raw) => {
                    if is_valid_uuid(raw) {
                        Ok(ValidatedClaims::LegacyUuid(raw.clone()))
                    } else {
                        Err(ValidationError::UuidInvalid)
                    }
                }
            }
        })
    }
}

// ========================================
// UUID v4 validator
// ========================================
fn is_valid_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    matches!(
        parts.as_slice(),
        [a, b, c, d, e]
        if a.len() == 8 && b.len() == 4
        && c.len() == 4 && d.len() == 4
        && e.len() == 12
        && s.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-')
    )
}
