use std::future::Future;
use crate::token::validator::ValidatedClaims;
use crate::token::extractor::RawToken;

// ========================================
// Error
// ========================================
#[derive(Debug)]
pub enum ClaimsError {
    MissingField(String),
    InvalidValue(String),
    WrongTokenType, // Requested JWT and got UUID or vice versa
}

// ========================================
// The Trait — Developer adheres to it
// Transforms ValidatedClaims → Custom struct
// ========================================
pub trait ClaimsExtractor: Send + Sync + 'static {
    // Developer defines the shape of their Claims
    type Claims: Send + Sync + Clone + 'static;
    type Future: Future<Output = Result<Self::Claims, ClaimsError>> + Send;

    fn extract(&self, validated: ValidatedClaims) -> Self::Future;
}

// ========================================
// RequestContext — Injected into the request after extraction
// This is what the handler sees in the end
// ========================================
#[derive(Debug, Clone)]
pub struct RequestContext<C> {
    pub claims: C,
    pub token_kind: TokenKind,
    pub raw_subject: String, // sub from JWT or UUID from legacy
}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    Jwt,
    LegacyUuid,
}

impl<C> RequestContext<C> {
    pub fn new(claims: C, token_kind: TokenKind, raw_subject: String) -> Self {
        Self { claims, token_kind, raw_subject }
    }

    pub fn is_legacy(&self) -> bool {
        self.token_kind == TokenKind::LegacyUuid
    }
}


// Add this directly in src/claims/extractor.rs
impl From<&RawToken> for TokenKind {
    fn from(token: &RawToken) -> Self {
        match token {
            RawToken::Jwt(_)        => TokenKind::Jwt,
            RawToken::LegacyUuid(_) => TokenKind::LegacyUuid,
        }
    }
}