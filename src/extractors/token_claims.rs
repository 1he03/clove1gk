use std::future::Future;

use axum::{
    extract::FromRequestParts,
    http::request::Parts
};

use crate::{
    token::extractor::RawToken,
    claims::extractor::{ClaimsExtractor, RequestContext, TokenKind},
    token::validator::TokenValidator,
};

use super::AuthRejection;

// ── The State Trait
pub trait TokenClaimsState: Send + Sync + 'static {
    type Validator: TokenValidator + Send + Sync;
    type Extractor: ClaimsExtractor + Send + Sync;

    fn validator(&self) -> &Self::Validator;
    fn extractor(&self) -> &Self::Extractor;
}

// ── The Extractor Struct
pub struct TokenClaims<C>(pub C);

// ── The impl — without #[async_trait] and manual lifetimes
impl<S> FromRequestParts<S> for TokenClaims<<S::Extractor as ClaimsExtractor>::Claims>
where
    S: TokenClaimsState,
    <S::Extractor as ClaimsExtractor>::Claims: Clone + Send + Sync + 'static,
{
    type Rejection = AuthRejection;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        // Collect what we need before the async block
        // to avoid borrowing parts or state inside async
        let headers = parts.headers.clone();
        let validator = state.validator();
        let extractor = state.extractor();

        // Run the pipeline outside async as much as possible
        let raw_token = RawToken::from_headers(&headers);

        async move {
            // STEP 1
            let raw_token = raw_token
                .map_err(|_| AuthRejection::MissingToken)?;

            // STEP 2
            let validated = validator
                .validate(&raw_token)
                .await
                .map_err(|e| AuthRejection::InvalidToken(format!("{:?}", e)))?;

            // STEP 3
            let claims = extractor
                .extract(validated)
                .await
                .map_err(|e| AuthRejection::ClaimsFailed(format!("{:?}", e)))?;

            let req_ctx = RequestContext::new(
                claims,
                TokenKind::from(&raw_token),
                raw_token.raw().to_string(),
            );

            Ok(TokenClaims(req_ctx.claims))
        }
    }
}
