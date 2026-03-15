use std::future::Future;

use axum::{
    extract::FromRequestParts,
    http::request::Parts,
};

use crate::{
    token::extractor::RawToken,
    token::validator::TokenValidator,
    claims::extractor::{ClaimsExtractor, RequestContext, TokenKind},
    loader::{AuthContext, ContextLoader, LoaderError},
};

use super::AuthRejection;

pub trait AuthUserState: Send + Sync + 'static {
    type Validator: TokenValidator + Send + Sync;
    type Extractor: ClaimsExtractor + Send + Sync;
    type Loader: ContextLoader<Claims = <Self::Extractor as ClaimsExtractor>::Claims> + Send + Sync;

    fn validator(&self) -> &Self::Validator;
    fn extractor(&self) -> &Self::Extractor;
    fn loader(&self) -> &Self::Loader;
}

pub struct AuthUser<Ctx>(pub Ctx);

impl<S> FromRequestParts<S> for AuthUser<<S::Loader as ContextLoader>::Context>
where
    S: AuthUserState,
    <S::Loader as ContextLoader>::Context: AuthContext + Clone + Send + Sync + 'static,
    <S::Extractor as ClaimsExtractor>::Claims: Clone + Send + Sync + 'static,
{
    type Rejection = AuthRejection;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let headers   = parts.headers.clone();
        let validator = state.validator();
        let extractor = state.extractor();
        let loader    = state.loader();

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

            // STEP 4
            let auth_ctx = loader
                .load(&req_ctx)
                .await
                .map_err(|e| match e {
                    LoaderError::NotFound     => AuthRejection::UserNotFound,
                    LoaderError::Inactive     => AuthRejection::AccountInactive,
                    LoaderError::Unauthorized => AuthRejection::Forbidden("unauthorized".into()),
                    LoaderError::Custom(m)    => AuthRejection::Forbidden(m),
                })?;

            Ok(AuthUser(auth_ctx))
        }
    }
}
