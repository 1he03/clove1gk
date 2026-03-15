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
    guard::AuthGuard,
};

use super::AuthRejection;

use crate::validation::DynCustomValidator;

pub trait ProtectedState: Send + Sync + 'static {
    type Validator: TokenValidator + Send + Sync;
    type Extractor: ClaimsExtractor + Send + Sync;
    type Loader:    ContextLoader<Claims = <Self::Extractor as ClaimsExtractor>::Claims> + Send + Sync;
    type RoleId:    Eq + std::hash::Hash + Clone + std::fmt::Debug + Send + Sync + 'static;
    type PermId:    Eq + std::hash::Hash + Clone + std::fmt::Debug + Send + Sync + 'static;

    fn validator(&self) -> &Self::Validator;
    fn extractor(&self) -> &Self::Extractor;
    fn loader(&self)    -> &Self::Loader;
    fn guard(&self)     -> &AuthGuard<Self::RoleId, Self::PermId>;

    // ✅ Returns DynCustomValidator — completely object-safe
    fn custom_validator(&self) -> &dyn DynCustomValidator<
        <Self::Extractor as ClaimsExtractor>::Claims,
        <Self::Loader as ContextLoader>::Context,
    >;
}


pub struct Protected<Ctx>(pub Ctx);

impl<S> FromRequestParts<S> for Protected<<S::Loader as ContextLoader>::Context>
where
    S: ProtectedState,
    <S::Loader as ContextLoader>::Context: AuthContext<
        RoleId       = S::RoleId,
        PermissionId = S::PermId,
    > + Clone + Send + Sync + 'static,
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
        // let custom    = state.custom_validator();
        let guard     = state.guard();

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

            // STEP 5
            state.custom_validator()
            .validate_dyn(&req_ctx, &auth_ctx)   // validate_dyn is correct
            .await
            .map_err(|e| AuthRejection::CustomFailed(format!("{:?}", e)))?;

            // STEP 6
            guard
                .check(&auth_ctx)
                .map_err(|e| AuthRejection::Forbidden(format!("{:?}", e)))?;

            Ok(Protected(auth_ctx))
        }
    }
}
