use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;

use actix_web::{
    dev::Payload,
    web::Data,
    FromRequest,
    HttpRequest,
    HttpResponse,
    ResponseError,
};

use crate::{
    token::extractor::RawToken,
    token::validator::TokenValidator,
    claims::extractor::{ClaimsExtractor, RequestContext, TokenKind},
    loader::{AuthContext, ContextLoader, LoaderError},
    validation::DynCustomValidator,
    guard::AuthGuard,
};

// ============================================================
// Rejection
// ============================================================
#[derive(Debug)]
pub enum ActixRejection {
    MissingToken,
    InvalidToken(String),
    ClaimsFailed(String),
    UserNotFound,
    AccountInactive,
    Forbidden(String),
    CustomFailed(String),
}

impl std::fmt::Display for ActixRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingToken      => write!(f, "missing token"),
            Self::InvalidToken(m)   => write!(f, "invalid token: {}", m),
            Self::ClaimsFailed(m)   => write!(f, "claims failed: {}", m),
            Self::UserNotFound      => write!(f, "user not found"),
            Self::AccountInactive   => write!(f, "account inactive"),
            Self::Forbidden(m)      => write!(f, "forbidden: {}", m),
            Self::CustomFailed(m)   => write!(f, "custom validation failed: {}", m),
        }
    }
}

impl ResponseError for ActixRejection {
    fn error_response(&self) -> HttpResponse {
        use actix_web::http::StatusCode;
        let status = match self {
            Self::MissingToken      => StatusCode::UNAUTHORIZED,
            Self::InvalidToken(_)   => StatusCode::UNAUTHORIZED,
            Self::ClaimsFailed(_)   => StatusCode::UNAUTHORIZED,
            Self::UserNotFound      => StatusCode::UNAUTHORIZED,
            Self::AccountInactive   => StatusCode::FORBIDDEN,
            Self::Forbidden(_)      => StatusCode::FORBIDDEN,
            Self::CustomFailed(_)   => StatusCode::FORBIDDEN,
        };
        HttpResponse::build(status)
            .json(serde_json::json!({ "error": self.to_string() }))
    }
}

// ============================================================
// State Traits
// ============================================================
pub trait ActixTokenClaimsState: Send + Sync + 'static {
    type Validator: TokenValidator + Send + Sync;
    type Extractor: ClaimsExtractor + Send + Sync;
    fn validator(&self) -> &Self::Validator;
    fn extractor(&self) -> &Self::Extractor;
}

pub trait ActixAuthUserState: Send + Sync + 'static {
    type Validator: TokenValidator + Send + Sync;
    type Extractor: ClaimsExtractor + Send + Sync;
    type Loader: ContextLoader<
        Claims = <Self::Extractor as ClaimsExtractor>::Claims,
    > + Send + Sync;
    fn validator(&self) -> &Self::Validator;
    fn extractor(&self) -> &Self::Extractor;
    fn loader(&self)    -> &Self::Loader;
}

pub trait ActixProtectedState: Send + Sync + 'static {
    type Validator: TokenValidator + Send + Sync;
    type Extractor: ClaimsExtractor + Send + Sync;
    type Loader: ContextLoader<
        Claims = <Self::Extractor as ClaimsExtractor>::Claims,
    > + Send + Sync;
    type RoleId: Eq + std::hash::Hash + Clone + std::fmt::Debug + Send + Sync + 'static;
    type PermId: Eq + std::hash::Hash + Clone + std::fmt::Debug + Send + Sync + 'static;

    fn validator(&self)        -> &Self::Validator;
    fn extractor(&self)        -> &Self::Extractor;
    fn loader(&self)           -> &Self::Loader;
    fn guard(&self)            -> &AuthGuard<Self::RoleId, Self::PermId>;
    fn custom_validator(&self) -> &dyn DynCustomValidator<
        <Self::Extractor as ClaimsExtractor>::Claims,
        <Self::Loader as ContextLoader>::Context,
    >;
}

// ============================================================
// Helper — Authorization header → RawToken
// ============================================================
fn extract_raw_token(req: &HttpRequest) -> Result<RawToken, ActixRejection> {
    let value = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .ok_or(ActixRejection::MissingToken)?
        .to_str()
        .map_err(|_| ActixRejection::MissingToken)?;

    let mut std_map = http::HeaderMap::new();
    std_map.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(value)
            .map_err(|_| ActixRejection::MissingToken)?,
    );

    RawToken::from_headers(&std_map)
        .map_err(|_| ActixRejection::MissingToken)
}

// ============================================================
// EXTRACTOR 1 — TokenClaims: STEP 1 + 2 + 3
// ============================================================
pub struct TokenClaims<S, C> {
    pub claims: C,
    _state: PhantomData<fn() -> S>,
}

impl<S, C> TokenClaims<S, C> {
    fn new(claims: C) -> Self {
        Self { claims, _state: PhantomData }
    }
}

impl<S> FromRequest for TokenClaims<S, <S::Extractor as ClaimsExtractor>::Claims>
where
    S: ActixTokenClaimsState + 'static,
    <S::Extractor as ClaimsExtractor>::Claims: Clone + Send + Sync + 'static,
{
    type Error  = ActixRejection;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let state = match req.app_data::<Data<S>>() {
            Some(s) => s.clone(),
            None    => return Box::pin(async { Err(ActixRejection::MissingToken) }),
        };
        let raw = extract_raw_token(req);

        Box::pin(async move {
            // STEP 1
            let raw = raw?;

            // STEP 2
            let validated = state.validator()
                .validate(&raw)
                .await
                .map_err(|e| ActixRejection::InvalidToken(format!("{:?}", e)))?;

            // STEP 3
            let claims = state.extractor()
                .extract(validated)
                .await
                .map_err(|e| ActixRejection::ClaimsFailed(format!("{:?}", e)))?;

            Ok(TokenClaims::new(claims))
        })
    }
}

// ============================================================
// EXTRACTOR 2 — AuthUser: STEP 1 + 2 + 3 + 4
// ============================================================
pub struct AuthUser<S, Ctx> {
    pub context: Ctx,
    _state: PhantomData<fn() -> S>,
}

impl<S, Ctx> AuthUser<S, Ctx> {
    fn new(context: Ctx) -> Self {
        Self { context, _state: PhantomData }
    }
}

impl<S> FromRequest for AuthUser<S, <S::Loader as ContextLoader>::Context>
where
    S: ActixAuthUserState + 'static,
    <S::Loader as ContextLoader>::Context:
        AuthContext + Clone + Send + Sync + 'static,
    <S::Extractor as ClaimsExtractor>::Claims:
        Clone + Send + Sync + 'static,
{
    type Error  = ActixRejection;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let state = match req.app_data::<Data<S>>() {
            Some(s) => s.clone(),
            None    => return Box::pin(async { Err(ActixRejection::MissingToken) }),
        };
        let raw = extract_raw_token(req);

        Box::pin(async move {
            // STEP 1
            let raw = raw?;

            // STEP 2
            let validated = state.validator()
                .validate(&raw)
                .await
                .map_err(|e| ActixRejection::InvalidToken(format!("{:?}", e)))?;

            // STEP 3
            let claims = state.extractor()
                .extract(validated)
                .await
                .map_err(|e| ActixRejection::ClaimsFailed(format!("{:?}", e)))?;

            let req_ctx = RequestContext::new(
                claims,
                TokenKind::from(&raw),
                raw.raw().to_string(),
            );

            // STEP 4
            let auth_ctx = state.loader()
                .load(&req_ctx)
                .await
                .map_err(|e| match e {
                    LoaderError::NotFound     => ActixRejection::UserNotFound,
                    LoaderError::Inactive     => ActixRejection::AccountInactive,
                    LoaderError::Unauthorized => ActixRejection::Forbidden("unauthorized".into()),
                    LoaderError::Custom(m)    => ActixRejection::Forbidden(m),
                })?;

            Ok(AuthUser::new(auth_ctx))
        })
    }
}

// ============================================================
// EXTRACTOR 3 — Protected: STEP 1 + 2 + 3 + 4 + 5 + 6
// ============================================================
pub struct Protected<S, Ctx> {
    pub context: Ctx,
    _state: PhantomData<fn() -> S>,
}

impl<S, Ctx> Protected<S, Ctx> {
    fn new(context: Ctx) -> Self {
        Self { context, _state: PhantomData }
    }
}

impl<S> FromRequest for Protected<S, <S::Loader as ContextLoader>::Context>
where
    S: ActixProtectedState + 'static,
    <S::Loader as ContextLoader>::Context: AuthContext<
        RoleId       = S::RoleId,
        PermissionId = S::PermId,
    > + Clone + Send + Sync + 'static,
    <S::Extractor as ClaimsExtractor>::Claims:
        Clone + Send + Sync + 'static,
{
    type Error  = ActixRejection;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let state = match req.app_data::<Data<S>>() {
            Some(s) => s.clone(),
            None    => return Box::pin(async { Err(ActixRejection::MissingToken) }),
        };
        let raw = extract_raw_token(req);

        Box::pin(async move {
            // STEP 1
            let raw = raw?;

            // STEP 2
            let validated = state.validator()
                .validate(&raw)
                .await
                .map_err(|e| ActixRejection::InvalidToken(format!("{:?}", e)))?;

            // STEP 3
            let claims = state.extractor()
                .extract(validated)
                .await
                .map_err(|e| ActixRejection::ClaimsFailed(format!("{:?}", e)))?;

            let req_ctx = RequestContext::new(
                claims,
                TokenKind::from(&raw),
                raw.raw().to_string(),
            );

            // STEP 4
            let auth_ctx = state.loader()
                .load(&req_ctx)
                .await
                .map_err(|e| match e {
                    LoaderError::NotFound     => ActixRejection::UserNotFound,
                    LoaderError::Inactive     => ActixRejection::AccountInactive,
                    LoaderError::Unauthorized => ActixRejection::Forbidden("unauthorized".into()),
                    LoaderError::Custom(m)    => ActixRejection::Forbidden(m),
                })?;

            // STEP 5
            state.custom_validator()
                .validate_dyn(&req_ctx, &auth_ctx)
                .await
                .map_err(|e| ActixRejection::CustomFailed(format!("{:?}", e)))?;

            // STEP 6
            state.guard()
                .check(&auth_ctx)
                .map_err(|e| ActixRejection::Forbidden(format!("{:?}", e)))?;

            Ok(Protected::new(auth_ctx))
        })
    }
}
