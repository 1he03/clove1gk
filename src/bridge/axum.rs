use std::pin::Pin;
use std::future::Future;
use std::task::{Context, Poll};

use axum::{
    extract::Request,
    response::Response
};
use tower::{Layer, Service};

use crate::bridge::errors::{map_custom_err, map_guard_err, map_loader_err, map_validation_err, unauthorized};
use crate::{
    token::extractor::RawToken,
    token::validator::TokenValidator,
    claims::extractor::{ClaimsExtractor, RequestContext},
    loader::ContextLoader,
    validation::CustomValidator,
    guard::AuthGuard,
};

// ========================================
// PipelineLayer — Injected into the Router
// This is all the developer sees
// ========================================
#[derive(Clone)]
pub struct PipelineLayer<V, E, L, Cv, R, P>
where
    R: Eq + std::hash::Hash + Clone + std::fmt::Debug + Send + Sync + 'static,
    P: Eq + std::hash::Hash + Clone + std::fmt::Debug + Send + Sync + 'static,
{
    pub validator: V,    // STEP 2
    pub extractor: E,    // STEP 3
    pub loader: L,       // STEP 4
    pub custom: Cv,      // STEP 5
    pub guard: AuthGuard<R, P>, // STEP 6
}

impl<S, V, E, L, Cv, R, P> Layer<S> for PipelineLayer<V, E, L, Cv, R, P>
where
    V: TokenValidator + Clone,
    E: ClaimsExtractor + Clone,
    L: ContextLoader<Claims = E::Claims> + Clone,
    Cv: CustomValidator<Claims = E::Claims, Context = L::Context> + Clone,
    R: Eq + std::hash::Hash + Clone + std::fmt::Debug + Send + Sync + 'static,
    P: Eq + std::hash::Hash + Clone + std::fmt::Debug + Send + Sync + 'static,
    L::Context: crate::loader::AuthContext<RoleId = R, PermissionId = P>,
{
    type Service = PipelineService<S, V, E, L, Cv, R, P>;

    fn layer(&self, inner: S) -> Self::Service {
        PipelineService {
            inner,
            validator: self.validator.clone(),
            extractor: self.extractor.clone(),
            loader: self.loader.clone(),
            custom: self.custom.clone(),
            guard: self.guard.clone(),
        }
    }
}

// ========================================
// PipelineService — Runs the pipeline on every request
// ========================================
#[derive(Clone)]
pub struct PipelineService<S, V, E, L, Cv, R, P>
where
    R: Eq + std::hash::Hash + Clone + std::fmt::Debug + Send + Sync + 'static,
    P: Eq + std::hash::Hash + Clone + std::fmt::Debug + Send + Sync + 'static,
{
    inner: S,
    validator: V,
    extractor: E,
    loader: L,
    custom: Cv,
    guard: AuthGuard<R, P>,
}

impl<S, V, E, L, Cv, R, P> Service<Request> for PipelineService<S, V, E, L, Cv, R, P>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    V: TokenValidator + Clone + Send + 'static,
    E: ClaimsExtractor + Clone + Send + 'static,
    L: ContextLoader<Claims = E::Claims> + Clone + Send + 'static,
    Cv: CustomValidator<Claims = E::Claims, Context = L::Context> + Clone + Send + 'static,
    R: Eq + std::hash::Hash + Clone + std::fmt::Debug + Send + Sync + 'static,
    P: Eq + std::hash::Hash + Clone + std::fmt::Debug + Send + Sync + 'static,
    L::Context: crate::loader::AuthContext<RoleId = R, PermissionId = P> + Clone,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let validator = self.validator.clone();
        let extractor = self.extractor.clone();
        let loader    = self.loader.clone();
        let custom    = self.custom.clone();
        let guard     = self.guard.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // ── STEP 1 ── Extract token from header
            let raw_token = match RawToken::from_headers(req.headers()) {
                Ok(t)  => t,
                Err(_) => return Ok(unauthorized("missing or invalid token")),
            };

            // ── STEP 2 ── Validate token
            let validated = match validator.validate(&raw_token).await {
                Ok(v)  => v,
                Err(e) => return Ok(map_validation_err(e)),
            };

            // ── STEP 3 ── Extract claims
            let req_ctx = match extractor.extract(validated).await {
                Ok(claims) => RequestContext::new(
                    claims,
                    crate::claims::extractor::TokenKind::from(&raw_token),
                    raw_token.raw().to_string(),
                ),
                Err(_) => return Ok(unauthorized("claims extraction failed")),
            };

            // ── STEP 4 ── Load AuthContext
            let auth_ctx = match loader.load(&req_ctx).await {
                Ok(ctx) => ctx,
                Err(e)  => return Ok(map_loader_err(e)),
            };

            // ── STEP 5 ── Custom validation
            if let Err(e) = custom.validate(&req_ctx, &auth_ctx).await {
                return Ok(map_custom_err(e));
            }

            // ── STEP 6 ── Guard check
            if let Err(e) = guard.check(&auth_ctx) {
                return Ok(map_guard_err(e));
            }

            // ── ✅ inject AuthContext into request extensions
            let mut req = req;
            req.extensions_mut().insert(auth_ctx);
            req.extensions_mut().insert(req_ctx);

            inner.call(req).await
        })
    }
}
