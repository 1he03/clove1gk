use std::future::Future;
use std::pin::Pin;
use crate::loader::AuthContext;
use crate::claims::extractor::RequestContext;
use std::marker::PhantomData;

// ========================================
// Error
// ========================================
#[derive(Debug)]
pub enum ValidationError {
    Forbidden(String),   // Forbidden — clear reason
    Invalid(String),     // Invalid data
    Custom(String),      // Any custom developer error
}

// ========================================
// Trait — Developer writes custom logic
// ========================================
pub trait CustomValidator: Send + Sync + 'static {
    type Claims: Send + Sync + Clone + 'static;
    type Context: AuthContext + Send + Sync + Clone + 'static;
    type Future: Future<Output = Result<(), ValidationError>> + Send;

    fn validate(
        &self,
        claims: &RequestContext<Self::Claims>,  // Data from token
        context: &Self::Context,                // AuthContext from STEP 4
    ) -> Self::Future;
}

// ========================================
// NoopValidator — updated with PhantomData
// ========================================
#[derive(Clone)]
pub struct NoopValidator<C, Ctx> {
    _phantom: PhantomData<(C, Ctx)>,
}

impl<C, Ctx> NoopValidator<C, Ctx> {
    pub fn new() -> Self {
        Self { _phantom: PhantomData }
    }
}

impl<C, Ctx> CustomValidator for NoopValidator<C, Ctx>
where
    C: Send + Sync + Clone + 'static,
    Ctx: AuthContext + Send + Sync + Clone + 'static,
{
    type Claims = C;
    type Context = Ctx;
    type Future = Pin<Box<dyn Future<Output = Result<(), ValidationError>> + Send>>;

    fn validate(&self, _claims: &RequestContext<C>, _context: &Ctx) -> Self::Future {
        Box::pin(async { Ok(()) })
    }
}
// ========================================
// ValidatorChain — Run multiple validators in sequence
// ========================================
pub struct ValidatorChain<C, Ctx> {
    validators: Vec<Box<dyn DynValidator<C, Ctx>>>,
}

impl<C, Ctx> ValidatorChain<C, Ctx>
where
    C: Send + Sync + Clone + 'static,
    Ctx: AuthContext + Send + Sync + Clone + 'static,
{
    pub fn new() -> Self {
        Self { validators: Vec::new() }
    }

    pub fn add<V>(mut self, validator: V) -> Self
    where
        V: CustomValidator<Claims = C, Context = Ctx> + 'static,
    {
        self.validators.push(Box::new(DynValidatorWrapper(validator)));
        self
    }

    pub async fn run(
        &self,
        claims: &RequestContext<C>,
        context: &Ctx,
    ) -> Result<(), ValidationError> {
        for v in &self.validators {
            v.validate_dyn(claims, context).await?;
        }
        Ok(())
    }
}

// ========================================
// Internals — Dynamic dispatch for the chain
// ========================================
trait DynValidator<C, Ctx>: Send + Sync {
    fn validate_dyn<'a>(
        &'a self,
        claims: &'a RequestContext<C>,
        context: &'a Ctx,
    ) -> Pin<Box<dyn Future<Output = Result<(), ValidationError>> + Send + 'a>>;
}

struct DynValidatorWrapper<V>(V);

impl<V, C, Ctx> DynValidator<C, Ctx> for DynValidatorWrapper<V>
where
    V: CustomValidator<Claims = C, Context = Ctx>,
    C: Send + Sync + Clone + 'static,
    Ctx: AuthContext + Send + Sync + Clone + 'static,
{
    fn validate_dyn<'a>(
        &'a self,
        claims: &'a RequestContext<C>,
        context: &'a Ctx,
    ) -> Pin<Box<dyn Future<Output = Result<(), ValidationError>> + Send + 'a>> {
        Box::pin(self.0.validate(claims, context))
    }
}


// ── Helper trait — makes CustomValidator object-safe
pub trait DynCustomValidator<C, Ctx>: Send + Sync {
    fn validate_dyn<'a>(
        &'a self,
        claims:  &'a RequestContext<C>,
        context: &'a Ctx,
    ) -> Pin<Box<dyn Future<Output = Result<(), ValidationError>> + Send + 'a>>;
}

// ── auto impl for everything that implements CustomValidator
impl<T, C, Ctx> DynCustomValidator<C, Ctx> for T
where
    T: CustomValidator<Claims = C, Context = Ctx>,
    C:   Send + Sync + 'static,
    Ctx: Send + Sync + 'static,
{
    fn validate_dyn<'a>(
        &'a self,
        claims:  &'a RequestContext<C>,
        context: &'a Ctx,
    ) -> Pin<Box<dyn Future<Output = Result<(), ValidationError>> + Send + 'a>> {
        Box::pin(self.validate(claims, context))
    }
}


// impl<C, Ctx> DynCustomValidator<C, Ctx> for ValidatorChain<C, Ctx>
// where
//     C:   Clone + Send + Sync + 'static,    // ✅ added Clone
//     Ctx: AuthContext + Clone + Send + Sync + 'static,  // ✅ added AuthContext + Clone
// {
//     fn validate_dyn<'a>(
//         &'a self,
//         claims:  &'a RequestContext<C>,
//         context: &'a Ctx,
//     ) -> Pin<Box<dyn Future<Output = Result<(), ValidationError>> + Send + 'a>> {
//         let fut = self.run(claims, context);
//         Box::pin(fut)
//     }
// }

