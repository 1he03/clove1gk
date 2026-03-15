pub mod context;

use std::future::Future;
use crate::claims::extractor::RequestContext;

pub use context::DefaultAuthContext;

#[derive(Debug)]
pub enum LoaderError {
    NotFound,
    Inactive,
    Unauthorized,
    Custom(String),
}

pub trait AuthContext: Send + Sync + 'static {
    type RoleId: Eq + std::hash::Hash + Send + Sync;
    type PermissionId: Eq + std::hash::Hash + Send + Sync;

    fn subject_id(&self) -> u64;
    fn is_active(&self) -> bool;
    fn has_role(&self, role: &Self::RoleId) -> bool;
    fn has_permission(&self, perm: &Self::PermissionId) -> bool;
}

pub trait ContextLoader: Send + Sync + 'static {
    type Claims: Send + Sync + Clone + 'static;
    type Context: AuthContext + Send + Sync + Clone + 'static;
    type Future: Future<Output = Result<Self::Context, LoaderError>> + Send;

    fn load(&self, ctx: &RequestContext<Self::Claims>) -> Self::Future;
}
