pub mod presets;

use crate::loader::AuthContext;

// ========================================
// Error
// ========================================
#[derive(Debug)]
pub enum GuardError {
    MissingRole(String),
    MissingPermission(String),
    AccountInactive,
}

// ========================================
// GuardRule — Single verification unit
// ========================================
#[derive(Debug, Clone)]
pub enum GuardRule<R, P> {
    RequireRole(R),
    RequirePermission(P),
    RequireActive,
    RequireAnyRole(Vec<R>),        // Any role from the list is sufficient
    RequireAnyPermission(Vec<P>),  // Any permission from the list is sufficient
}

// ========================================
// AuthGuard — Combines multiple rules and runs them in sequence
// ========================================
#[derive(Clone)]
pub struct AuthGuard<R, P> {
    rules: Vec<GuardRule<R, P>>,
}

impl<R, P> AuthGuard<R, P>
where
    R: Eq + std::hash::Hash + Clone + std::fmt::Debug,
    P: Eq + std::hash::Hash + Clone + std::fmt::Debug,
{
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    // Builder pattern — adds rule
    pub fn require_role(mut self, role: R) -> Self {
        self.rules.push(GuardRule::RequireRole(role));
        self
    }

    pub fn require_permission(mut self, perm: P) -> Self {
        self.rules.push(GuardRule::RequirePermission(perm));
        self
    }

    pub fn require_active(mut self) -> Self {
        self.rules.push(GuardRule::RequireActive);
        self
    }

    pub fn require_any_role(mut self, roles: Vec<R>) -> Self {
        self.rules.push(GuardRule::RequireAnyRole(roles));
        self
    }

    pub fn require_any_permission(mut self, perms: Vec<P>) -> Self {
        self.rules.push(GuardRule::RequireAnyPermission(perms));
        self
    }

    // ========================================
    // Execution point — runs all rules in sequence
    // ========================================
    pub fn check<Ctx>(&self, context: &Ctx) -> Result<(), GuardError>
    where
        Ctx: AuthContext<RoleId = R, PermissionId = P>,
    {
        for rule in &self.rules {
            match rule {
                GuardRule::RequireActive => {
                    if !context.is_active() {
                        return Err(GuardError::AccountInactive);
                    }
                }

                GuardRule::RequireRole(role) => {
                    if !context.has_role(role) {
                        return Err(GuardError::MissingRole(
                            format!("{:?}", role)
                        ));
                    }
                }

                GuardRule::RequirePermission(perm) => {
                    if !context.has_permission(perm) {
                        return Err(GuardError::MissingPermission(
                            format!("{:?}", perm)
                        ));
                    }
                }

                GuardRule::RequireAnyRole(roles) => {
                    let ok = roles.iter().any(|r| context.has_role(r));
                    if !ok {
                        return Err(GuardError::MissingRole(
                            format!("none of {:?}", roles)
                        ));
                    }
                }

                GuardRule::RequireAnyPermission(perms) => {
                    let ok = perms.iter().any(|p| context.has_permission(p));
                    if !ok {
                        return Err(GuardError::MissingPermission(
                            format!("none of {:?}", perms)
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}
