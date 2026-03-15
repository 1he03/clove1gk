use super::AuthGuard;

// Ready presets — shortcuts for common cases
impl<R, P> AuthGuard<R, P>
where
    R: Eq + std::hash::Hash + Clone + std::fmt::Debug + From<&'static str>,
    P: Eq + std::hash::Hash + Clone + std::fmt::Debug,
{
    // Any request must have an active account at least
    pub fn authenticated() -> Self {
        Self::new().require_active()
    }
}
