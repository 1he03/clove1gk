use std::collections::HashSet;
use super::AuthContext;

// ========================================
// Default AuthContext — ready out-of-the-box
// Developer uses it if they don't have something specific
// ========================================
#[derive(Debug, Clone)]
pub struct DefaultAuthContext {
    pub subject_id: u64,
    pub is_active: bool,
    pub roles: HashSet<String>,
    pub permissions: HashSet<String>,
}

impl DefaultAuthContext {
    pub fn new(subject_id: u64) -> Self {
        Self {
            subject_id,
            is_active: true,
            roles: HashSet::new(),
            permissions: HashSet::new(),
        }
    }

    pub fn with_roles(mut self, roles: impl IntoIterator<Item = String>) -> Self {
        self.roles.extend(roles);
        self
    }

    pub fn with_permissions(mut self, perms: impl IntoIterator<Item = String>) -> Self {
        self.permissions.extend(perms);
        self
    }
}

impl AuthContext for DefaultAuthContext {
    type RoleId = String;
    type PermissionId = String;

    fn subject_id(&self) -> u64 { self.subject_id }
    fn is_active(&self) -> bool { self.is_active }

    fn has_role(&self, role: &String) -> bool {
        self.roles.contains(role)
    }

    fn has_permission(&self, perm: &String) -> bool {
        // FullAccess — passes everything
        if self.permissions.contains("full_access.owner")
            || self.permissions.contains("full_access.server_developer")
        {
            return true;
        }
        self.permissions.contains(perm)
    }
}
