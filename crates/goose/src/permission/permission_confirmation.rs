use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Permission {
    AlwaysAllow,
    AllowOnce,
    Cancel,
    DenyOnce,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum SecurityPermission {
    AllowOnce,
    DenyOnce,
    AlwaysAllow, // For this type of threat
    NeverAllow,  // For this type of threat
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema)]
pub enum PrincipalType {
    Extension,
    Tool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PermissionConfirmation {
    pub principal_type: PrincipalType,
    pub permission: Permission,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityConfirmation {
    pub permission: SecurityPermission,
    pub threat_level: String,
}
