// Security Prime MSP Server - Data Models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ============================================================================
// User Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub name: String,
    pub role: UserRole,
    pub organization_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "snake_case")]
pub enum UserRole {
    SuperAdmin,
    MspAdmin,
    MspUser,
    ClientAdmin,
    ClientUser,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub name: String,
    pub role: UserRole,
    pub organization_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub name: Option<String>,
    pub role: Option<UserRole>,
    pub is_active: Option<bool>,
}

// ============================================================================
// Organization Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub org_type: OrgType,
    pub parent_id: Option<Uuid>,
    pub settings: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
    pub max_endpoints: i32,
    pub license_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "org_type", rename_all = "snake_case")]
pub enum OrgType {
    Msp,
    Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub org_type: OrgType,
    pub parent_id: Option<Uuid>,
    pub max_endpoints: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
    pub settings: Option<serde_json::Value>,
    pub is_active: Option<bool>,
    pub max_endpoints: Option<i32>,
}

// ============================================================================
// Endpoint Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Endpoint {
    pub id: Uuid,
    pub endpoint_id: String,
    pub organization_id: Uuid,
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub agent_version: String,
    pub last_seen: DateTime<Utc>,
    pub status: EndpointStatus,
    pub security_score: i32,
    pub threats_detected: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "endpoint_status", rename_all = "snake_case")]
pub enum EndpointStatus {
    Online,
    Offline,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub endpoint_id: String,
    pub api_key: String,
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub agent_version: String,
    pub security_score: i32,
    pub threats_detected: i32,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub success: bool,
    pub server_time: DateTime<Utc>,
    pub commands: Vec<EndpointCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointCommand {
    pub command_type: String,
    pub payload: serde_json::Value,
}

// ============================================================================
// Alert Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Alert {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub endpoint_id: Option<Uuid>,
    pub title: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub status: AlertStatus,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<Uuid>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "alert_severity", rename_all = "snake_case")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "alert_status", rename_all = "snake_case")]
pub enum AlertStatus {
    Open,
    Acknowledged,
    InProgress,
    Resolved,
    Dismissed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAlertRequest {
    pub organization_id: Uuid,
    pub endpoint_id: Option<Uuid>,
    pub title: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub source: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAlertRequest {
    pub status: Option<AlertStatus>,
    pub title: Option<String>,
    pub description: Option<String>,
}

// ============================================================================
// Event Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEventsRequest {
    pub endpoint_id: String,
    pub api_key: String,
    pub events: Vec<SecurityEvent>,
}

// ============================================================================
// License Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct License {
    pub id: Uuid,
    pub license_key: String,
    pub organization_id: Uuid,
    pub max_endpoints: i32,
    pub features: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLicenseRequest {
    pub organization_id: Uuid,
    pub max_endpoints: i32,
    pub features: Vec<String>,
    pub duration_days: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateLicenseRequest {
    pub license_key: String,
    pub endpoint_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateLicenseResponse {
    pub valid: bool,
    pub organization_name: Option<String>,
    pub features: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

// ============================================================================
// Auth Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub refresh_token: String,
    pub user: UserPublic,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublic {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub role: UserRole,
    pub organization_id: Option<Uuid>,
}

impl From<User> for UserPublic {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            organization_id: user.organization_id,
        }
    }
}

// ============================================================================
// Report Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub total_organizations: i64,
    pub total_endpoints: i64,
    pub online_endpoints: i64,
    pub offline_endpoints: i64,
    pub critical_alerts: i64,
    pub total_threats_today: i64,
    pub average_security_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_threats: i64,
    pub by_severity: Vec<SeverityCount>,
    pub by_type: Vec<TypeCount>,
    pub top_affected_endpoints: Vec<EndpointThreatCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityCount {
    pub severity: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeCount {
    pub threat_type: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointThreatCount {
    pub endpoint_id: Uuid,
    pub hostname: String,
    pub threat_count: i64,
}
