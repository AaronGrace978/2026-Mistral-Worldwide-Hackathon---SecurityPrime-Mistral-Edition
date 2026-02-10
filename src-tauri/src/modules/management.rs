// Cyber Security Prime - Enterprise Management Module
// Provides centralized management capabilities for enterprise deployments

use crate::modules::{SecurityModule, ModuleHealth};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use uuid::Uuid;

// Global management state
static MANAGEMENT_STATE: Lazy<Mutex<ManagementState>> = Lazy::new(|| Mutex::new(ManagementState::new()));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementState {
    pub instances: HashMap<String, ManagedInstance>,
    pub users: HashMap<String, User>,
    pub audit_logs: Vec<AuditEntry>,
    pub policies: HashMap<String, SecurityPolicy>,
    pub alerts: Vec<ManagementAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedInstance {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub status: InstanceStatus,
    pub last_heartbeat: DateTime<Utc>,
    pub version: String,
    pub modules: Vec<String>,
    pub config: InstanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceConfig {
    pub auto_update: bool,
    pub monitoring_enabled: bool,
    pub alert_thresholds: AlertThresholds,
    pub compliance_settings: ComplianceSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_usage: f32,
    pub threat_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSettings {
    pub gdpr_enabled: bool,
    pub hipaa_enabled: bool,
    pub pci_dss_enabled: bool,
    pub auto_reporting: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InstanceStatus {
    Online,
    Offline,
    Maintenance,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: UserRole,
    pub permissions: Vec<String>,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserRole {
    Admin,
    Manager,
    Analyst,
    Auditor,
    ReadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub action: String,
    pub resource: String,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub rules: Vec<PolicyRule>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub condition: String,
    pub action: String,
    pub severity: String,
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementAlert {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub level: AlertLevel,
    pub title: String,
    pub message: String,
    pub instance_id: Option<String>,
    pub resolved: bool,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertLevel {
    Info,
    Warning,
    Error,
    Critical,
}

impl ManagementState {
    fn new() -> Self {
        Self {
            instances: HashMap::new(),
            users: HashMap::new(),
            audit_logs: Vec::new(),
            policies: HashMap::new(),
            alerts: Vec::new(),
        }
    }
}

pub struct ManagementModule {
    pub name: &'static str,
    pub description: &'static str,
    pub version: &'static str,
    pub active: bool,
}

impl Default for ManagementModule {
    fn default() -> Self {
        Self {
            name: "Enterprise Management",
            description: "Centralized management console for enterprise deployments",
            version: "1.0.0",
            active: true,
        }
    }
}

impl SecurityModule for ManagementModule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn description(&self) -> &'static str {
        self.description
    }

    fn is_active(&self) -> bool {
        self.active
    }

    fn initialize(&mut self) -> Result<(), String> {
        // Initialize default policies
        let mut state = MANAGEMENT_STATE.lock().unwrap();
        self.initialize_default_policies(&mut state);

        // Create default admin user if none exists
        if state.users.is_empty() {
            self.create_default_admin(&mut state);
        }

        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn health_check(&self) -> ModuleHealth {
        ModuleHealth {
            healthy: true,
            message: "Management module is operational".to_string(),
            last_check: Utc::now().to_rfc3339(),
        }
    }
}

impl ManagementModule {
    fn initialize_default_policies(&self, state: &mut ManagementState) {
        let policies = vec![
            SecurityPolicy {
                id: "password-policy".to_string(),
                name: "Password Security Policy".to_string(),
                description: "Enforces strong password requirements".to_string(),
                rules: vec![
                    PolicyRule {
                        id: "min-length".to_string(),
                        condition: "password_length < 12".to_string(),
                        action: "reject".to_string(),
                        severity: "high".to_string(),
                        parameters: HashMap::new(),
                    },
                ],
                enabled: true,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            SecurityPolicy {
                id: "access-control".to_string(),
                name: "Access Control Policy".to_string(),
                description: "Controls user access to sensitive resources".to_string(),
                rules: vec![
                    PolicyRule {
                        id: "admin-only".to_string(),
                        condition: "user_role != 'admin'".to_string(),
                        action: "deny".to_string(),
                        severity: "critical".to_string(),
                        parameters: HashMap::new(),
                    },
                ],
                enabled: true,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ];

        for policy in policies {
            state.policies.insert(policy.id.clone(), policy);
        }
    }

    fn create_default_admin(&self, state: &mut ManagementState) {
        let admin = User {
            id: Uuid::new_v4().to_string(),
            username: "admin".to_string(),
            email: "admin@securityprime.local".to_string(),
            role: UserRole::Admin,
            permissions: vec![
                "manage_users".to_string(),
                "manage_instances".to_string(),
                "view_audit_logs".to_string(),
                "manage_policies".to_string(),
                "view_reports".to_string(),
            ],
            last_login: None,
            created_at: Utc::now(),
        };

        state.users.insert(admin.id.clone(), admin);
    }
}

// Tauri commands for management console
#[tauri::command]
pub fn get_managed_instances() -> Result<Vec<ManagedInstance>, String> {
    let state = MANAGEMENT_STATE.lock().unwrap();
    Ok(state.instances.values().cloned().collect())
}

#[tauri::command]
pub fn register_instance(name: String, endpoint: String, config: InstanceConfig) -> Result<String, String> {
    let mut state = MANAGEMENT_STATE.lock().unwrap();
    let instance_id = Uuid::new_v4().to_string();

    let instance = ManagedInstance {
        id: instance_id.clone(),
        name,
        endpoint,
        status: InstanceStatus::Online,
        last_heartbeat: Utc::now(),
        version: "1.0.0".to_string(),
        modules: vec![],
        config,
    };

    state.instances.insert(instance_id.clone(), instance);
    Ok(instance_id)
}

#[tauri::command]
pub fn update_instance_status(instance_id: String, status: InstanceStatus) -> Result<(), String> {
    let mut state = MANAGEMENT_STATE.lock().unwrap();

    if let Some(instance) = state.instances.get_mut(&instance_id) {
        instance.status = status;
        instance.last_heartbeat = Utc::now();
        Ok(())
    } else {
        Err(format!("Instance {} not found", instance_id))
    }
}

#[tauri::command]
pub fn get_users() -> Result<Vec<User>, String> {
    let state = MANAGEMENT_STATE.lock().unwrap();
    Ok(state.users.values().cloned().collect())
}

#[tauri::command]
pub fn create_user(username: String, email: String, role: UserRole) -> Result<String, String> {
    let mut state = MANAGEMENT_STATE.lock().unwrap();

    // Check if username or email already exists
    if state.users.values().any(|u| u.username == username) {
        return Err("Username already exists".to_string());
    }
    if state.users.values().any(|u| u.email == email) {
        return Err("Email already exists".to_string());
    }

    let user_id = Uuid::new_v4().to_string();
    let permissions = match role {
        UserRole::Admin => vec![
            "manage_users".to_string(),
            "manage_instances".to_string(),
            "view_audit_logs".to_string(),
            "manage_policies".to_string(),
            "view_reports".to_string(),
        ],
        UserRole::Manager => vec![
            "manage_instances".to_string(),
            "view_audit_logs".to_string(),
            "view_reports".to_string(),
        ],
        UserRole::Analyst => vec![
            "view_audit_logs".to_string(),
            "view_reports".to_string(),
        ],
        UserRole::Auditor => vec![
            "view_audit_logs".to_string(),
        ],
        UserRole::ReadOnly => vec![
            "view_reports".to_string(),
        ],
    };

    let user = User {
        id: user_id.clone(),
        username,
        email,
        role,
        permissions,
        last_login: None,
        created_at: Utc::now(),
    };

    state.users.insert(user_id.clone(), user);
    Ok(user_id)
}

#[tauri::command]
pub fn get_audit_logs(limit: Option<usize>) -> Result<Vec<AuditEntry>, String> {
    let state = MANAGEMENT_STATE.lock().unwrap();
    let limit = limit.unwrap_or(100);
    let mut logs = state.audit_logs.clone();
    logs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    logs.truncate(limit);
    Ok(logs)
}

#[tauri::command]
pub fn log_audit_event(user_id: String, action: String, resource: String, details: serde_json::Value) -> Result<(), String> {
    let mut state = MANAGEMENT_STATE.lock().unwrap();

    let entry = AuditEntry {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        user_id,
        action,
        resource,
        details,
        ip_address: None, // Would be populated from request context in a real implementation
        user_agent: None,
    };

    state.audit_logs.push(entry);
    Ok(())
}

#[tauri::command]
pub fn get_security_policies() -> Result<Vec<SecurityPolicy>, String> {
    let state = MANAGEMENT_STATE.lock().unwrap();
    Ok(state.policies.values().cloned().collect())
}

#[tauri::command]
pub fn create_security_policy(name: String, description: String, rules: Vec<PolicyRule>) -> Result<String, String> {
    let mut state = MANAGEMENT_STATE.lock().unwrap();
    let policy_id = Uuid::new_v4().to_string();

    let policy = SecurityPolicy {
        id: policy_id.clone(),
        name,
        description,
        rules,
        enabled: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    state.policies.insert(policy_id.clone(), policy);
    Ok(policy_id)
}

#[tauri::command]
pub fn get_management_alerts() -> Result<Vec<ManagementAlert>, String> {
    let state = MANAGEMENT_STATE.lock().unwrap();
    Ok(state.alerts.clone())
}

#[tauri::command]
pub fn create_management_alert(level: AlertLevel, title: String, message: String, instance_id: Option<String>) -> Result<String, String> {
    let mut state = MANAGEMENT_STATE.lock().unwrap();
    let alert_id = Uuid::new_v4().to_string();

    let alert = ManagementAlert {
        id: alert_id.clone(),
        timestamp: Utc::now(),
        level,
        title,
        message,
        instance_id,
        resolved: false,
        resolved_at: None,
    };

    state.alerts.push(alert);
    Ok(alert_id)
}

#[tauri::command]
pub fn resolve_management_alert(alert_id: String) -> Result<(), String> {
    let mut state = MANAGEMENT_STATE.lock().unwrap();

    if let Some(alert) = state.alerts.iter_mut().find(|a| a.id == alert_id) {
        alert.resolved = true;
        alert.resolved_at = Some(Utc::now());
        Ok(())
    } else {
        Err(format!("Alert {} not found", alert_id))
    }
}

#[tauri::command]
pub fn get_management_dashboard_data() -> Result<serde_json::Value, String> {
    let state = MANAGEMENT_STATE.lock().unwrap();

    let dashboard_data = serde_json::json!({
        "total_instances": state.instances.len(),
        "online_instances": state.instances.values().filter(|i| i.status == InstanceStatus::Online).count(),
        "total_users": state.users.len(),
        "active_alerts": state.alerts.iter().filter(|a| !a.resolved).count(),
        "recent_audit_entries": state.audit_logs.len().min(10),
        "policies_count": state.policies.len()
    });

    Ok(dashboard_data)
}