// Cyber Security Prime - Utility Functions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Generate a new unique ID
pub fn generate_id() -> String {
    Uuid::new_v4().to_string()
}

/// Get the current timestamp
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// Format a timestamp for display
pub fn format_timestamp(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Severity levels for security events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Status for various security modules
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ModuleStatus {
    Active,
    Inactive,
    Warning,
    Error,
    Scanning,
}

impl ModuleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ModuleStatus::Active => "active",
            ModuleStatus::Inactive => "inactive",
            ModuleStatus::Warning => "warning",
            ModuleStatus::Error => "error",
            ModuleStatus::Scanning => "scanning",
        }
    }
}

/// Activity event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityType {
    ScanStarted,
    ScanCompleted,
    ThreatDetected,
    ThreatQuarantined,
    FirewallBlocked,
    FileEncrypted,
    FileDecrypted,
    VulnerabilityFound,
    SystemUpdate,
    SettingsChanged,
    ModuleEnabled,
    ModuleDisabled,
}

/// A security activity event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub id: String,
    pub event_type: ActivityType,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub timestamp: DateTime<Utc>,
    pub module: String,
}

impl ActivityEvent {
    pub fn new(
        event_type: ActivityType,
        title: &str,
        description: &str,
        severity: Severity,
        module: &str,
    ) -> Self {
        Self {
            id: generate_id(),
            event_type,
            title: title.to_string(),
            description: description.to_string(),
            severity,
            timestamp: now(),
            module: module.to_string(),
        }
    }
}

/// A threat alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub resolved: bool,
}

impl ThreatAlert {
    pub fn new(title: &str, description: &str, severity: Severity, source: &str) -> Self {
        Self {
            id: generate_id(),
            title: title.to_string(),
            description: description.to_string(),
            severity,
            source: source.to_string(),
            timestamp: now(),
            resolved: false,
        }
    }
}

/// Application settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub theme: String,
    pub auto_start: bool,
    pub real_time_protection: bool,
    pub auto_update: bool,
    pub notifications_enabled: bool,
    pub scan_on_startup: bool,
    pub modules_enabled: ModulesEnabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModulesEnabled {
    pub scanner: bool,
    pub firewall: bool,
    pub encryption: bool,
    pub vulnerability: bool,
    pub network: bool,
    pub vpn: bool,
    pub agent: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            auto_start: false,
            real_time_protection: true,
            auto_update: true,
            notifications_enabled: true,
            scan_on_startup: false,
            modules_enabled: ModulesEnabled {
                scanner: true,
                firewall: true,
                encryption: true,
                vulnerability: true,
                network: true,
                vpn: true,
                agent: true,
            },
        }
    }
}

