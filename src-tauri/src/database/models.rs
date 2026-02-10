// Cyber Security Prime - Database Models
// Data structures for SQLite persistence

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Scan record stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: String,
    pub scan_type: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub threats_found: i32,
    pub files_scanned: i64,
}

impl ScanRecord {
    pub fn new(id: String, scan_type: String) -> Self {
        Self {
            id,
            scan_type,
            status: "running".to_string(),
            started_at: Utc::now(),
            completed_at: None,
            threats_found: 0,
            files_scanned: 0,
        }
    }
}

/// Threat record stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatRecord {
    pub id: String,
    pub scan_id: Option<String>,
    pub name: String,
    pub severity: String,
    pub file_path: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub status: String,
    pub action_taken: Option<String>,
}

impl ThreatRecord {
    pub fn new(id: String, name: String, severity: String) -> Self {
        Self {
            id,
            scan_id: None,
            name,
            severity,
            file_path: None,
            detected_at: Utc::now(),
            status: "detected".to_string(),
            action_taken: None,
        }
    }
}

/// Activity log record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityRecord {
    pub id: String,
    pub event_type: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub module: String,
    pub timestamp: DateTime<Utc>,
}

impl ActivityRecord {
    pub fn new(event_type: String, title: String, description: String, severity: String, module: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            event_type,
            title,
            description,
            severity,
            module,
            timestamp: Utc::now(),
        }
    }
}

/// License record stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseRecord {
    pub id: i32,
    pub license_key: String,
    pub organization_id: Option<String>,
    pub organization_name: Option<String>,
    pub activated_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub endpoint_id: Option<String>,
    pub max_endpoints: Option<i32>,
    pub features: String,
}

impl LicenseRecord {
    pub fn new(license_key: String) -> Self {
        Self {
            id: 1,
            license_key,
            organization_id: None,
            organization_name: None,
            activated_at: None,
            expires_at: None,
            endpoint_id: None,
            max_endpoints: None,
            features: String::new(),
        }
    }
    
    pub fn is_valid(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            return expires_at > Utc::now();
        }
        false
    }
    
    pub fn get_features(&self) -> Vec<String> {
        self.features
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect()
    }
}

/// Threat statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatStats {
    pub total_threats: i32,
    pub threats_today: i32,
    pub threats_this_week: i32,
    pub unresolved_threats: i32,
    pub by_severity: HashMap<String, i32>,
}

/// Firewall rule record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleRecord {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub direction: String,
    pub action: String,
    pub protocol: String,
    pub local_port: Option<String>,
    pub remote_port: Option<String>,
    pub remote_address: Option<String>,
    pub application: Option<String>,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

/// Network connection record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionRecord {
    pub id: String,
    pub process_name: String,
    pub process_id: u32,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub timestamp: DateTime<Utc>,
}

/// Endpoint information for MSP management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub endpoint_id: String,
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub last_seen: DateTime<Utc>,
    pub security_score: i32,
    pub threats_detected: i32,
    pub status: String,
}

impl EndpointInfo {
    pub fn new(endpoint_id: String, hostname: String, os_name: String, os_version: String) -> Self {
        Self {
            endpoint_id,
            hostname,
            os_name,
            os_version,
            last_seen: Utc::now(),
            security_score: 100,
            threats_detected: 0,
            status: "online".to_string(),
        }
    }
}
