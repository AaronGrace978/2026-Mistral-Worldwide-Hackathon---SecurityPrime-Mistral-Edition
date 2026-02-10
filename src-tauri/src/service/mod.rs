// Cyber Security Prime - Windows Service Module
// Provides background monitoring as a Windows service

#[cfg(windows)]
pub mod windows_service;

#[cfg(windows)]
pub mod ipc;

use serde::{Deserialize, Serialize};

/// Service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub monitoring_interval_secs: u64,
    pub heartbeat_interval_secs: u64,
    pub auto_scan_enabled: bool,
    pub real_time_protection: bool,
    pub network_monitoring: bool,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            monitoring_interval_secs: 60,
            heartbeat_interval_secs: 30,
            auto_scan_enabled: true,
            real_time_protection: true,
            network_monitoring: true,
        }
    }
}

/// Service status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub running: bool,
    pub uptime_secs: u64,
    pub last_scan: Option<String>,
    pub threats_detected_today: u32,
    pub connections_monitored: u32,
    pub events_processed: u64,
}

/// Commands that can be sent to the service via IPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceCommand {
    /// Get current service status
    GetStatus,
    /// Start a scan
    StartScan { scan_type: String },
    /// Stop current scan
    StopScan,
    /// Update configuration
    UpdateConfig(ServiceConfig),
    /// Force heartbeat to MSP server
    ForceHeartbeat,
    /// Shutdown the service
    Shutdown,
}

/// Response from service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceResponse {
    Status(ServiceStatus),
    ScanStarted { scan_id: String },
    ScanStopped,
    ConfigUpdated,
    HeartbeatSent,
    Error(String),
    Ok,
}

/// Service events for logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEvent {
    pub timestamp: String,
    pub event_type: String,
    pub message: String,
    pub severity: String,
}
