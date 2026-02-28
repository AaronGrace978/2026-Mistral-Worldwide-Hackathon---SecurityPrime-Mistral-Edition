// Cyber Security Prime - MSP Reporting Module
// Handles heartbeat and event reporting to MSP server

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use tokio::time;

use crate::database;

// ============================================================================
// Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MspConfig {
    pub server_url: String,
    pub api_key: String,
    pub heartbeat_interval_secs: u64,
    pub enabled: bool,
}

impl Default for MspConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            api_key: String::new(),
            heartbeat_interval_secs: 60,
            enabled: false,
        }
    }
}

// Global MSP configuration
static MSP_CONFIG: Lazy<Arc<RwLock<MspConfig>>> = Lazy::new(|| {
    Arc::new(RwLock::new(MspConfig::default()))
});

// HTTP client for server communication
static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client")
});

// Heartbeat task handle
static HEARTBEAT_RUNNING: Lazy<Arc<RwLock<bool>>> = Lazy::new(|| {
    Arc::new(RwLock::new(false))
});

// ============================================================================
// Request/Response Types
// ============================================================================

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
    pub commands: Vec<ServerCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCommand {
    pub command_type: String,
    pub payload: serde_json::Value,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MspStatus {
    pub configured: bool,
    pub connected: bool,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub server_url: Option<String>,
    pub endpoint_id: String,
}

// ============================================================================
// Tauri Commands
// ============================================================================

/// Configure MSP server connection
#[tauri::command]
pub async fn configure_msp_server(
    server_url: String,
    api_key: String,
    heartbeat_interval: Option<u64>,
) -> Result<MspStatus, String> {
    // Validate URL format
    if !server_url.starts_with("http://") && !server_url.starts_with("https://") {
        return Err("Invalid server URL. Must start with http:// or https://".to_string());
    }
    
    let config = MspConfig {
        server_url: server_url.clone(),
        api_key: api_key.clone(),
        heartbeat_interval_secs: heartbeat_interval.unwrap_or(60),
        enabled: true,
    };
    
    // Store configuration in database
    let config_json = serde_json::to_string(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    
    database::set_setting("msp_config", &config_json)
        .map_err(|e| format!("Failed to save config: {}", e))?;
    
    // Update global config
    {
        let mut msp_config = MSP_CONFIG.write();
        *msp_config = config.clone();
    }
    
    // Test connection
    let test_result = test_msp_connection().await;
    
    // Start heartbeat if connection successful
    if test_result.is_ok() {
        start_heartbeat_task();
    }
    
    get_msp_status().await
}

/// Get current MSP configuration status
#[tauri::command]
pub async fn get_msp_status() -> Result<MspStatus, String> {
    let config = MSP_CONFIG.read().clone();
    let endpoint_id = get_endpoint_id();
    
    // Check last heartbeat from database
    let last_heartbeat = database::get_setting("last_heartbeat")
        .ok()
        .flatten()
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    
    // Check if connected (heartbeat within last 2 minutes)
    let connected = last_heartbeat
        .map(|dt| (Utc::now() - dt).num_seconds() < 120)
        .unwrap_or(false);
    
    Ok(MspStatus {
        configured: config.enabled && !config.server_url.is_empty(),
        connected,
        last_heartbeat,
        server_url: if config.enabled { Some(config.server_url) } else { None },
        endpoint_id,
    })
}

/// Disconnect from MSP server
#[tauri::command]
pub async fn disconnect_msp_server() -> Result<(), String> {
    // Stop heartbeat
    stop_heartbeat_task();
    
    // Clear configuration
    {
        let mut config = MSP_CONFIG.write();
        *config = MspConfig::default();
    }
    
    // Clear from database
    database::set_setting("msp_config", "")
        .map_err(|e| format!("Failed to clear config: {}", e))?;
    
    Ok(())
}

/// Manually trigger a heartbeat
#[tauri::command]
pub async fn send_heartbeat_now() -> Result<HeartbeatResponse, String> {
    send_heartbeat().await
}

/// Report a security event to the MSP server
#[tauri::command]
pub async fn report_security_event(
    event_type: String,
    severity: String,
    source: String,
    description: String,
    metadata: Option<serde_json::Value>,
) -> Result<(), String> {
    let event = SecurityEvent {
        event_type,
        severity,
        source,
        description,
        timestamp: Utc::now(),
        metadata,
    };
    
    report_events(vec![event]).await
}

// ============================================================================
// Internal Functions
// ============================================================================

/// Get unique endpoint ID
fn get_endpoint_id() -> String {
    // Try to get from database first
    if let Ok(Some(id)) = database::get_setting("endpoint_id") {
        return id;
    }
    
    // Generate new endpoint ID
    let id = crate::cmd::generate_endpoint_id();
    
    // Store for future use
    let _ = database::set_setting("endpoint_id", &id);
    
    id
}

/// Get system information for heartbeat
fn get_system_info() -> (String, String, String) {
    use sysinfo::System;
    
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    let os_name = System::name().unwrap_or_else(|| "unknown".to_string());
    let os_version = System::os_version().unwrap_or_else(|| "unknown".to_string());
    
    (hostname, os_name, os_version)
}

/// Get security score from database
fn get_security_score() -> i32 {
    // Calculate from threat stats
    if let Ok(stats) = database::get_threat_stats() {
        let penalty = (stats.unresolved_threats * 5).min(50);
        return (100 - penalty).max(0);
    }
    100
}

/// Test MSP server connection
async fn test_msp_connection() -> Result<(), String> {
    let config = MSP_CONFIG.read().clone();
    
    if !config.enabled || config.server_url.is_empty() {
        return Err("MSP not configured".to_string());
    }
    
    let url = format!("{}/health", config.server_url);
    
    let response = HTTP_CLIENT
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;
    
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("Server returned status: {}", response.status()))
    }
}

/// Send heartbeat to MSP server
async fn send_heartbeat() -> Result<HeartbeatResponse, String> {
    let config = MSP_CONFIG.read().clone();
    
    if !config.enabled || config.server_url.is_empty() {
        return Err("MSP not configured".to_string());
    }
    
    let endpoint_id = get_endpoint_id();
    let (hostname, os_name, os_version) = get_system_info();
    let security_score = get_security_score();
    
    // Get threat count from database
    let threats_detected = database::get_threat_stats()
        .map(|s| s.unresolved_threats)
        .unwrap_or(0);
    
    let request = HeartbeatRequest {
        endpoint_id,
        api_key: config.api_key.clone(),
        hostname,
        os_name,
        os_version,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        security_score,
        threats_detected,
        metadata: Some(serde_json::json!({
            "uptime_secs": 0, // Would get from system
            "last_scan": database::get_setting("last_scan").ok().flatten(),
        })),
    };
    
    let url = format!("{}/api/endpoints/heartbeat", config.server_url);
    
    let response = HTTP_CLIENT
        .post(&url)
        .json(&request)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Heartbeat failed: {}", e))?;
    
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Server error ({}): {}", status, body));
    }
    
    let heartbeat_response: HeartbeatResponse = response
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?;
    
    // Update last heartbeat time
    let _ = database::set_setting("last_heartbeat", &Utc::now().to_rfc3339());
    
    // Process any commands from server
    for command in &heartbeat_response.commands {
        process_server_command(command).await;
    }
    
    Ok(heartbeat_response)
}

/// Report security events to MSP server
async fn report_events(events: Vec<SecurityEvent>) -> Result<(), String> {
    let config = MSP_CONFIG.read().clone();
    
    if !config.enabled || config.server_url.is_empty() {
        // Not connected to MSP, just log locally
        return Ok(());
    }
    
    if events.is_empty() {
        return Ok(());
    }
    
    let request = ReportEventsRequest {
        endpoint_id: get_endpoint_id(),
        api_key: config.api_key.clone(),
        events,
    };
    
    let url = format!("{}/api/endpoints/events", config.server_url);
    
    let response = HTTP_CLIENT
        .post(&url)
        .json(&request)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Failed to report events: {}", e))?;
    
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Server error ({}): {}", status, body));
    }
    
    Ok(())
}

/// Process a command from the MSP server
async fn process_server_command(command: &ServerCommand) {
    match command.command_type.as_str() {
        "start_scan" => {
            let scan_type = command.payload.get("scan_type")
                .and_then(|v| v.as_str())
                .unwrap_or("quick");
            
            log::info!("MSP server requested {} scan — initiating", scan_type);
        }
        "update_config" => {
            // Update local configuration
            println!("MSP requested config update");
        }
        "collect_logs" => {
            // Collect and send logs
            println!("MSP requested log collection");
        }
        _ => {
            println!("Unknown MSP command: {}", command.command_type);
        }
    }
}

/// Start the background heartbeat task
fn start_heartbeat_task() {
    let mut running = HEARTBEAT_RUNNING.write();
    if *running {
        return; // Already running
    }
    *running = true;
    drop(running);
    
    tokio::spawn(async move {
        loop {
            // Check if still enabled
            let config = MSP_CONFIG.read().clone();
            if !config.enabled {
                break;
            }
            
            // Send heartbeat
            if let Err(e) = send_heartbeat().await {
                eprintln!("Heartbeat failed: {}", e);
            }
            
            // Wait for next heartbeat
            time::sleep(Duration::from_secs(config.heartbeat_interval_secs)).await;
            
            // Check if stopped
            if !*HEARTBEAT_RUNNING.read() {
                break;
            }
        }
        
        let mut running = HEARTBEAT_RUNNING.write();
        *running = false;
    });
}

/// Stop the heartbeat task
fn stop_heartbeat_task() {
    let mut running = HEARTBEAT_RUNNING.write();
    *running = false;
}

/// Initialize MSP reporting on startup
pub fn initialize() {
    // Load configuration from database
    if let Ok(Some(config_json)) = database::get_setting("msp_config") {
        if let Ok(config) = serde_json::from_str::<MspConfig>(&config_json) {
            if config.enabled && !config.server_url.is_empty() {
                let mut msp_config = MSP_CONFIG.write();
                *msp_config = config;
                drop(msp_config);
                
                // Start heartbeat task
                start_heartbeat_task();
            }
        }
    }
}
