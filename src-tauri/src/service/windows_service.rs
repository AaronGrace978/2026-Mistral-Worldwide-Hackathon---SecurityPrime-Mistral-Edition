// Cyber Security Prime - Windows Service Implementation
// Runs as a background service for always-on protection

#![cfg(windows)]

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::process::Command;
use std::os::windows::process::CommandExt;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use super::{ServiceConfig, ServiceEvent};

const SERVICE_NAME: &str = "SecurityPrimeService";
const SERVICE_DISPLAY_NAME: &str = "Security Prime Protection Service";
const SERVICE_DESCRIPTION: &str = "Provides real-time security monitoring and protection for Security Prime";

// Windows constant to hide console window when running sc.exe commands
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Helper to create a command with hidden console window
fn hidden_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

// Global shutdown flag
static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);

define_windows_service!(ffi_service_main, service_main);

/// Main entry point for the Windows service
pub fn run_service() -> Result<(), String> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| format!("Failed to start service dispatcher: {}", e))
}

/// Service main function - called by Windows
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service_impl() {
        eprintln!("Service error: {}", e);
    }
}

fn run_service_impl() -> Result<(), String> {
    // Register service control handler
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_flag_clone = shutdown_flag.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown_flag_clone.store(true, Ordering::SeqCst);
                SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .map_err(|e| format!("Failed to register service control handler: {}", e))?;

    // Set service to running
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|e| format!("Failed to set service status: {}", e))?;

    // Log service start
    log_event(ServiceEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: "service_started".to_string(),
        message: "Security Prime service started".to_string(),
        severity: "info".to_string(),
    });

    // Initialize database
    if let Err(e) = crate::database::initialize_database() {
        eprintln!("Warning: Failed to initialize database: {}", e);
    }

    // Load configuration
    let config = load_config();

    // Main service loop
    let mut last_scan_check = std::time::Instant::now();
    let mut last_heartbeat = std::time::Instant::now();

    while !shutdown_flag.load(Ordering::SeqCst) {
        // Check for IPC commands
        if let Some(response) = super::ipc::check_for_commands() {
            // Process command and send response
            let _ = super::ipc::send_response(response);
        }

        // Periodic monitoring tasks
        let now = std::time::Instant::now();

        // Network monitoring
        if config.network_monitoring {
            if let Err(e) = check_network_connections() {
                eprintln!("Network monitoring error: {}", e);
            }
        }

        // Periodic scan check (every hour by default)
        if config.auto_scan_enabled && now.duration_since(last_scan_check) > Duration::from_secs(3600) {
            if let Err(e) = run_quick_scan() {
                eprintln!("Auto scan error: {}", e);
            }
            last_scan_check = now;
        }

        // Heartbeat to MSP server
        if now.duration_since(last_heartbeat) > Duration::from_secs(config.heartbeat_interval_secs) {
            if let Err(e) = send_heartbeat() {
                eprintln!("Heartbeat error: {}", e);
            }
            last_heartbeat = now;
        }

        // Sleep to prevent busy-waiting
        std::thread::sleep(Duration::from_secs(config.monitoring_interval_secs.min(10)));
    }

    // Log service stop
    log_event(ServiceEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: "service_stopped".to_string(),
        message: "Security Prime service stopped".to_string(),
        severity: "info".to_string(),
    });

    // Set service to stopped
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .ok();

    Ok(())
}

/// Install the Windows service
pub fn install_service() -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get executable path: {}", e))?;

    // Use sc.exe to create the service (with hidden console)
    let output = hidden_command("sc")
        .args(&[
            "create",
            SERVICE_NAME,
            &format!("binPath= \"{}\" --service", exe_path.display()),
            &format!("DisplayName= {}", SERVICE_DISPLAY_NAME),
            "start= auto",
        ])
        .output()
        .map_err(|e| format!("Failed to execute sc command: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to create service: {}", stderr));
    }

    // Set service description
    let _ = hidden_command("sc")
        .args(&[
            "description",
            SERVICE_NAME,
            SERVICE_DESCRIPTION,
        ])
        .output();

    // Configure service recovery (restart on failure)
    let _ = hidden_command("sc")
        .args(&[
            "failure",
            SERVICE_NAME,
            "reset= 86400",
            "actions= restart/60000/restart/60000/restart/60000",
        ])
        .output();

    Ok(())
}

/// Uninstall the Windows service
pub fn uninstall_service() -> Result<(), String> {
    // Stop the service first (with hidden console)
    let _ = hidden_command("sc")
        .args(&["stop", SERVICE_NAME])
        .output();

    // Wait a bit for service to stop
    std::thread::sleep(Duration::from_secs(2));

    // Delete the service
    let output = hidden_command("sc")
        .args(&["delete", SERVICE_NAME])
        .output()
        .map_err(|e| format!("Failed to execute sc command: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to delete service: {}", stderr));
    }

    Ok(())
}

/// Start the service
pub fn start_service() -> Result<(), String> {
    let output = hidden_command("sc")
        .args(&["start", SERVICE_NAME])
        .output()
        .map_err(|e| format!("Failed to execute sc command: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to start service: {}", stderr));
    }

    Ok(())
}

/// Stop the service
pub fn stop_service() -> Result<(), String> {
    let output = hidden_command("sc")
        .args(&["stop", SERVICE_NAME])
        .output()
        .map_err(|e| format!("Failed to execute sc command: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to stop service: {}", stderr));
    }

    Ok(())
}

/// Check if service is installed
pub fn is_service_installed() -> bool {
    let output = hidden_command("sc")
        .args(&["query", SERVICE_NAME])
        .output();

    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Get service status
pub fn get_service_status() -> Result<String, String> {
    let output = hidden_command("sc")
        .args(&["query", SERVICE_NAME])
        .output()
        .map_err(|e| format!("Failed to query service: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse state from output
    for line in stdout.lines() {
        if line.contains("STATE") {
            if line.contains("RUNNING") {
                return Ok("running".to_string());
            } else if line.contains("STOPPED") {
                return Ok("stopped".to_string());
            } else if line.contains("PAUSED") {
                return Ok("paused".to_string());
            }
        }
    }

    Ok("unknown".to_string())
}

// ============================================================================
// Internal Functions
// ============================================================================

fn load_config() -> ServiceConfig {
    // Try to load from database settings
    if let Ok(Some(config_json)) = crate::database::get_setting("service_config") {
        if let Ok(config) = serde_json::from_str(&config_json) {
            return config;
        }
    }
    ServiceConfig::default()
}

fn log_event(event: ServiceEvent) {
    // Store event in database
    let activity = crate::database::models::ActivityRecord::new(
        event.event_type,
        event.message.clone(),
        event.message,
        event.severity,
        "service".to_string(),
    );
    let _ = crate::database::insert_activity(&activity);
}

fn check_network_connections() -> Result<(), String> {
    // Get current connections
    let connections = crate::modules::network::get_connections()?;
    
    // Check for suspicious connections
    let suspicious: Vec<_> = connections.iter()
        .filter(|c| {
            // Check for suspicious ports
            let suspicious_ports = [4444, 5555, 6666, 31337, 12345];
            suspicious_ports.contains(&c.remote_port)
        })
        .collect();
    
    if !suspicious.is_empty() {
        log_event(ServiceEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: "suspicious_connection".to_string(),
            message: format!("Detected {} suspicious network connections", suspicious.len()),
            severity: "high".to_string(),
        });
        
        // Store threat in database
        for conn in suspicious {
            let threat = crate::database::models::ThreatRecord {
                id: uuid::Uuid::new_v4().to_string(),
                scan_id: None,
                name: format!("Suspicious connection to {}:{}", conn.remote_address, conn.remote_port),
                severity: "high".to_string(),
                file_path: Some(conn.process_name.clone()),
                detected_at: chrono::Utc::now(),
                status: "detected".to_string(),
                action_taken: None,
            };
            let _ = crate::database::insert_threat(&threat);
        }
    }
    
    Ok(())
}

fn run_quick_scan() -> Result<(), String> {
    log_event(ServiceEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: "auto_scan_started".to_string(),
        message: "Starting automated quick scan".to_string(),
        severity: "info".to_string(),
    });
    
    // This would trigger the actual scan
    // For now, just log that we would scan
    
    Ok(())
}

fn send_heartbeat() -> Result<(), String> {
    // Check if MSP server is configured
    if let Ok(Some(_server_url)) = crate::database::get_setting("msp_server_url") {
        // TODO: Send heartbeat to MSP server
        // This will be implemented in the agent-heartbeat todo
    }
    Ok(())
}
