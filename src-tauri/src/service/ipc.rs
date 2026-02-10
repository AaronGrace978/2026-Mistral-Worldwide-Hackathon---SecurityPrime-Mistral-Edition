// Cyber Security Prime - IPC Communication
// Inter-process communication between service and GUI

#![cfg(windows)]

use std::io::{Read, Write};

use super::{ServiceCommand, ServiceResponse, ServiceStatus};

const PIPE_NAME: &str = r"\\.\pipe\SecurityPrimeService";
const PIPE_TIMEOUT_MS: u32 = 5000;

/// Check for incoming commands from the GUI
pub fn check_for_commands() -> Option<ServiceResponse> {
    // In a real implementation, this would listen on a named pipe
    // For now, return None (no commands)
    None
}

/// Send a response back to the GUI
pub fn send_response(_response: ServiceResponse) -> Result<(), String> {
    // In a real implementation, this would send via named pipe
    Ok(())
}

/// Client-side: Send a command to the service and get a response
pub fn send_command(command: ServiceCommand) -> Result<ServiceResponse, String> {
    use std::fs::OpenOptions;
    
    // Try to connect to the named pipe
    let mut pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE_NAME)
        .map_err(|e| format!("Failed to connect to service: {}. Is the service running?", e))?;
    
    // Serialize and send command
    let command_json = serde_json::to_string(&command)
        .map_err(|e| format!("Failed to serialize command: {}", e))?;
    
    pipe.write_all(command_json.as_bytes())
        .map_err(|e| format!("Failed to send command: {}", e))?;
    
    pipe.write_all(b"\n")
        .map_err(|e| format!("Failed to send command: {}", e))?;
    
    // Read response
    let mut response_buf = String::new();
    pipe.read_to_string(&mut response_buf)
        .map_err(|e| format!("Failed to read response: {}", e))?;
    
    // Parse response
    serde_json::from_str(&response_buf)
        .map_err(|e| format!("Failed to parse response: {}", e))
}

/// Check if the service is responding
pub fn is_service_responding() -> bool {
    match send_command(ServiceCommand::GetStatus) {
        Ok(ServiceResponse::Status(_)) => true,
        _ => false,
    }
}

/// Get service status via IPC
pub fn get_service_status_ipc() -> Result<ServiceStatus, String> {
    match send_command(ServiceCommand::GetStatus)? {
        ServiceResponse::Status(status) => Ok(status),
        ServiceResponse::Error(e) => Err(e),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Request a scan via IPC
pub fn request_scan(scan_type: String) -> Result<String, String> {
    match send_command(ServiceCommand::StartScan { scan_type })? {
        ServiceResponse::ScanStarted { scan_id } => Ok(scan_id),
        ServiceResponse::Error(e) => Err(e),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Stop a scan via IPC
pub fn stop_scan() -> Result<(), String> {
    match send_command(ServiceCommand::StopScan)? {
        ServiceResponse::ScanStopped => Ok(()),
        ServiceResponse::Error(e) => Err(e),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Force heartbeat via IPC
pub fn force_heartbeat() -> Result<(), String> {
    match send_command(ServiceCommand::ForceHeartbeat)? {
        ServiceResponse::HeartbeatSent => Ok(()),
        ServiceResponse::Error(e) => Err(e),
        _ => Err("Unexpected response".to_string()),
    }
}
