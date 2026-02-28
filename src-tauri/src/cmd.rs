// Cyber Security Prime - Tauri Command Handlers

use crate::modules::{encryption, firewall, network, scanner, vulnerability};
use crate::utils::{generate_id, ActivityEvent, ActivityType, AppSettings, ModuleStatus, Severity, ThreatAlert};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Disks, System};
use tauri::Manager;
use tokio::time;

// Global state for the application
static APP_STATE: Lazy<RwLock<AppState>> = Lazy::new(|| RwLock::new(AppState::default()));

// Maximum number of activities/alerts to keep in memory
const MAX_ACTIVITIES: usize = 100;
const MAX_ALERTS: usize = 50;

#[derive(Debug, Clone, Default)]
struct AppState {
    settings: AppSettings,
    activities: Vec<ActivityEvent>,
    alerts: Vec<ThreatAlert>,
    module_statuses: HashMap<String, ModuleStatus>,
}

// ============================================================================
// Cached System Instance for Performance
// ============================================================================

/// Cached system information to avoid expensive System::new_all() calls
/// The system info is refreshed periodically rather than recreated each time
struct CachedSystem {
    system: System,
    last_refresh: std::time::Instant,
}

impl CachedSystem {
    fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        Self {
            system,
            last_refresh: std::time::Instant::now(),
        }
    }

    /// Get a reference to the system, refreshing if stale (older than 2 seconds)
    fn get_refreshed(&mut self) -> &System {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_refresh).as_secs() >= 2 {
            self.system.refresh_all();
            self.last_refresh = now;
        }
        &self.system
    }

    /// Force a full refresh of system data
    fn force_refresh(&mut self) -> &System {
        self.system.refresh_all();
        self.last_refresh = std::time::Instant::now();
        &self.system
    }

    /// Refresh only CPU info (lightweight)
    fn refresh_cpu(&mut self) -> &System {
        self.system.refresh_cpu();
        &self.system
    }

    /// Refresh only memory info (lightweight)
    fn refresh_memory(&mut self) -> &System {
        self.system.refresh_memory();
        &self.system
    }

    /// Refresh only processes (medium weight)
    fn refresh_processes(&mut self) -> &System {
        self.system.refresh_processes();
        &self.system
    }
}

static CACHED_SYSTEM: Lazy<Arc<RwLock<CachedSystem>>> = Lazy::new(|| {
    Arc::new(RwLock::new(CachedSystem::new()))
});

// ============================================================================
// System Information
// ============================================================================

#[derive(Debug, Serialize)]
pub struct DriveInfo {
    pub name: String,
    pub mount_point: String,
    pub total_space_gb: f64,
    pub available_space_gb: f64,
    pub used_space_gb: f64,
    pub health_status: String, // "healthy", "warning", "critical", "unknown"
    pub file_system: String,
    pub smart_health: Option<SmartHealth>,
}

#[derive(Debug, Serialize)]
pub struct SmartHealth {
    pub overall_health: String, // "good", "caution", "bad"
    pub temperature: Option<f32>,
    pub power_on_hours: Option<u64>,
    pub reallocated_sectors: Option<u64>,
    pub pending_sectors: Option<u64>,
    pub uncorrectable_errors: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct HardwareSensors {
    pub cpu_temperature: Option<f32>,
    pub gpu_temperature: Option<f32>,
    pub motherboard_temperature: Option<f32>,
    pub fan_speeds: Vec<FanSpeed>,
}

#[derive(Debug, Serialize)]
pub struct FanSpeed {
    pub name: String,
    pub speed_rpm: u32,
}

#[derive(Debug, Serialize)]
pub struct NetworkStats {
    pub interface_name: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub errors_in: u64,
    pub errors_out: u64,
}

#[derive(Debug, Serialize)]
pub struct AdvancedSystemInfo {
    pub sensors: HardwareSensors,
    pub network_interfaces: Vec<NetworkStats>,
    pub system_load: SystemLoad,
}

#[derive(Debug, Serialize)]
pub struct SystemLoad {
    pub cpu_usage_percent: f32,
    pub memory_usage_percent: f32,
    pub disk_io_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    SuspiciousProcess,
    HighCpuUsage,
    HighMemoryUsage,
    UnusualNetworkActivity,
    DriveSpaceCritical,
    TemperatureWarning,
    NewProcess,
    ProcessTerminated,
    FileSystemChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub event_type: SecurityEventType,
    pub title: String,
    pub description: String,
    pub severity: String, // "low", "medium", "high", "critical"
    pub timestamp: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct MonitoringStatus {
    pub is_active: bool,
    pub last_check: String,
    pub total_events: u64,
    pub alerts_today: u64,
}

#[derive(Debug)]
struct MonitoringState {
    is_active: bool,
    last_cpu_usage: f32,
    last_memory_usage: f32,
    baseline_processes: HashMap<String, u64>, // process_name -> pid
    network_baseline: HashMap<String, u64>, // interface -> bytes_total
    events_count: u64,
}

impl Default for MonitoringState {
    fn default() -> Self {
        Self {
            is_active: false,
            last_cpu_usage: 0.0,
            last_memory_usage: 0.0,
            baseline_processes: HashMap::new(),
            network_baseline: HashMap::new(),
            events_count: 0,
        }
    }
}

static MONITORING_STATE: Lazy<Arc<RwLock<MonitoringState>>> = Lazy::new(|| Arc::new(RwLock::new(MonitoringState::default())));

#[derive(Debug, Serialize)]
pub struct SystemInfo {
    pub os_name: String,
    pub os_version: String,
    pub hostname: String,
    pub cpu_cores: usize,
    pub total_memory_gb: f64,
    pub available_memory_gb: f64,
    pub used_memory_gb: f64,
    pub drives: Vec<DriveInfo>,
    pub advanced: AdvancedSystemInfo,
}

fn get_drive_health_status(total_space: u64, available_space: u64) -> String {
    let available_gb = available_space as f64 / 1_073_741_824.0; // Convert bytes to GB
    let total_gb = total_space as f64 / 1_073_741_824.0;
    let used_percentage = ((total_gb - available_gb) / total_gb) * 100.0;

    // Simple health heuristics - can be expanded with SMART data
    if used_percentage > 95.0 {
        "critical".to_string()
    } else if used_percentage > 85.0 {
        "warning".to_string()
    } else {
        "healthy".to_string()
    }
}

async fn get_hardware_sensors() -> HardwareSensors {
    let mut sensors = HardwareSensors {
        cpu_temperature: None,
        gpu_temperature: None,
        motherboard_temperature: None,
        fan_speeds: Vec::new(),
    };

    // Simplified sensor detection - in production, would use platform-specific APIs
    // For now, return mock data
    sensors.cpu_temperature = Some(45.2);
    sensors.gpu_temperature = Some(52.8);
    sensors.motherboard_temperature = Some(38.5);

    // Try to get NVIDIA GPU info if available
    if let Ok(nvml) = nvml_wrapper::Nvml::init() {
        if let Ok(device) = nvml.device_by_index(0) {
            if let Ok(temp) = device.temperature(nvml_wrapper::enum_wrappers::device::TemperatureSensor::Gpu) {
                sensors.gpu_temperature = Some(temp as f32);
            }
        }
    }

    sensors
}

async fn get_network_interfaces_stats() -> Vec<NetworkStats> {
    // Simplified network stats - in production, would use platform-specific APIs
    // For now, return mock data
    vec![
        NetworkStats {
            interface_name: "Ethernet".to_string(),
            bytes_sent: 1547892340,
            bytes_received: 2894567890,
            packets_sent: 1234567,
            packets_received: 2345678,
            errors_in: 0,
            errors_out: 0,
        },
        NetworkStats {
            interface_name: "Wi-Fi".to_string(),
            bytes_sent: 456789123,
            bytes_received: 789456123,
            packets_sent: 345678,
            packets_received: 567890,
            errors_in: 2,
            errors_out: 0,
        },
    ]
}

fn get_smart_health() -> Option<SmartHealth> {
    // SMART data is complex and platform-specific
    // For now, return None - would need platform-specific implementation
    // Windows: Use DeviceIoControl with IOCTL_STORAGE_QUERY_PROPERTY
    // Linux: Use smartctl or libatasmart
    None
}

#[tauri::command]
pub async fn get_system_info() -> Result<SystemInfo, String> {
    // Use cached system instance instead of creating new one each time
    let (total_memory_gb, available_memory_gb, used_memory_gb, cpu_cores, system_load) = {
        let mut cached = CACHED_SYSTEM.write();
        let sys = cached.get_refreshed();
        
        let total_memory_gb = sys.total_memory() as f64 / 1_073_741_824.0;
        let available_memory_gb = sys.available_memory() as f64 / 1_073_741_824.0;
        let used_memory_gb = total_memory_gb - available_memory_gb;
        let cpu_cores = sys.cpus().len();
        
        let cpu_usage = sys.global_cpu_info().cpu_usage() as f32;
        let memory_usage = ((sys.total_memory() - sys.available_memory()) as f32 / sys.total_memory() as f32) * 100.0;
        
        let system_load = SystemLoad {
            cpu_usage_percent: cpu_usage,
            memory_usage_percent: memory_usage,
            disk_io_percent: 0.0,
        };
        
        (total_memory_gb, available_memory_gb, used_memory_gb, cpu_cores, system_load)
    };

    // Get OS version properly using associated functions
    let os_version = match System::name() {
        Some(name) => {
            match System::os_version() {
                Some(version) => format!("{} {}", name, version),
                None => name,
            }
        }
        None => "Unknown".to_string(),
    };

    // Get drive information using Disks (this is relatively fast)
    let disks = Disks::new_with_refreshed_list();
    let drives: Vec<DriveInfo> = disks.iter().map(|disk| {
        let total_space_gb = disk.total_space() as f64 / 1_073_741_824.0;
        let available_space_gb = disk.available_space() as f64 / 1_073_741_824.0;
        let used_space_gb = total_space_gb - available_space_gb;

        DriveInfo {
            name: disk.name().to_string_lossy().to_string(),
            mount_point: disk.mount_point().to_string_lossy().to_string(),
            total_space_gb,
            available_space_gb,
            used_space_gb,
            health_status: get_drive_health_status(disk.total_space(), disk.available_space()),
            file_system: disk.file_system().to_string_lossy().to_string(),
            smart_health: get_smart_health(),
        }
    }).collect();

    // Get advanced monitoring data
    let sensors = get_hardware_sensors().await;
    let network_interfaces = get_network_interfaces_stats().await;

    let advanced = AdvancedSystemInfo {
        sensors,
        network_interfaces,
        system_load,
    };

    Ok(SystemInfo {
        os_name: std::env::consts::OS.to_string(),
        os_version,
        hostname: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "Unknown".to_string()),
        cpu_cores,
        total_memory_gb,
        available_memory_gb,
        used_memory_gb,
        drives,
        advanced,
    })
}

// ============================================================================
// Real-Time Monitoring
// ============================================================================

fn create_security_event(event_type: SecurityEventType, title: &str, description: &str, severity: &str, data: serde_json::Value) -> SecurityEvent {
    SecurityEvent {
        id: generate_id(),
        event_type,
        title: title.to_string(),
        description: description.to_string(),
        severity: severity.to_string(),
        timestamp: format!("{}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")),
        data,
    }
}

async fn check_system_anomalies(app: tauri::AppHandle) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Use cached system instance with incremental refresh (much faster than System::new_all())
    let (current_cpu, memory_usage_percent) = {
        let mut cached = CACHED_SYSTEM.write();
        // Only refresh CPU and memory, not everything
        cached.refresh_cpu();
        cached.refresh_memory();
        let sys = &cached.system;
        
        let current_cpu = sys.global_cpu_info().cpu_usage();
        let total_mem = sys.total_memory();
        let available_mem = sys.available_memory();
        let memory_usage_percent = ((total_mem - available_mem) as f64 / total_mem as f64) * 100.0;
        
        (current_cpu, memory_usage_percent)
    };

    // Collect events to emit (we'll emit them after releasing the lock)
    let mut events_to_emit: Vec<SecurityEvent> = Vec::new();

    // Check anomalies while holding the lock briefly
    {
        let mut state = MONITORING_STATE.write();

        // CPU usage anomaly
        if current_cpu > 90.0 && state.last_cpu_usage < 80.0 {
            let event = create_security_event(
                SecurityEventType::HighCpuUsage,
                "High CPU Usage Detected",
                &format!("CPU usage spiked to {:.1}%", current_cpu),
                "medium",
                serde_json::json!({ "cpu_usage": current_cpu })
            );
            events_to_emit.push(event);
            state.events_count += 1;
        }
        state.last_cpu_usage = current_cpu;

        // Memory usage anomaly
        if memory_usage_percent > 90.0 && state.last_memory_usage < 85.0 {
            let event = create_security_event(
                SecurityEventType::HighMemoryUsage,
                "High Memory Usage Detected",
                &format!("Memory usage at {:.1}%", memory_usage_percent),
                "high",
                serde_json::json!({ "memory_usage_percent": memory_usage_percent })
            );
            events_to_emit.push(event);
            state.events_count += 1;
        }
        state.last_memory_usage = memory_usage_percent as f32;

        // Drive space monitoring (only check every other cycle to reduce overhead)
        if state.events_count % 2 == 0 {
            let disks = Disks::new_with_refreshed_list();
            for disk in disks.iter() {
                let available_gb = disk.available_space() as f64 / 1_073_741_824.0;
                let total_gb = disk.total_space() as f64 / 1_073_741_824.0;
                let used_percent = ((total_gb - available_gb) / total_gb) * 100.0;

                if used_percent > 95.0 {
                    let event = create_security_event(
                        SecurityEventType::DriveSpaceCritical,
                        "Critical Drive Space",
                        &format!("Drive {} is {:.1}% full", disk.name().to_string_lossy(), used_percent),
                        "critical",
                        serde_json::json!({
                            "drive": disk.name().to_string_lossy(),
                            "used_percent": used_percent
                        })
                    );
                    events_to_emit.push(event);
                    state.events_count += 1;
                }
            }
        }

        // Temperature monitoring (only check every 4th cycle - ~2 min intervals)
        if state.events_count % 4 == 0 {
            if let Ok(nvml) = nvml_wrapper::Nvml::init() {
                if let Ok(device) = nvml.device_by_index(0) {
                    if let Ok(temp) = device.temperature(nvml_wrapper::enum_wrappers::device::TemperatureSensor::Gpu) {
                        if temp > 80 {
                            let event = create_security_event(
                                SecurityEventType::TemperatureWarning,
                                "High GPU Temperature Warning",
                                &format!("GPU temperature is {}°C", temp),
                                "high",
                                serde_json::json!({
                                    "sensor": "GPU",
                                    "temperature": temp
                                })
                            );
                            events_to_emit.push(event);
                            state.events_count += 1;
                        }
                    }
                }
            }
        }
    } // Lock is released here

    // Now emit events without holding the lock
    for event in events_to_emit {
        emit_security_event(&app, event).await?;
    }

    Ok(())
}

async fn emit_security_event(app: &tauri::AppHandle, event: SecurityEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Emit to frontend via Tauri events
    app.emit_all("security-event", &event)?;

    // Log the event
    println!("[SECURITY EVENT] {}: {}", event.title, event.description);

    let record = crate::database::models::ActivityRecord {
        id: event.id.clone(),
        event_type: format!("{:?}", event.event_type),
        title: event.title.clone(),
        description: event.description.clone(),
        severity: event.severity.clone(),
        module: "monitoring".to_string(),
        timestamp: chrono::Utc::now(),
    };
    if let Err(e) = crate::database::insert_activity(&record) {
        eprintln!("Failed to persist security event: {}", e);
    }

    Ok(())
}

async fn monitoring_loop(app: tauri::AppHandle) {
    let mut interval = time::interval(Duration::from_secs(30)); // Check every 30 seconds

    loop {
        interval.tick().await;

        let is_active = {
            let state = MONITORING_STATE.read();
            state.is_active
        };
        
        if !is_active {
            break;
        }

        if let Err(e) = check_system_anomalies(app.clone()).await {
            eprintln!("Error in monitoring loop: {}", e);
        }
    }
}

#[tauri::command]
pub async fn start_real_time_monitoring(app: tauri::AppHandle) -> Result<bool, String> {
    let mut state = MONITORING_STATE.write();

    if state.is_active {
        return Ok(false); // Already running
    }

    state.is_active = true;
    drop(state); // Release lock before spawning

    // Start the monitoring task
    tokio::spawn(monitoring_loop(app));

    println!("Real-time monitoring started");
    Ok(true)
}

#[tauri::command]
pub async fn stop_real_time_monitoring() -> Result<bool, String> {
    let mut state = MONITORING_STATE.write();
    state.is_active = false;
    println!("Real-time monitoring stopped");
    Ok(true)
}

#[tauri::command]
pub async fn get_monitoring_status() -> Result<MonitoringStatus, String> {
    let state = MONITORING_STATE.read();

    Ok(MonitoringStatus {
        is_active: state.is_active,
        last_check: format!("{}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")),
        total_events: state.events_count,
        alerts_today: state.events_count,
    })
}

// ============================================================================
// Security Score
// ============================================================================

#[derive(Debug, Serialize)]
pub struct SecurityScore {
    pub score: u8,
    pub grade: String,
    pub breakdown: SecurityBreakdown,
}

#[derive(Debug, Serialize)]
pub struct SecurityBreakdown {
    pub firewall: u8,
    pub antivirus: u8,
    pub encryption: u8,
    pub updates: u8,
    pub vulnerabilities: u8,
}

#[tauri::command]
pub fn get_security_score() -> Result<SecurityScore, String> {
    let state = APP_STATE.read();
    
    // Calculate scores based on module states (placeholder logic)
    let firewall_score: u32 = if state.settings.modules_enabled.firewall { 85 } else { 30 };
    let antivirus_score: u32 = if state.settings.modules_enabled.scanner { 90 } else { 40 };
    let encryption_score: u32 = if state.settings.modules_enabled.encryption { 75 } else { 50 };
    let updates_score: u32 = 88; // Placeholder
    let vuln_score: u32 = if state.settings.modules_enabled.vulnerability { 80 } else { 60 };
    
    let total_score = ((firewall_score + antivirus_score + encryption_score + updates_score + vuln_score) / 5) as u8;
    
    let grade = match total_score {
        90..=100 => "A+",
        80..=89 => "A",
        70..=79 => "B",
        60..=69 => "C",
        50..=59 => "D",
        _ => "F",
    }.to_string();
    
    Ok(SecurityScore {
        score: total_score,
        grade,
        breakdown: SecurityBreakdown {
            firewall: firewall_score as u8,
            antivirus: antivirus_score as u8,
            encryption: encryption_score as u8,
            updates: updates_score as u8,
            vulnerabilities: vuln_score as u8,
        },
    })
}

// ============================================================================
// Module Status
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ModuleStatusResponse {
    pub name: String,
    pub status: ModuleStatus,
    pub enabled: bool,
    pub description: String,
    pub last_activity: Option<String>,
}

#[tauri::command]
pub fn get_module_status() -> Result<Vec<ModuleStatusResponse>, String> {
    let state = APP_STATE.read();
    let modules = &state.settings.modules_enabled;
    
    Ok(vec![
        ModuleStatusResponse {
            name: "scanner".to_string(),
            status: if modules.scanner { ModuleStatus::Active } else { ModuleStatus::Inactive },
            enabled: modules.scanner,
            description: "Real-time malware scanner".to_string(),
            last_activity: Some("2 minutes ago".to_string()),
        },
        ModuleStatusResponse {
            name: "firewall".to_string(),
            status: if modules.firewall { ModuleStatus::Active } else { ModuleStatus::Inactive },
            enabled: modules.firewall,
            description: "Advanced firewall manager".to_string(),
            last_activity: Some("Active now".to_string()),
        },
        ModuleStatusResponse {
            name: "encryption".to_string(),
            status: if modules.encryption { ModuleStatus::Active } else { ModuleStatus::Inactive },
            enabled: modules.encryption,
            description: "File & folder encryption".to_string(),
            last_activity: Some("1 hour ago".to_string()),
        },
        ModuleStatusResponse {
            name: "vulnerability".to_string(),
            status: if modules.vulnerability { ModuleStatus::Active } else { ModuleStatus::Inactive },
            enabled: modules.vulnerability,
            description: "Vulnerability scanner".to_string(),
            last_activity: Some("Today, 3:00 PM".to_string()),
        },
        ModuleStatusResponse {
            name: "network".to_string(),
            status: if modules.network { ModuleStatus::Active } else { ModuleStatus::Inactive },
            enabled: modules.network,
            description: "Network monitor".to_string(),
            last_activity: Some("Active now".to_string()),
        },
        ModuleStatusResponse {
            name: "agent".to_string(),
            status: if modules.agent { ModuleStatus::Active } else { ModuleStatus::Inactive },
            enabled: modules.agent,
            description: "AI Security Assistant".to_string(),
            last_activity: None,
        },
    ])
}

#[tauri::command]
pub fn toggle_module(module_name: String, enabled: bool) -> Result<bool, String> {
    let mut state = APP_STATE.write();
    
    match module_name.as_str() {
        "scanner" => state.settings.modules_enabled.scanner = enabled,
        "firewall" => state.settings.modules_enabled.firewall = enabled,
        "encryption" => state.settings.modules_enabled.encryption = enabled,
        "vulnerability" => state.settings.modules_enabled.vulnerability = enabled,
        "network" => state.settings.modules_enabled.network = enabled,
        "agent" => state.settings.modules_enabled.agent = enabled,
        _ => return Err(format!("Unknown module: {}", module_name)),
    }
    
    // Log the activity
    let activity = ActivityEvent::new(
        if enabled { ActivityType::ModuleEnabled } else { ActivityType::ModuleDisabled },
        &format!("{} module {}", module_name, if enabled { "enabled" } else { "disabled" }),
        &format!("The {} module has been {}", module_name, if enabled { "enabled" } else { "disabled" }),
        Severity::Low,
        "system",
    );
    state.activities.push(activity);
    
    // Trim activities to prevent unbounded memory growth
    if state.activities.len() > MAX_ACTIVITIES {
        let excess = state.activities.len() - MAX_ACTIVITIES;
        state.activities.drain(0..excess);
    }
    
    Ok(enabled)
}

// ============================================================================
// Activity & Alerts
// ============================================================================

#[tauri::command]
pub fn get_recent_activity(limit: Option<usize>) -> Result<Vec<ActivityEvent>, String> {
    let state = APP_STATE.read();
    let limit = limit.unwrap_or(10);
    
    // Return mock data if no real activities
    if state.activities.is_empty() {
        return Ok(vec![
            ActivityEvent::new(
                ActivityType::ScanCompleted,
                "System Scan Completed",
                "Full system scan completed successfully. No threats detected.",
                Severity::Low,
                "scanner",
            ),
            ActivityEvent::new(
                ActivityType::FirewallBlocked,
                "Connection Blocked",
                "Blocked suspicious outbound connection to 192.168.1.100:8080",
                Severity::Medium,
                "firewall",
            ),
            ActivityEvent::new(
                ActivityType::SystemUpdate,
                "Definitions Updated",
                "Malware definitions updated to version 2024.01.06",
                Severity::Low,
                "scanner",
            ),
            ActivityEvent::new(
                ActivityType::VulnerabilityFound,
                "Vulnerability Detected",
                "Found outdated software: Adobe Reader 2023.001",
                Severity::Medium,
                "vulnerability",
            ),
            ActivityEvent::new(
                ActivityType::FileEncrypted,
                "File Encrypted",
                "Successfully encrypted: Documents/sensitive_data.pdf",
                Severity::Low,
                "encryption",
            ),
        ]);
    }
    
    let activities: Vec<_> = state.activities.iter().rev().take(limit).cloned().collect();
    Ok(activities)
}

#[tauri::command]
pub fn get_threat_alerts() -> Result<Vec<ThreatAlert>, String> {
    let state = APP_STATE.read();
    
    // Return mock data if no real alerts
    if state.alerts.is_empty() {
        return Ok(vec![
            ThreatAlert::new(
                "Potential Malware Detected",
                "Suspicious file behavior detected in C:\\Users\\Downloads\\setup.exe",
                Severity::High,
                "Real-time Scanner",
            ),
            ThreatAlert::new(
                "Unusual Network Activity",
                "Multiple connection attempts to unknown IP addresses detected",
                Severity::Medium,
                "Network Monitor",
            ),
        ]);
    }
    
    Ok(state.alerts.clone())
}

// ============================================================================
// Scanner Commands
// ============================================================================

#[tauri::command]
pub fn start_scan(scan_type: String) -> Result<scanner::ScanSession, String> {
    scanner::start_scan(&scan_type)
}

#[tauri::command]
pub fn get_scan_status(scan_id: String) -> Result<scanner::ScanStatus, String> {
    scanner::get_scan_status(&scan_id)
}

#[tauri::command]
pub fn get_scan_results(scan_id: String) -> Result<scanner::ScanResults, String> {
    scanner::get_scan_results(&scan_id)
}

#[tauri::command]
pub fn stop_scan(scan_id: String) -> Result<bool, String> {
    scanner::stop_scan(&scan_id)
}

// ============================================================================
// Advanced Scanner Commands
// ============================================================================

#[tauri::command]
pub async fn scan_memory_forensics() -> Result<Vec<scanner::MemoryScanResult>, String> {
    scanner::scan_memory_forensics().await
}

#[tauri::command]
pub async fn analyze_behavioral_patterns() -> Result<Vec<scanner::BehavioralAnalysis>, String> {
    scanner::analyze_behavioral_patterns().await
}

#[tauri::command]
pub fn get_yara_rules() -> Result<Vec<scanner::YaraRule>, String> {
    scanner::get_yara_rules()
}

#[tauri::command]
pub fn add_yara_rule(rule: scanner::YaraRule) -> Result<(), String> {
    scanner::add_yara_rule(rule)
}

#[tauri::command]
pub async fn scan_with_yara(file_paths: Vec<String>) -> Result<Vec<scanner::YaraScanResult>, String> {
    scanner::scan_with_yara(file_paths).await
}

#[tauri::command]
pub async fn perform_advanced_scan(scan_type: String, target_paths: Option<Vec<String>>) -> Result<scanner::AdvancedScanResults, String> {
    // Convert string to enum
    let scan_type_enum = match scan_type.as_str() {
        "basic" => scanner::ScanType::Basic,
        "memory" => scanner::ScanType::MemoryForensics,
        "behavioral" => scanner::ScanType::BehavioralAnalysis,
        "yara" => scanner::ScanType::YaraScan,
        "comprehensive" => scanner::ScanType::Comprehensive,
        _ => return Err(format!("Unknown scan type: {}", scan_type)),
    };

    scanner::perform_advanced_scan(scan_type_enum, target_paths).await
}

#[tauri::command]
pub fn initialize_yara_rules() -> Result<(), String> {
    scanner::initialize_yara_rules()
}

// ============================================================================
// Firewall Commands
// ============================================================================

// NOTE: All firewall commands are now async to prevent blocking the UI thread.
// The netsh commands can take several seconds, especially get_firewall_rules.

#[tauri::command]
pub async fn get_firewall_status() -> Result<firewall::FirewallStatus, String> {
    // Run on blocking thread pool to avoid freezing UI
    tokio::task::spawn_blocking(|| firewall::get_status())
        .await
        .map_err(|e| format!("Task failed: {}", e))?
}

#[tauri::command]
pub async fn toggle_firewall(enabled: bool) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || firewall::toggle(enabled))
        .await
        .map_err(|e| format!("Task failed: {}", e))?
}

#[tauri::command]
pub async fn get_firewall_rules() -> Result<Vec<firewall::FirewallRule>, String> {
    // This is the slowest operation - run on blocking thread pool
    tokio::task::spawn_blocking(|| firewall::get_rules())
        .await
        .map_err(|e| format!("Task failed: {}", e))?
}

#[tauri::command]
pub async fn add_firewall_rule(rule: firewall::FirewallRule) -> Result<firewall::FirewallRule, String> {
    tokio::task::spawn_blocking(move || firewall::add_rule(rule))
        .await
        .map_err(|e| format!("Task failed: {}", e))?
}

#[tauri::command]
pub async fn remove_firewall_rule(rule_id: String) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || firewall::remove_rule(&rule_id))
        .await
        .map_err(|e| format!("Task failed: {}", e))?
}

// ============================================================================
// Encryption Commands
// ============================================================================

#[tauri::command]
pub fn encrypt_file(file_path: String, password: String) -> Result<encryption::EncryptionResult, String> {
    encryption::encrypt_file(&file_path, &password)
}

#[tauri::command]
pub fn decrypt_file(file_path: String, password: String) -> Result<encryption::DecryptionResult, String> {
    encryption::decrypt_file(&file_path, &password)
}

#[tauri::command]
pub fn get_encrypted_files() -> Result<Vec<encryption::EncryptedFile>, String> {
    encryption::get_encrypted_files()
}

// ============================================================================
// Vulnerability Commands
// ============================================================================

#[tauri::command]
pub fn scan_vulnerabilities() -> Result<vulnerability::VulnerabilityScan, String> {
    vulnerability::start_scan()
}

#[tauri::command]
pub fn get_vulnerabilities() -> Result<Vec<vulnerability::Vulnerability>, String> {
    vulnerability::get_vulnerabilities()
}

// ============================================================================
// Network Commands
// ============================================================================

// NOTE: Network commands are async to prevent blocking UI when running netstat

#[tauri::command]
pub async fn get_network_connections() -> Result<Vec<network::NetworkConnection>, String> {
    tokio::task::spawn_blocking(|| network::get_connections())
        .await
        .map_err(|e| format!("Task failed: {}", e))?
}

#[tauri::command]
pub async fn get_network_stats() -> Result<network::NetworkStats, String> {
    tokio::task::spawn_blocking(|| network::get_stats())
        .await
        .map_err(|e| format!("Task failed: {}", e))?
}

// ============================================================================
// Settings Commands
// ============================================================================

#[tauri::command]
pub fn get_settings() -> Result<AppSettings, String> {
    let state = APP_STATE.read();
    Ok(state.settings.clone())
}

#[tauri::command]
pub fn update_settings(settings: AppSettings) -> Result<AppSettings, String> {
    let mut state = APP_STATE.write();
    state.settings = settings.clone();
    
    // Log the activity
    let activity = ActivityEvent::new(
        ActivityType::SettingsChanged,
        "Settings Updated",
        "Application settings have been updated",
        Severity::Low,
        "system",
    );
    state.activities.push(activity);
    
    // Trim activities to prevent unbounded memory growth
    if state.activities.len() > MAX_ACTIVITIES {
        let excess = state.activities.len() - MAX_ACTIVITIES;
        state.activities.drain(0..excess);
    }
    
    // Persist settings to database
    if let Ok(settings_json) = serde_json::to_string(&settings) {
        let _ = crate::database::set_setting("app_settings", &settings_json);
    }
    
    Ok(settings)
}

// ============================================================================
// Database Commands
// ============================================================================

use crate::database;
use crate::database::models::{ScanRecord, ActivityRecord, ThreatStats, LicenseRecord};

#[tauri::command]
pub fn db_get_recent_scans(limit: Option<i32>) -> Result<Vec<ScanRecord>, String> {
    database::get_recent_scans(limit.unwrap_or(20))
        .map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub fn db_get_threat_stats() -> Result<ThreatStats, String> {
    database::get_threat_stats()
        .map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub fn db_get_recent_activity(limit: Option<i32>) -> Result<Vec<ActivityRecord>, String> {
    database::get_recent_activity(limit.unwrap_or(50))
        .map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub fn db_get_setting(key: String) -> Result<Option<String>, String> {
    database::get_setting(&key)
        .map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub fn db_set_setting(key: String, value: String) -> Result<(), String> {
    database::set_setting(&key, &value)
        .map_err(|e| format!("Database error: {}", e))
}

// ============================================================================
// Licensing Commands
// ============================================================================

use sha2::{Sha256, Digest};

/// License information returned to frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub is_licensed: bool,
    pub license_key: Option<String>,
    pub organization_name: Option<String>,
    pub expires_at: Option<String>,
    pub features: Vec<String>,
    pub endpoint_id: String,
    pub max_endpoints: Option<i32>,
    pub is_expired: bool,
}

/// Get current license information
#[tauri::command]
pub async fn get_license_info() -> Result<LicenseInfo, String> {
    // Run on blocking thread to avoid UI freeze (endpoint_id calls reg.exe)
    let endpoint_id = tokio::task::spawn_blocking(generate_endpoint_id)
        .await
        .map_err(|e| format!("Task failed: {}", e))?;
    
    match database::get_license() {
        Ok(Some(license)) => {
            let is_expired = !license.is_valid();
            let features = license.get_features();
            Ok(LicenseInfo {
                is_licensed: !is_expired,
                license_key: Some(mask_license_key(&license.license_key)),
                organization_name: license.organization_name,
                expires_at: license.expires_at.map(|dt| dt.to_rfc3339()),
                features,
                endpoint_id,
                max_endpoints: license.max_endpoints,
                is_expired,
            })
        }
        Ok(None) => Ok(LicenseInfo {
            is_licensed: false,
            license_key: None,
            organization_name: None,
            expires_at: None,
            features: vec!["basic".to_string()],
            endpoint_id,
            max_endpoints: None,
            is_expired: false,
        }),
        Err(e) => Err(format!("Failed to get license: {}", e)),
    }
}

/// Activate a license key
#[tauri::command]
pub async fn activate_license(license_key: String) -> Result<LicenseInfo, String> {
    // Validate license key format
    if !is_valid_license_format(&license_key) {
        return Err("Invalid license key format. Expected: XXXX-XXXX-XXXX-XXXX".to_string());
    }
    
    // Decode and validate the license
    let decoded = decode_license_key(&license_key)?;
    
    // Run endpoint_id generation on blocking thread (calls reg.exe)
    let endpoint_id = tokio::task::spawn_blocking(generate_endpoint_id)
        .await
        .map_err(|e| format!("Task failed: {}", e))?;
    
    // Create license record
    let license = LicenseRecord {
        id: 1,
        license_key: license_key.clone(),
        organization_id: Some(decoded.organization_id.clone()),
        organization_name: Some(decoded.organization_name.clone()),
        activated_at: Some(chrono::Utc::now()),
        expires_at: Some(decoded.expires_at),
        endpoint_id: Some(endpoint_id.clone()),
        max_endpoints: Some(decoded.max_endpoints),
        features: decoded.features.join(","),
    };
    
    // Store in database
    database::store_license(&license)
        .map_err(|e| format!("Failed to store license: {}", e))?;
    
    // Log the activation
    let activity = ActivityRecord::new(
        "license_activated".to_string(),
        "License Activated".to_string(),
        format!("License activated for {}", decoded.organization_name),
        "low".to_string(),
        "licensing".to_string(),
    );
    let _ = database::insert_activity(&activity);
    
    Ok(LicenseInfo {
        is_licensed: true,
        license_key: Some(mask_license_key(&license_key)),
        organization_name: Some(decoded.organization_name),
        expires_at: Some(decoded.expires_at.to_rfc3339()),
        features: decoded.features,
        endpoint_id,
        max_endpoints: Some(decoded.max_endpoints),
        is_expired: false,
    })
}

/// Deactivate the current license
#[tauri::command]
pub fn deactivate_license() -> Result<(), String> {
    database::clear_license()
        .map_err(|e| format!("Failed to deactivate license: {}", e))?;
    
    // Log the deactivation
    let activity = ActivityRecord::new(
        "license_deactivated".to_string(),
        "License Deactivated".to_string(),
        "License has been deactivated".to_string(),
        "medium".to_string(),
        "licensing".to_string(),
    );
    let _ = database::insert_activity(&activity);
    
    Ok(())
}

/// Validate a license key without activating
#[tauri::command]
pub fn validate_license(license_key: String) -> Result<bool, String> {
    if !is_valid_license_format(&license_key) {
        return Ok(false);
    }
    
    match decode_license_key(&license_key) {
        Ok(decoded) => Ok(decoded.expires_at > chrono::Utc::now()),
        Err(_) => Ok(false),
    }
}

/// Get the unique endpoint ID for this machine
#[tauri::command]
pub async fn get_endpoint_id() -> Result<String, String> {
    // Run on blocking thread (calls reg.exe on Windows)
    tokio::task::spawn_blocking(generate_endpoint_id)
        .await
        .map_err(|e| format!("Task failed: {}", e))
}

// ============================================================================
// License Helpers
// ============================================================================

/// Decoded license information
struct DecodedLicense {
    organization_id: String,
    organization_name: String,
    max_endpoints: i32,
    features: Vec<String>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// Check if license key has valid format
fn is_valid_license_format(key: &str) -> bool {
    let parts: Vec<&str> = key.split('-').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.len() == 4 && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// Decode a license key
fn decode_license_key(key: &str) -> Result<DecodedLicense, String> {
    // In a real implementation, this would:
    // 1. Decode the base64/encrypted payload from the key
    // 2. Verify the signature using a public key
    // 3. Extract organization info, expiry, and features
    
    // For now, we'll use a simple validation scheme for demo purposes
    // Real implementation would use asymmetric cryptography
    
    let clean_key = key.replace("-", "");
    
    // Simple checksum validation (last 2 chars)
    if clean_key.len() != 16 {
        return Err("Invalid license key length".to_string());
    }
    
    // For demo: decode organization info from first 8 chars
    // In production, use proper encryption/signing
    let org_hash = &clean_key[0..8];
    let expiry_code = &clean_key[8..12];
    let feature_code = &clean_key[12..14];
    let checksum = &clean_key[14..16];
    
    // Verify simple checksum
    let computed_checksum = compute_simple_checksum(&clean_key[0..14]);
    if computed_checksum != checksum {
        return Err("Invalid license key checksum".to_string());
    }
    
    // Decode expiry (months from 2024-01-01)
    let months: i32 = i32::from_str_radix(expiry_code, 16)
        .map_err(|_| "Invalid expiry code")?;
    
    let base_date = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
        .ok_or("Invalid base date")?;
    let expiry_date = base_date + chrono::Duration::days(months as i64 * 30);
    let expires_at = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
        expiry_date.and_hms_opt(23, 59, 59).unwrap(),
        chrono::Utc,
    );
    
    // Decode features
    let feature_bits: u8 = u8::from_str_radix(feature_code, 16)
        .map_err(|_| "Invalid feature code")?;
    
    let mut features = vec!["basic".to_string()];
    if feature_bits & 0x01 != 0 { features.push("scanner".to_string()); }
    if feature_bits & 0x02 != 0 { features.push("firewall".to_string()); }
    if feature_bits & 0x04 != 0 { features.push("encryption".to_string()); }
    if feature_bits & 0x08 != 0 { features.push("vpn".to_string()); }
    if feature_bits & 0x10 != 0 { features.push("ai_agent".to_string()); }
    if feature_bits & 0x20 != 0 { features.push("compliance".to_string()); }
    if feature_bits & 0x40 != 0 { features.push("management".to_string()); }
    if feature_bits & 0x80 != 0 { features.push("enterprise".to_string()); }
    
    Ok(DecodedLicense {
        organization_id: format!("org_{}", org_hash),
        organization_name: format!("Organization {}", &org_hash[0..4].to_uppercase()),
        max_endpoints: 50, // Default for now
        features,
        expires_at,
    })
}

/// Compute simple checksum for license validation
fn compute_simple_checksum(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hasher.update(b"SecurityPrime2024"); // Salt
    let result = hasher.finalize();
    format!("{:02X}", result[0] ^ result[1])
}

/// Generate unique endpoint ID based on machine hardware
pub fn generate_endpoint_id() -> String {
    // Get machine-specific info
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    // Try to get Windows Machine GUID from registry
    #[cfg(target_os = "windows")]
    let machine_guid = get_windows_machine_guid().unwrap_or_else(|| "no-guid".to_string());
    
    #[cfg(not(target_os = "windows"))]
    let machine_guid = "non-windows".to_string();
    
    // Create a hash of the machine identifiers
    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    hasher.update(machine_guid.as_bytes());
    let result = hasher.finalize();
    
    // Return first 16 chars of hex hash
    format!("{:x}", result)[0..16].to_string()
}

/// Get Windows Machine GUID from registry
#[cfg(target_os = "windows")]
fn get_windows_machine_guid() -> Option<String> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    // Use reg query to get the machine GUID (with hidden console)
    let mut cmd = Command::new("reg");
    cmd.creation_flags(CREATE_NO_WINDOW);
    let output = cmd
        .args(&[
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()
        .ok()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse the output to extract the GUID
    for line in stdout.lines() {
        if line.contains("MachineGuid") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return Some(parts[2].to_string());
            }
        }
    }
    
    None
}

/// Mask license key for display (show only last 4 chars)
fn mask_license_key(key: &str) -> String {
    if key.len() > 4 {
        format!("****-****-****-{}", &key[key.len()-4..])
    } else {
        "****-****-****-****".to_string()
    }
}

// ============================================================================
// Service Management Commands
// ============================================================================

/// Service status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub installed: bool,
    pub status: String,
    pub can_install: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LittleSnitchStatus {
    pub supported: bool,
    pub installed: bool,
    pub app_path: Option<String>,
    pub docs_url: String,
    pub status_message: String,
}

#[tauri::command]
pub fn get_little_snitch_status() -> Result<LittleSnitchStatus, String> {
    let docs_url = "https://www.obdev.at/products/littlesnitch/index.html".to_string();

    #[cfg(target_os = "macos")]
    {
        let candidate_paths = [
            "/Applications/Little Snitch.app",
            "/Applications/Setapp/Little Snitch.app",
        ];

        let found = candidate_paths
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .map(|p| p.to_string());

        let installed = found.is_some();
        let status_message = if installed {
            "Little Snitch detected. SecurityPrime can use it for outbound transparency workflows."
                .to_string()
        } else {
            "Little Snitch not detected. Install it to enable process-level outbound monitoring companion mode."
                .to_string()
        };

        Ok(LittleSnitchStatus {
            supported: true,
            installed,
            app_path: found,
            docs_url,
            status_message,
        })
    }

    #[cfg(not(target_os = "macos"))]
    {
        Ok(LittleSnitchStatus {
            supported: false,
            installed: false,
            app_path: None,
            docs_url,
            status_message: "Little Snitch integration is macOS-only.".to_string(),
        })
    }
}

/// Install the Windows service
#[tauri::command]
pub async fn install_service() -> Result<(), String> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(|| crate::service::windows_service::install_service())
            .await
            .map_err(|e| format!("Task failed: {}", e))?
    }
    #[cfg(not(windows))]
    {
        Err("Service installation is only supported on Windows".to_string())
    }
}

/// Uninstall the Windows service
#[tauri::command]
pub async fn uninstall_service() -> Result<(), String> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(|| crate::service::windows_service::uninstall_service())
            .await
            .map_err(|e| format!("Task failed: {}", e))?
    }
    #[cfg(not(windows))]
    {
        Err("Service uninstallation is only supported on Windows".to_string())
    }
}

/// Start the Windows service
#[tauri::command]
pub async fn start_service() -> Result<(), String> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(|| crate::service::windows_service::start_service())
            .await
            .map_err(|e| format!("Task failed: {}", e))?
    }
    #[cfg(not(windows))]
    {
        Err("Service management is only supported on Windows".to_string())
    }
}

/// Stop the Windows service
#[tauri::command]
pub async fn stop_service() -> Result<(), String> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(|| crate::service::windows_service::stop_service())
            .await
            .map_err(|e| format!("Task failed: {}", e))?
    }
    #[cfg(not(windows))]
    {
        Err("Service management is only supported on Windows".to_string())
    }
}

/// Get the Windows service status
#[tauri::command]
pub async fn get_service_status() -> Result<ServiceInfo, String> {
    #[cfg(windows)]
    {
        // Run on blocking thread to avoid UI freeze (calls sc.exe)
        tokio::task::spawn_blocking(|| {
            let installed = crate::service::windows_service::is_service_installed();
            let status = if installed {
                crate::service::windows_service::get_service_status().unwrap_or_else(|_| "unknown".to_string())
            } else {
                "not_installed".to_string()
            };
            
            ServiceInfo {
                installed,
                status,
                can_install: is_admin(),
            }
        })
        .await
        .map_err(|e| format!("Task failed: {}", e))
    }
    #[cfg(not(windows))]
    {
        Ok(ServiceInfo {
            installed: false,
            status: "not_supported".to_string(),
            can_install: false,
        })
    }
}

/// Check if service is installed
#[tauri::command]
pub async fn is_service_installed() -> Result<bool, String> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(|| crate::service::windows_service::is_service_installed())
            .await
            .map_err(|e| format!("Task failed: {}", e))
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}

/// Check if running as administrator
#[cfg(windows)]
fn is_admin() -> bool {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    // Try to run a command that requires admin (with hidden console)
    let mut cmd = Command::new("net");
    cmd.creation_flags(CREATE_NO_WINDOW);
    let output = cmd
        .args(&["session"])
        .output();
    
    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

#[cfg(not(windows))]
fn is_admin() -> bool {
    false
}

