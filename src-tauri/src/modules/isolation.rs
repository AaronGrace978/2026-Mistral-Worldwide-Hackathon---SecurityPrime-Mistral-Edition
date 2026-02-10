// Cyber Security Prime - Process Isolation Module
// Provides sandboxing and containerization features for enhanced security

use crate::modules::{SecurityModule, ModuleHealth};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use uuid::Uuid;

// Global isolation state
static ISOLATION_STATE: Lazy<Mutex<IsolationState>> = Lazy::new(|| Mutex::new(IsolationState::new()));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationState {
    pub sandboxes: HashMap<String, Sandbox>,
    pub containers: HashMap<String, Container>,
    pub isolation_profiles: HashMap<String, IsolationProfile>,
    pub running_processes: Vec<IsolatedProcess>,
    pub isolation_events: Vec<IsolationEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sandbox {
    pub id: String,
    pub name: String,
    pub isolation_level: IsolationLevel,
    pub status: SandboxStatus,
    pub created_at: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
    pub allowed_paths: Vec<String>,
    pub blocked_paths: Vec<String>,
    pub network_access: NetworkAccess,
    pub resource_limits: ResourceLimits,
    pub processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: ContainerStatus,
    pub created_at: DateTime<Utc>,
    pub ports: Vec<PortMapping>,
    pub volumes: Vec<VolumeMapping>,
    pub environment: HashMap<String, String>,
    pub security_profile: ContainerSecurityProfile,
    pub processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub isolation_level: IsolationLevel,
    pub default_settings: IsolationSettings,
    pub allowed_applications: Vec<String>,
    pub security_policies: Vec<SecurityPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolatedProcess {
    pub id: String,
    pub process_id: u32,
    pub name: String,
    pub sandbox_id: Option<String>,
    pub container_id: Option<String>,
    pub isolation_level: IsolationLevel,
    pub started_at: DateTime<Utc>,
    pub status: ProcessStatus,
    pub resource_usage: ResourceUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: IsolationEventType,
    pub sandbox_id: Option<String>,
    pub container_id: Option<String>,
    pub process_id: Option<String>,
    pub description: String,
    pub severity: EventSeverity,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IsolationLevel {
    None,
    Basic,      // Basic process isolation
    Standard,   // Standard sandboxing
    Strict,     // Strict sandboxing with network restrictions
    Maximum,    // Maximum isolation with minimal system access
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SandboxStatus {
    Created,
    Starting,
    Running,
    Stopping,
    Stopped,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContainerStatus {
    Created,
    Running,
    Paused,
    Stopped,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkAccess {
    None,
    HostOnly,
    NAT,
    Bridged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_cores: Option<f32>,
    pub memory_mb: Option<u64>,
    pub disk_mb: Option<u64>,
    pub network_mbps: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMapping {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityProfile {
    pub privileged: bool,
    pub apparmor_profile: Option<String>,
    pub seccomp_profile: Option<String>,
    pub capabilities: Vec<String>,
    pub no_new_privileges: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationSettings {
    pub network_isolation: bool,
    pub filesystem_isolation: bool,
    pub process_isolation: bool,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub id: String,
    pub name: String,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProcessStatus {
    Running,
    Suspended,
    Terminated,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_percent: f32,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub network_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IsolationEventType {
    SandboxCreated,
    SandboxStarted,
    SandboxStopped,
    ContainerCreated,
    ContainerStarted,
    ContainerStopped,
    ProcessIsolated,
    ProcessViolation,
    ResourceLimitExceeded,
    SecurityViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl IsolationState {
    fn new() -> Self {
        let mut state = Self {
            sandboxes: HashMap::new(),
            containers: HashMap::new(),
            isolation_profiles: HashMap::new(),
            running_processes: Vec::new(),
            isolation_events: Vec::new(),
        };

        // Initialize default isolation profiles
        state.initialize_default_profiles();
        state
    }

    fn initialize_default_profiles(&mut self) {
        let profiles = vec![
            IsolationProfile {
                id: "web-browsing".to_string(),
                name: "Web Browsing".to_string(),
                description: "Isolated environment for web browsing".to_string(),
                isolation_level: IsolationLevel::Standard,
                default_settings: IsolationSettings {
                    network_isolation: false,
                    filesystem_isolation: true,
                    process_isolation: true,
                    resource_limits: ResourceLimits {
                        cpu_cores: Some(1.0),
                        memory_mb: Some(1024),
                        disk_mb: Some(512),
                        network_mbps: Some(10),
                    },
                },
                allowed_applications: vec!["firefox".to_string(), "chrome".to_string(), "edge".to_string()],
                security_policies: vec![
                    SecurityPolicy {
                        id: "no-system-access".to_string(),
                        name: "No System Access".to_string(),
                        rules: vec![
                            "block /system32".to_string(),
                            "block /windows".to_string(),
                            "allow /users".to_string(),
                        ],
                    },
                ],
            },
            IsolationProfile {
                id: "file-analysis".to_string(),
                name: "File Analysis".to_string(),
                description: "Isolated environment for analyzing potentially malicious files".to_string(),
                isolation_level: IsolationLevel::Strict,
                default_settings: IsolationSettings {
                    network_isolation: true,
                    filesystem_isolation: true,
                    process_isolation: true,
                    resource_limits: ResourceLimits {
                        cpu_cores: Some(0.5),
                        memory_mb: Some(512),
                        disk_mb: Some(256),
                        network_mbps: None,
                    },
                },
                allowed_applications: vec!["file_analyzer".to_string(), "hex_editor".to_string()],
                security_policies: vec![
                    SecurityPolicy {
                        id: "analysis-only".to_string(),
                        name: "Analysis Only".to_string(),
                        rules: vec![
                            "block network".to_string(),
                            "block system_writes".to_string(),
                            "allow read_only".to_string(),
                        ],
                    },
                ],
            },
            IsolationProfile {
                id: "development".to_string(),
                name: "Development Environment".to_string(),
                description: "Isolated development environment with controlled access".to_string(),
                isolation_level: IsolationLevel::Basic,
                default_settings: IsolationSettings {
                    network_isolation: false,
                    filesystem_isolation: false,
                    process_isolation: true,
                    resource_limits: ResourceLimits {
                        cpu_cores: Some(2.0),
                        memory_mb: Some(4096),
                        disk_mb: Some(10240),
                        network_mbps: Some(100),
                    },
                },
                allowed_applications: vec!["vscode".to_string(), "git".to_string(), "node".to_string()],
                security_policies: vec![
                    SecurityPolicy {
                        id: "dev-access".to_string(),
                        name: "Development Access".to_string(),
                        rules: vec![
                            "allow development_tools".to_string(),
                            "block system_critical".to_string(),
                        ],
                    },
                ],
            },
        ];

        for profile in profiles {
            self.isolation_profiles.insert(profile.id.clone(), profile);
        }
    }
}

pub struct IsolationModule {
    pub name: &'static str,
    pub description: &'static str,
    pub version: &'static str,
    pub active: bool,
}

impl Default for IsolationModule {
    fn default() -> Self {
        Self {
            name: "Process Isolation",
            description: "Sandboxing and containerization for enhanced security",
            version: "1.0.0",
            active: true,
        }
    }
}

impl SecurityModule for IsolationModule {
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
        // Initialize isolation state
        let _state = ISOLATION_STATE.lock().unwrap();
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), String> {
        // Clean up running sandboxes and containers
        let mut state = ISOLATION_STATE.lock().unwrap();

        // Stop all running sandboxes
        for sandbox in state.sandboxes.values_mut() {
            if matches!(sandbox.status, SandboxStatus::Running) {
                sandbox.status = SandboxStatus::Stopped;
                self.log_event(
                    IsolationEventType::SandboxStopped,
                    Some(sandbox.id.clone()),
                    None,
                    None,
                    format!("Sandbox {} stopped during shutdown", sandbox.name),
                    EventSeverity::Low,
                    serde_json::json!({}),
                );
            }
        }

        // Stop all running containers
        for container in state.containers.values_mut() {
            if matches!(container.status, ContainerStatus::Running) {
                container.status = ContainerStatus::Stopped;
                self.log_event(
                    IsolationEventType::ContainerStopped,
                    None,
                    Some(container.id.clone()),
                    None,
                    format!("Container {} stopped during shutdown", container.name),
                    EventSeverity::Low,
                    serde_json::json!({}),
                );
            }
        }

        Ok(())
    }

    fn health_check(&self) -> ModuleHealth {
        let state = ISOLATION_STATE.lock().unwrap();

        let running_sandboxes = state.sandboxes.values()
            .filter(|s| matches!(s.status, SandboxStatus::Running))
            .count();

        let running_containers = state.containers.values()
            .filter(|c| matches!(c.status, ContainerStatus::Running))
            .count();

        let healthy = true; // Isolation module is always healthy unless critical errors

        let message = format!(
            "Isolation module operational: {} sandboxes running, {} containers running",
            running_sandboxes, running_containers
        );

        ModuleHealth {
            healthy,
            message,
            last_check: Utc::now().to_rfc3339(),
        }
    }
}

impl IsolationModule {
    fn log_event(
        &self,
        event_type: IsolationEventType,
        sandbox_id: Option<String>,
        container_id: Option<String>,
        process_id: Option<String>,
        description: String,
        severity: EventSeverity,
        details: serde_json::Value,
    ) {
        let mut state = ISOLATION_STATE.lock().unwrap();

        let event = IsolationEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            sandbox_id,
            container_id,
            process_id,
            description,
            severity,
            details,
        };

        state.isolation_events.push(event);
    }
}

// Tauri commands for isolation module
#[tauri::command]
pub fn get_isolation_profiles() -> Result<Vec<IsolationProfile>, String> {
    let state = ISOLATION_STATE.lock().unwrap();
    Ok(state.isolation_profiles.values().cloned().collect())
}

#[tauri::command]
pub fn create_sandbox(name: String, profile_id: String) -> Result<String, String> {
    let mut state = ISOLATION_STATE.lock().unwrap();

    let profile = state.isolation_profiles.get(&profile_id)
        .ok_or_else(|| format!("Isolation profile {} not found", profile_id))?;

    // Clone what we need before inserting
    let profile_name = profile.name.clone();
    let isolation_level = profile.isolation_level.clone();
    let resource_limits = profile.default_settings.resource_limits.clone();

    let sandbox_id = Uuid::new_v4().to_string();

    let sandbox = Sandbox {
        id: sandbox_id.clone(),
        name: name.clone(),
        isolation_level: isolation_level.clone(),
        status: SandboxStatus::Created,
        created_at: Utc::now(),
        last_used: Utc::now(),
        allowed_paths: vec![],
        blocked_paths: vec![],
        network_access: match isolation_level {
            IsolationLevel::None | IsolationLevel::Basic => NetworkAccess::Bridged,
            IsolationLevel::Standard => NetworkAccess::NAT,
            IsolationLevel::Strict | IsolationLevel::Maximum => NetworkAccess::None,
        },
        resource_limits,
        processes: vec![],
    };

    state.sandboxes.insert(sandbox_id.clone(), sandbox);
    drop(state); // Release lock before logging

    // Log the event
    let module = IsolationModule::default();
    module.log_event(
        IsolationEventType::SandboxCreated,
        Some(sandbox_id.clone()),
        None,
        None,
        format!("Sandbox '{}' created with profile '{}'", name, profile_name),
        EventSeverity::Low,
        serde_json::json!({
            "profile_id": profile_id,
            "isolation_level": format!("{:?}", isolation_level)
        }),
    );

    Ok(sandbox_id)
}

#[tauri::command]
pub fn start_sandbox(sandbox_id: String) -> Result<(), String> {
    let mut state = ISOLATION_STATE.lock().unwrap();

    let sandbox = state.sandboxes.get_mut(&sandbox_id)
        .ok_or_else(|| format!("Sandbox {} not found", sandbox_id))?;

    if !matches!(sandbox.status, SandboxStatus::Created | SandboxStatus::Stopped) {
        return Err(format!("Sandbox {} is not in a startable state", sandbox_id));
    }

    sandbox.status = SandboxStatus::Running;
    sandbox.last_used = Utc::now();

    // Log the event
    let module = IsolationModule::default();
    module.log_event(
        IsolationEventType::SandboxStarted,
        Some(sandbox_id.clone()),
        None,
        None,
        format!("Sandbox '{}' started", sandbox.name),
        EventSeverity::Low,
        serde_json::json!({}),
    );

    Ok(())
}

#[tauri::command]
pub fn stop_sandbox(sandbox_id: String) -> Result<(), String> {
    let mut state = ISOLATION_STATE.lock().unwrap();

    let sandbox = state.sandboxes.get_mut(&sandbox_id)
        .ok_or_else(|| format!("Sandbox {} not found", sandbox_id))?;

    if !matches!(sandbox.status, SandboxStatus::Running) {
        return Err(format!("Sandbox {} is not running", sandbox_id));
    }

    sandbox.status = SandboxStatus::Stopped;

    // Log the event
    let module = IsolationModule::default();
    module.log_event(
        IsolationEventType::SandboxStopped,
        Some(sandbox_id.clone()),
        None,
        None,
        format!("Sandbox '{}' stopped", sandbox.name),
        EventSeverity::Low,
        serde_json::json!({}),
    );

    Ok(())
}

#[tauri::command]
pub fn get_sandboxes() -> Result<Vec<Sandbox>, String> {
    let state = ISOLATION_STATE.lock().unwrap();
    Ok(state.sandboxes.values().cloned().collect())
}

#[tauri::command]
pub fn create_container(name: String, image: String, profile_id: String) -> Result<String, String> {
    let mut state = ISOLATION_STATE.lock().unwrap();

    let profile = state.isolation_profiles.get(&profile_id)
        .ok_or_else(|| format!("Isolation profile {} not found", profile_id))?;

    // Clone what we need before inserting
    let profile_name = profile.name.clone();
    let image_clone = image.clone();

    let container_id = Uuid::new_v4().to_string();

    let container = Container {
        id: container_id.clone(),
        name: name.clone(),
        image,
        status: ContainerStatus::Created,
        created_at: Utc::now(),
        ports: vec![],
        volumes: vec![],
        environment: HashMap::new(),
        security_profile: ContainerSecurityProfile {
            privileged: false,
            apparmor_profile: Some("docker-default".to_string()),
            seccomp_profile: Some("docker-default".to_string()),
            capabilities: vec!["NET_BIND_SERVICE".to_string()],
            no_new_privileges: true,
        },
        processes: vec![],
    };

    state.containers.insert(container_id.clone(), container);
    drop(state); // Release lock before logging

    // Log the event
    let module = IsolationModule::default();
    module.log_event(
        IsolationEventType::ContainerCreated,
        None,
        Some(container_id.clone()),
        None,
        format!("Container '{}' created with profile '{}'", name, profile_name),
        EventSeverity::Low,
        serde_json::json!({
            "profile_id": profile_id,
            "image": image_clone
        }),
    );

    Ok(container_id)
}

#[tauri::command]
pub fn start_container(container_id: String) -> Result<(), String> {
    let mut state = ISOLATION_STATE.lock().unwrap();

    let container = state.containers.get_mut(&container_id)
        .ok_or_else(|| format!("Container {} not found", container_id))?;

    if !matches!(container.status, ContainerStatus::Created | ContainerStatus::Stopped) {
        return Err(format!("Container {} is not in a startable state", container_id));
    }

    container.status = ContainerStatus::Running;

    // Log the event
    let module = IsolationModule::default();
    module.log_event(
        IsolationEventType::ContainerStarted,
        None,
        Some(container_id.clone()),
        None,
        format!("Container '{}' started", container.name),
        EventSeverity::Low,
        serde_json::json!({}),
    );

    Ok(())
}

#[tauri::command]
pub fn stop_container(container_id: String) -> Result<(), String> {
    let mut state = ISOLATION_STATE.lock().unwrap();

    let container = state.containers.get_mut(&container_id)
        .ok_or_else(|| format!("Container {} not found", container_id))?;

    if !matches!(container.status, ContainerStatus::Running) {
        return Err(format!("Container {} is not running", container_id));
    }

    container.status = ContainerStatus::Stopped;

    // Log the event
    let module = IsolationModule::default();
    module.log_event(
        IsolationEventType::ContainerStopped,
        None,
        Some(container_id.clone()),
        None,
        format!("Container '{}' stopped", container.name),
        EventSeverity::Low,
        serde_json::json!({}),
    );

    Ok(())
}

#[tauri::command]
pub fn get_containers() -> Result<Vec<Container>, String> {
    let state = ISOLATION_STATE.lock().unwrap();
    Ok(state.containers.values().cloned().collect())
}

#[tauri::command]
pub fn get_running_processes() -> Result<Vec<IsolatedProcess>, String> {
    let state = ISOLATION_STATE.lock().unwrap();
    Ok(state.running_processes.clone())
}

#[tauri::command]
pub fn isolate_process(process_name: String, sandbox_id: Option<String>, container_id: Option<String>) -> Result<String, String> {
    let mut state = ISOLATION_STATE.lock().unwrap();

    // Validate that either sandbox_id or container_id is provided, but not both
    match (&sandbox_id, &container_id) {
        (Some(_), Some(_)) => return Err("Cannot specify both sandbox and container".to_string()),
        (None, None) => return Err("Must specify either sandbox or container".to_string()),
        _ => {}
    }

    let isolation_level = if sandbox_id.is_some() {
        state.sandboxes.get(sandbox_id.as_ref().unwrap())
            .map(|s| s.isolation_level.clone())
            .unwrap_or(IsolationLevel::Basic)
    } else {
        IsolationLevel::Standard // Default for containers
    };

    let isolation_level_str = format!("{:?}", isolation_level);
    let process_id = Uuid::new_v4().to_string();

    let process = IsolatedProcess {
        id: process_id.clone(),
        process_id: 0, // Would be assigned by OS
        name: process_name.clone(),
        sandbox_id: sandbox_id.clone(),
        container_id: container_id.clone(),
        isolation_level,
        started_at: Utc::now(),
        status: ProcessStatus::Running,
        resource_usage: ResourceUsage {
            cpu_percent: 0.0,
            memory_mb: 0,
            disk_mb: 0,
            network_bytes: 0,
        },
    };

    state.running_processes.push(process);
    drop(state); // Release lock before logging

    // Log the event
    let module = IsolationModule::default();
    module.log_event(
        IsolationEventType::ProcessIsolated,
        sandbox_id.clone(),
        container_id.clone(),
        Some(process_id.clone()),
        format!("Process '{}' isolated", process_name),
        EventSeverity::Low,
        serde_json::json!({
            "isolation_level": isolation_level_str
        }),
    );

    Ok(process_id)
}

#[tauri::command]
pub fn get_isolation_events(limit: Option<usize>) -> Result<Vec<IsolationEvent>, String> {
    let state = ISOLATION_STATE.lock().unwrap();
    let limit = limit.unwrap_or(100);
    let mut events = state.isolation_events.clone();
    events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    events.truncate(limit);
    Ok(events)
}

#[tauri::command]
pub fn get_isolation_dashboard() -> Result<serde_json::Value, String> {
    let state = ISOLATION_STATE.lock().unwrap();

    let dashboard = serde_json::json!({
        "total_sandboxes": state.sandboxes.len(),
        "running_sandboxes": state.sandboxes.values().filter(|s| matches!(s.status, SandboxStatus::Running)).count(),
        "total_containers": state.containers.len(),
        "running_containers": state.containers.values().filter(|c| matches!(c.status, ContainerStatus::Running)).count(),
        "isolated_processes": state.running_processes.len(),
        "total_profiles": state.isolation_profiles.len(),
        "recent_events": state.isolation_events.len().min(10),
        "security_violations": state.isolation_events.iter().filter(|e| matches!(e.event_type, IsolationEventType::SecurityViolation)).count()
    });

    Ok(dashboard)
}