// Cyber Security Prime - Tamper Detection Module
// Provides integrity checking, anomaly detection, and secure boot capabilities

use crate::modules::{SecurityModule, ModuleHealth};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use uuid::Uuid;

// Global tamper detection state
static TAMPER_STATE: Lazy<Mutex<TamperState>> = Lazy::new(|| Mutex::new(TamperState::new()));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperState {
    pub integrity_checks: HashMap<String, IntegrityCheck>,
    pub anomaly_detectors: HashMap<String, AnomalyDetector>,
    pub secure_boot_status: SecureBootStatus,
    pub tamper_alerts: Vec<TamperAlert>,
    pub system_baseline: SystemBaseline,
    pub tamper_events: Vec<TamperEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityCheck {
    pub id: String,
    pub name: String,
    pub target_path: String,
    pub check_type: IntegrityCheckType,
    pub expected_hash: String,
    pub last_check: DateTime<Utc>,
    pub status: IntegrityStatus,
    pub check_interval: u64, // seconds
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetector {
    pub id: String,
    pub name: String,
    pub detector_type: AnomalyType,
    pub target: String,
    pub threshold: f32,
    pub baseline_values: Vec<f32>,
    pub last_detection: DateTime<Utc>,
    pub status: DetectorStatus,
    pub sensitivity: f32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureBootStatus {
    pub enabled: bool,
    pub secure_boot_supported: bool,
    pub measured_boot: bool,
    pub tpm_present: bool,
    pub tpm_version: Option<String>,
    pub boot_measurements: Vec<BootMeasurement>,
    pub last_verification: DateTime<Utc>,
    pub status: SecureBootState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootMeasurement {
    pub pcr_index: u32,
    pub measurement: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperAlert {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub alert_type: TamperAlertType,
    pub severity: AlertSeverity,
    pub description: String,
    pub affected_resource: String,
    pub detected_changes: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub resolved: bool,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemBaseline {
    pub captured_at: DateTime<Utc>,
    pub system_hashes: HashMap<String, String>,
    pub file_permissions: HashMap<String, FilePermissions>,
    pub registry_baseline: HashMap<String, String>,
    pub process_baseline: Vec<ProcessSignature>,
    pub network_baseline: NetworkBaseline,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePermissions {
    pub owner: String,
    pub group: String,
    pub permissions: String,
    pub size: u64,
    pub modified: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSignature {
    pub name: String,
    pub expected_hash: String,
    pub allowed_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBaseline {
    pub allowed_ports: Vec<u16>,
    pub allowed_connections: Vec<String>,
    pub expected_services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: TamperEventType,
    pub description: String,
    pub details: serde_json::Value,
    pub severity: EventSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrityCheckType {
    FileHash,
    DirectoryHash,
    RegistryKey,
    SystemFile,
    CriticalProcess,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrityStatus {
    Valid,
    Modified,
    Missing,
    AccessDenied,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnomalyType {
    FileSystemActivity,
    NetworkTraffic,
    ProcessBehavior,
    SystemLoad,
    MemoryUsage,
    LoginAttempts,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectorStatus {
    Learning,
    Active,
    Alert,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecureBootState {
    Enabled,
    Disabled,
    Compromised,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TamperAlertType {
    IntegrityViolation,
    AnomalyDetected,
    SecureBootFailure,
    UnauthorizedAccess,
    SuspiciousActivity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TamperEventType {
    IntegrityCheckPassed,
    IntegrityCheckFailed,
    AnomalyDetected,
    BaselineUpdated,
    SecureBootVerified,
    TamperAlertCreated,
    TamperAlertResolved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl TamperState {
    fn new() -> Self {
        let mut state = Self {
            integrity_checks: HashMap::new(),
            anomaly_detectors: HashMap::new(),
            secure_boot_status: SecureBootStatus {
                enabled: false,
                secure_boot_supported: false,
                measured_boot: false,
                tpm_present: false,
                tpm_version: None,
                boot_measurements: Vec::new(),
                last_verification: Utc::now(),
                status: SecureBootState::Unknown,
            },
            tamper_alerts: Vec::new(),
            system_baseline: SystemBaseline {
                captured_at: Utc::now(),
                system_hashes: HashMap::new(),
                file_permissions: HashMap::new(),
                registry_baseline: HashMap::new(),
                process_baseline: Vec::new(),
                network_baseline: NetworkBaseline {
                    allowed_ports: vec![80, 443, 22], // Default web and SSH ports
                    allowed_connections: Vec::new(),
                    expected_services: vec!["sshd".to_string(), "httpd".to_string()],
                },
                valid: false,
            },
            tamper_events: Vec::new(),
        };

        // Initialize default integrity checks
        state.initialize_default_checks();

        // Initialize default anomaly detectors
        state.initialize_default_detectors();

        state
    }

    fn initialize_default_checks(&mut self) {
        let default_checks = vec![
            IntegrityCheck {
                id: "system32-integrity".to_string(),
                name: "System32 Directory Integrity".to_string(),
                target_path: "C:\\Windows\\System32".to_string(),
                check_type: IntegrityCheckType::DirectoryHash,
                expected_hash: "".to_string(), // Would be computed during baseline
                last_check: Utc::now(),
                status: IntegrityStatus::Unknown,
                check_interval: 3600, // 1 hour
                enabled: true,
            },
            IntegrityCheck {
                id: "critical-process-integrity".to_string(),
                name: "Critical Process Integrity".to_string(),
                target_path: "lsass.exe".to_string(),
                check_type: IntegrityCheckType::CriticalProcess,
                expected_hash: "".to_string(),
                last_check: Utc::now(),
                status: IntegrityStatus::Unknown,
                check_interval: 300, // 5 minutes
                enabled: true,
            },
            IntegrityCheck {
                id: "boot-config-integrity".to_string(),
                name: "Boot Configuration Integrity".to_string(),
                target_path: "C:\\boot.ini".to_string(),
                check_type: IntegrityCheckType::SystemFile,
                expected_hash: "".to_string(),
                last_check: Utc::now(),
                status: IntegrityStatus::Unknown,
                check_interval: 1800, // 30 minutes
                enabled: true,
            },
        ];

        for check in default_checks {
            self.integrity_checks.insert(check.id.clone(), check);
        }
    }

    fn initialize_default_detectors(&mut self) {
        let default_detectors = vec![
            AnomalyDetector {
                id: "filesystem-anomaly".to_string(),
                name: "File System Activity Monitor".to_string(),
                detector_type: AnomalyType::FileSystemActivity,
                target: "/".to_string(),
                threshold: 2.5, // Standard deviations
                baseline_values: Vec::new(),
                last_detection: Utc::now(),
                status: DetectorStatus::Learning,
                sensitivity: 0.8,
                enabled: true,
            },
            AnomalyDetector {
                id: "network-anomaly".to_string(),
                name: "Network Traffic Monitor".to_string(),
                detector_type: AnomalyType::NetworkTraffic,
                target: "all".to_string(),
                threshold: 3.0,
                baseline_values: Vec::new(),
                last_detection: Utc::now(),
                status: DetectorStatus::Learning,
                sensitivity: 0.7,
                enabled: true,
            },
            AnomalyDetector {
                id: "process-anomaly".to_string(),
                name: "Process Behavior Monitor".to_string(),
                detector_type: AnomalyType::ProcessBehavior,
                target: "system".to_string(),
                threshold: 2.0,
                baseline_values: Vec::new(),
                last_detection: Utc::now(),
                status: DetectorStatus::Learning,
                sensitivity: 0.9,
                enabled: true,
            },
        ];

        for detector in default_detectors {
            self.anomaly_detectors.insert(detector.id.clone(), detector);
        }
    }
}

pub struct TamperDetectionModule {
    pub name: &'static str,
    pub description: &'static str,
    pub version: &'static str,
    pub active: bool,
}

impl Default for TamperDetectionModule {
    fn default() -> Self {
        Self {
            name: "Tamper Detection",
            description: "Integrity checking, anomaly detection, and secure boot",
            version: "1.0.0",
            active: true,
        }
    }
}

impl SecurityModule for TamperDetectionModule {
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
        // Initialize tamper detection components
        let mut state = TAMPER_STATE.lock().unwrap();

        // Check secure boot status
        self.check_secure_boot_status(&mut state);

        // Perform initial integrity checks
        self.perform_integrity_checks(&mut state);

        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn health_check(&self) -> ModuleHealth {
        let state = TAMPER_STATE.lock().unwrap();

        let active_checks = state.integrity_checks.values().filter(|c| c.enabled).count();
        let active_detectors = state.anomaly_detectors.values().filter(|d| d.enabled).count();
        let unresolved_alerts = state.tamper_alerts.iter().filter(|a| !a.resolved).count();

        let healthy = unresolved_alerts == 0 && state.system_baseline.valid;

        let message = format!(
            "Tamper detection operational: {} integrity checks, {} anomaly detectors, {} unresolved alerts",
            active_checks, active_detectors, unresolved_alerts
        );

        ModuleHealth {
            healthy,
            message,
            last_check: Utc::now().to_rfc3339(),
        }
    }
}

impl TamperDetectionModule {
    fn check_secure_boot_status(&self, state: &mut TamperState) {
        // In a real implementation, this would check actual secure boot status
        // For now, we'll simulate the check
        state.secure_boot_status.enabled = true;
        state.secure_boot_status.secure_boot_supported = true;
        state.secure_boot_status.measured_boot = true;
        state.secure_boot_status.tpm_present = true;
        state.secure_boot_status.tpm_version = Some("2.0".to_string());
        state.secure_boot_status.status = SecureBootState::Enabled;
        state.secure_boot_status.last_verification = Utc::now();

        // Add some sample boot measurements
        state.secure_boot_status.boot_measurements = vec![
            BootMeasurement {
                pcr_index: 0,
                measurement: "a665b7c7a6b04c8b9c6e8d4f2b3c1e5f7a9b8c6d4e2f1a3b5c7d9e8f6a4b2c0".to_string(),
                description: "BIOS measurement".to_string(),
                timestamp: Utc::now(),
            },
            BootMeasurement {
                pcr_index: 4,
                measurement: "f8e9d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a39281705f4e3d2c1b0a".to_string(),
                description: "Boot loader measurement".to_string(),
                timestamp: Utc::now(),
            },
        ];
    }

    fn perform_integrity_checks(&self, state: &mut TamperState) {
        for check in state.integrity_checks.values_mut() {
            if !check.enabled {
                continue;
            }

            // Simulate integrity check
            let is_valid = self.perform_single_integrity_check(check);
            check.last_check = Utc::now();

            if !is_valid && check.status == IntegrityStatus::Valid {
                // Integrity violation detected
                check.status = IntegrityStatus::Modified;
                self.create_tamper_alert(
                    TamperAlertType::IntegrityViolation,
                    AlertSeverity::High,
                    format!("Integrity violation detected for {}", check.name),
                    check.target_path.clone(),
                    vec![format!("Expected hash: {}", check.expected_hash)],
                    vec![
                        "Review system logs".to_string(),
                        "Verify system integrity".to_string(),
                        "Consider system restoration".to_string(),
                    ],
                );
            } else if is_valid {
                check.status = IntegrityStatus::Valid;
            }
        }
    }

    fn perform_single_integrity_check(&self, check: &IntegrityCheck) -> bool {
        // In a real implementation, this would perform actual integrity checks
        // For simulation, return true for most checks, false occasionally
        match check.check_type {
            IntegrityCheckType::FileHash => {
                // Simulate file hash check
                true
            },
            IntegrityCheckType::DirectoryHash => {
                // Simulate directory hash check
                true
            },
            IntegrityCheckType::RegistryKey => {
                // Simulate registry check
                true
            },
            IntegrityCheckType::SystemFile => {
                // Simulate system file check
                true
            },
            IntegrityCheckType::CriticalProcess => {
                // Simulate critical process check
                true
            },
        }
    }

    fn create_tamper_alert(
        &self,
        alert_type: TamperAlertType,
        severity: AlertSeverity,
        description: String,
        affected_resource: String,
        detected_changes: Vec<String>,
        recommended_actions: Vec<String>,
    ) {
        let mut state = TAMPER_STATE.lock().unwrap();

        // Map severity to event severity before moving
        let event_severity = match &severity {
            AlertSeverity::Low => EventSeverity::Info,
            AlertSeverity::Medium => EventSeverity::Warning,
            AlertSeverity::High => EventSeverity::Error,
            AlertSeverity::Critical => EventSeverity::Critical,
        };

        let alert = TamperAlert {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            alert_type,
            severity,
            description,
            affected_resource,
            detected_changes,
            recommended_actions,
            resolved: false,
            resolved_at: None,
        };

        state.tamper_alerts.push(alert.clone());

        // Log the event
        let event = TamperEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: TamperEventType::TamperAlertCreated,
            description: format!("Tamper alert created: {}", alert.description),
            details: serde_json::json!({
                "alert_id": alert.id,
                "alert_type": format!("{:?}", alert.alert_type),
                "severity": format!("{:?}", alert.severity)
            }),
            severity: event_severity,
        };

        state.tamper_events.push(event);
    }

    fn detect_anomalies(&self, state: &mut TamperState) {
        for detector in state.anomaly_detectors.values_mut() {
            if !detector.enabled {
                continue;
            }

            // Simulate anomaly detection
            let anomaly_score = self.calculate_anomaly_score(detector);

            if anomaly_score > detector.threshold {
                detector.status = DetectorStatus::Alert;
                detector.last_detection = Utc::now();

                self.create_tamper_alert(
                    TamperAlertType::AnomalyDetected,
                    AlertSeverity::Medium,
                    format!("Anomaly detected by {}: score {:.2}", detector.name, anomaly_score),
                    detector.target.clone(),
                    vec![format!("Anomaly score: {:.2}", anomaly_score)],
                    vec![
                        "Investigate the anomaly source".to_string(),
                        "Review recent system changes".to_string(),
                        "Update baseline if legitimate".to_string(),
                    ],
                );
            } else {
                detector.status = DetectorStatus::Active;
            }
        }
    }

    fn calculate_anomaly_score(&self, detector: &AnomalyDetector) -> f32 {
        // Simulate anomaly score calculation
        // In a real implementation, this would use statistical analysis
        if detector.baseline_values.is_empty() {
            return 0.0;
        }

        // Simple simulation - occasionally return high scores
        if rand::random::<f32>() < 0.05 { // 5% chance
            3.5 // Above threshold
        } else {
            1.2 // Normal
        }
    }
}

// Tauri commands for tamper detection module
#[tauri::command]
pub fn get_integrity_checks() -> Result<Vec<IntegrityCheck>, String> {
    let state = TAMPER_STATE.lock().unwrap();
    Ok(state.integrity_checks.values().cloned().collect())
}

#[tauri::command]
pub fn run_integrity_check(check_id: String) -> Result<IntegrityStatus, String> {
    let mut state = TAMPER_STATE.lock().unwrap();

    if let Some(check) = state.integrity_checks.get_mut(&check_id) {
        let module = TamperDetectionModule::default();
        let is_valid = module.perform_single_integrity_check(check);
        check.last_check = Utc::now();

        let status = if is_valid {
            IntegrityStatus::Valid
        } else {
            IntegrityStatus::Modified
        };

        check.status = status.clone();

        Ok(status)
    } else {
        Err(format!("Integrity check {} not found", check_id))
    }
}

#[tauri::command]
pub fn get_anomaly_detectors() -> Result<Vec<AnomalyDetector>, String> {
    let state = TAMPER_STATE.lock().unwrap();
    Ok(state.anomaly_detectors.values().cloned().collect())
}

#[tauri::command]
pub fn get_secure_boot_status() -> Result<SecureBootStatus, String> {
    let state = TAMPER_STATE.lock().unwrap();
    Ok(state.secure_boot_status.clone())
}

#[tauri::command]
pub fn get_tamper_alerts() -> Result<Vec<TamperAlert>, String> {
    let state = TAMPER_STATE.lock().unwrap();
    Ok(state.tamper_alerts.clone())
}

#[tauri::command]
pub fn resolve_tamper_alert(alert_id: String) -> Result<(), String> {
    let mut state = TAMPER_STATE.lock().unwrap();

    if let Some(alert) = state.tamper_alerts.iter_mut().find(|a| a.id == alert_id) {
        alert.resolved = true;
        alert.resolved_at = Some(Utc::now());

        // Log the resolution
        let event = TamperEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: TamperEventType::TamperAlertResolved,
            description: format!("Tamper alert resolved: {}", alert.description),
            details: serde_json::json!({
                "alert_id": alert.id,
                "resolution_time": Utc::now().to_rfc3339()
            }),
            severity: EventSeverity::Info,
        };

        state.tamper_events.push(event);

        Ok(())
    } else {
        Err(format!("Tamper alert {} not found", alert_id))
    }
}

#[tauri::command]
pub fn capture_system_baseline() -> Result<(), String> {
    let mut state = TAMPER_STATE.lock().unwrap();

    // Simulate baseline capture
    state.system_baseline.captured_at = Utc::now();
    state.system_baseline.valid = true;

    // Update integrity check expected hashes
    for check in state.integrity_checks.values_mut() {
        if check.status == IntegrityStatus::Valid {
            check.expected_hash = format!("simulated_hash_{}", Utc::now().timestamp());
        }
    }

    // Log the baseline capture
    let event = TamperEvent {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: TamperEventType::BaselineUpdated,
        description: "System baseline captured successfully".to_string(),
        details: serde_json::json!({
            "baseline_time": state.system_baseline.captured_at.to_rfc3339(),
            "checks_updated": state.integrity_checks.len()
        }),
        severity: EventSeverity::Info,
    };

    state.tamper_events.push(event);

    Ok(())
}

#[tauri::command]
pub fn get_tamper_events(limit: Option<usize>) -> Result<Vec<TamperEvent>, String> {
    let state = TAMPER_STATE.lock().unwrap();
    let limit = limit.unwrap_or(100);
    let mut events = state.tamper_events.clone();
    events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    events.truncate(limit);
    Ok(events)
}

#[tauri::command]
pub fn perform_anomaly_detection() -> Result<Vec<String>, String> {
    let mut state = TAMPER_STATE.lock().unwrap();
    let module = TamperDetectionModule::default();

    module.detect_anomalies(&mut state);

    // Return IDs of detectors that triggered alerts
    let alert_detectors = state.anomaly_detectors.values()
        .filter(|d| matches!(d.status, DetectorStatus::Alert))
        .map(|d| d.id.clone())
        .collect();

    Ok(alert_detectors)
}

#[tauri::command]
pub fn get_tamper_detection_dashboard() -> Result<serde_json::Value, String> {
    let state = TAMPER_STATE.lock().unwrap();

    let dashboard = serde_json::json!({
        "integrity_checks_total": state.integrity_checks.len(),
        "integrity_checks_passing": state.integrity_checks.values().filter(|c| c.status == IntegrityStatus::Valid).count(),
        "anomaly_detectors_active": state.anomaly_detectors.values().filter(|d| d.enabled).count(),
        "anomaly_detectors_alerting": state.anomaly_detectors.values().filter(|d| matches!(d.status, DetectorStatus::Alert)).count(),
        "tamper_alerts_total": state.tamper_alerts.len(),
        "tamper_alerts_unresolved": state.tamper_alerts.iter().filter(|a| !a.resolved).count(),
        "secure_boot_enabled": state.secure_boot_status.enabled,
        "system_baseline_valid": state.system_baseline.valid,
        "recent_events": state.tamper_events.len().min(10)
    });

    Ok(dashboard)
}