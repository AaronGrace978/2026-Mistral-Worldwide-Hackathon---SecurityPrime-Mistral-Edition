// Cyber Security Prime - Tamper Detection Module Tests

use chrono::Utc;
use std::collections::HashMap;
use cyber_security_prime::modules::tamper_detection::{
    TamperDetectionModule, TamperState, IntegrityCheck, AnomalyDetector,
    SecureBootStatus, TamperAlert, SystemBaseline, FilePermissions,
    ProcessSignature, NetworkBaseline, IntegrityCheckType,
    IntegrityStatus, AnomalyType, DetectorStatus, SecureBootState,
    TamperAlertType, AlertSeverity, TamperEvent, TamperEventType,
    EventSeverity, BootMeasurement
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tamper_detection_module_initialization() {
        let mut module = TamperDetectionModule::default();
        assert_eq!(module.name(), "Tamper Detection");
        assert_eq!(module.description(), "Integrity checking, anomaly detection, and secure boot");
        assert!(module.is_active());

        // Test initialization
        let result = module.initialize();
        assert!(result.is_ok());
    }

    #[test]
    fn test_tamper_state_new() {
        let state = TamperState::new();

        assert!(state.integrity_checks.is_empty());
        assert!(state.anomaly_detectors.is_empty());
        assert!(state.tamper_alerts.is_empty());
        assert!(state.tamper_events.is_empty());

        // Check system baseline
        assert!(!state.system_baseline.valid);
        assert!(state.system_baseline.system_hashes.is_empty());
        assert!(state.system_baseline.file_permissions.is_empty());
        assert!(!state.system_baseline.registry_baseline.is_empty()); // Should have allowed ports
        assert!(state.system_baseline.process_baseline.is_empty());

        // Check secure boot status
        assert!(!state.secure_boot_status.enabled);
        assert!(!state.secure_boot_status.secure_boot_supported);
        assert!(!state.secure_boot_status.measured_boot);
        assert!(!state.secure_boot_status.tpm_present);
        assert_eq!(state.secure_boot_status.status, SecureBootState::Unknown);
    }

    #[test]
    fn test_integrity_check_creation() {
        let check = IntegrityCheck {
            id: "check-001".to_string(),
            name: "System32 Integrity".to_string(),
            target_path: "C:\\Windows\\System32".to_string(),
            check_type: IntegrityCheckType::DirectoryHash,
            expected_hash: "abc123...".to_string(),
            last_check: Utc::now(),
            status: IntegrityStatus::Valid,
            check_interval: 3600,
            enabled: true,
        };

        assert_eq!(check.name, "System32 Integrity");
        assert_eq!(check.check_type, IntegrityCheckType::DirectoryHash);
        assert_eq!(check.status, IntegrityStatus::Valid);
        assert_eq!(check.check_interval, 3600);
        assert!(check.enabled);
    }

    #[test]
    fn test_anomaly_detector_creation() {
        let detector = AnomalyDetector {
            id: "detector-001".to_string(),
            name: "Network Traffic Monitor".to_string(),
            detector_type: AnomalyType::NetworkTraffic,
            target: "eth0".to_string(),
            threshold: 3.0,
            baseline_values: vec![100.0, 120.0, 95.0, 110.0, 105.0],
            last_detection: Utc::now(),
            status: DetectorStatus::Active,
            sensitivity: 0.8,
            enabled: true,
        };

        assert_eq!(detector.name, "Network Traffic Monitor");
        assert_eq!(detector.detector_type, AnomalyType::NetworkTraffic);
        assert_eq!(detector.threshold, 3.0);
        assert_eq!(detector.baseline_values.len(), 5);
        assert_eq!(detector.status, DetectorStatus::Active);
        assert_eq!(detector.sensitivity, 0.8);
    }

    #[test]
    fn test_secure_boot_status() {
        let boot_status = SecureBootStatus {
            enabled: true,
            secure_boot_supported: true,
            measured_boot: true,
            tpm_present: true,
            tpm_version: Some("2.0".to_string()),
            boot_measurements: vec![
                BootMeasurement {
                    pcr_index: 0,
                    measurement: "hash1".to_string(),
                    description: "BIOS".to_string(),
                    timestamp: Utc::now(),
                },
                BootMeasurement {
                    pcr_index: 4,
                    measurement: "hash2".to_string(),
                    description: "Boot loader".to_string(),
                    timestamp: Utc::now(),
                },
            ],
            last_verification: Utc::now(),
            status: SecureBootState::Enabled,
        };

        assert!(boot_status.enabled);
        assert!(boot_status.secure_boot_supported);
        assert!(boot_status.measured_boot);
        assert!(boot_status.tpm_present);
        assert_eq!(boot_status.tpm_version, Some("2.0".to_string()));
        assert_eq!(boot_status.boot_measurements.len(), 2);
        assert_eq!(boot_status.status, SecureBootState::Enabled);
    }

    #[test]
    fn test_tamper_alert_creation() {
        let alert = TamperAlert {
            id: "alert-001".to_string(),
            timestamp: Utc::now(),
            alert_type: TamperAlertType::IntegrityViolation,
            severity: AlertSeverity::High,
            description: "File integrity violation detected".to_string(),
            affected_resource: "/etc/passwd".to_string(),
            detected_changes: vec![
                "File size changed".to_string(),
                "Hash mismatch".to_string(),
            ],
            recommended_actions: vec![
                "Review system logs".to_string(),
                "Verify file integrity".to_string(),
                "Check for malware".to_string(),
            ],
            resolved: false,
            resolved_at: None,
        };

        assert_eq!(alert.alert_type, TamperAlertType::IntegrityViolation);
        assert_eq!(alert.severity, AlertSeverity::High);
        assert_eq!(alert.affected_resource, "/etc/passwd");
        assert_eq!(alert.detected_changes.len(), 2);
        assert_eq!(alert.recommended_actions.len(), 3);
        assert!(!alert.resolved);
        assert!(alert.resolved_at.is_none());
    }

    #[test]
    fn test_system_baseline() {
        let baseline = SystemBaseline {
            captured_at: Utc::now(),
            system_hashes: HashMap::from([
                ("/bin/ls".to_string(), "hash1".to_string()),
                ("/bin/ps".to_string(), "hash2".to_string()),
            ]),
            file_permissions: HashMap::from([
                ("/etc/passwd".to_string(), FilePermissions {
                    owner: "root".to_string(),
                    group: "root".to_string(),
                    permissions: "644".to_string(),
                    size: 1024,
                    modified: Utc::now(),
                }),
            ]),
            registry_baseline: HashMap::new(),
            process_baseline: vec![
                ProcessSignature {
                    name: "sshd".to_string(),
                    expected_hash: "sshd_hash".to_string(),
                    allowed_paths: vec!["/usr/sbin/sshd".to_string()],
                },
            ],
            network_baseline: NetworkBaseline {
                allowed_ports: vec![22, 80, 443],
                allowed_connections: vec![],
                expected_services: vec!["sshd".to_string(), "httpd".to_string()],
            },
            valid: true,
        };

        assert!(baseline.valid);
        assert_eq!(baseline.system_hashes.len(), 2);
        assert_eq!(baseline.file_permissions.len(), 1);
        assert_eq!(baseline.process_baseline.len(), 1);
        assert_eq!(baseline.network_baseline.allowed_ports.len(), 3);
        assert_eq!(baseline.network_baseline.expected_services.len(), 2);
    }

    #[test]
    fn test_tamper_event_creation() {
        let event = TamperEvent {
            id: "event-001".to_string(),
            timestamp: Utc::now(),
            event_type: TamperEventType::IntegrityCheckPassed,
            description: "Integrity check passed for /etc/passwd".to_string(),
            details: serde_json::json!({
                "check_id": "check-001",
                "file_path": "/etc/passwd",
                "hash": "expected_hash"
            }),
            severity: EventSeverity::Info,
        };

        assert_eq!(event.event_type, TamperEventType::IntegrityCheckPassed);
        assert_eq!(event.severity, EventSeverity::Info);
        assert!(event.details.is_object());
    }

    #[test]
    fn test_boot_measurement() {
        let measurement = BootMeasurement {
            pcr_index: 7,
            measurement: "a665b7c7a6b04c8b9c6e8d4f2b3c1e5f7a9b8c6d4e2f1a3b5c7d9e8f6a4b2c0".to_string(),
            description: "Secure Boot Policy".to_string(),
            timestamp: Utc::now(),
        };

        assert_eq!(measurement.pcr_index, 7);
        assert_eq!(measurement.description, "Secure Boot Policy");
        assert!(!measurement.measurement.is_empty());
    }

    #[test]
    fn test_integrity_check_types() {
        assert_eq!(IntegrityCheckType::FileHash as u8, 0);
        assert_eq!(IntegrityCheckType::DirectoryHash as u8, 1);
        assert_eq!(IntegrityCheckType::RegistryKey as u8, 2);
        assert_eq!(IntegrityCheckType::SystemFile as u8, 3);
        assert_eq!(IntegrityCheckType::CriticalProcess as u8, 4);
    }

    #[test]
    fn test_integrity_status_enum() {
        assert_eq!(IntegrityStatus::Valid as u8, 0);
        assert_eq!(IntegrityStatus::Modified as u8, 1);
        assert_eq!(IntegrityStatus::Missing as u8, 2);
        assert_eq!(IntegrityStatus::AccessDenied as u8, 3);
        assert_eq!(IntegrityStatus::Unknown as u8, 4);
    }

    #[test]
    fn test_anomaly_types() {
        assert_eq!(AnomalyType::FileSystemActivity as u8, 0);
        assert_eq!(AnomalyType::NetworkTraffic as u8, 1);
        assert_eq!(AnomalyType::ProcessBehavior as u8, 2);
        assert_eq!(AnomalyType::SystemLoad as u8, 3);
        assert_eq!(AnomalyType::MemoryUsage as u8, 4);
        assert_eq!(AnomalyType::LoginAttempts as u8, 5);
    }

    #[test]
    fn test_detector_status_enum() {
        assert_eq!(DetectorStatus::Learning as u8, 0);
        assert_eq!(DetectorStatus::Active as u8, 1);
        assert_eq!(DetectorStatus::Alert as u8, 2);
        assert_eq!(DetectorStatus::Disabled as u8, 3);
    }

    #[test]
    fn test_secure_boot_state_enum() {
        assert_eq!(SecureBootState::Enabled as u8, 0);
        assert_eq!(SecureBootState::Disabled as u8, 1);
        assert_eq!(SecureBootState::Compromised as u8, 2);
        assert_eq!(SecureBootState::Unknown as u8, 3);
    }

    #[test]
    fn test_tamper_alert_types() {
        assert_eq!(TamperAlertType::IntegrityViolation as u8, 0);
        assert_eq!(TamperAlertType::AnomalyDetected as u8, 1);
        assert_eq!(TamperAlertType::SecureBootFailure as u8, 2);
        assert_eq!(TamperAlertType::UnauthorizedAccess as u8, 3);
        assert_eq!(TamperAlertType::SuspiciousActivity as u8, 4);
    }

    #[test]
    fn test_alert_severity_enum() {
        assert_eq!(AlertSeverity::Low as u8, 0);
        assert_eq!(AlertSeverity::Medium as u8, 1);
        assert_eq!(AlertSeverity::High as u8, 2);
        assert_eq!(AlertSeverity::Critical as u8, 3);
    }

    #[test]
    fn test_tamper_event_types() {
        assert_eq!(TamperEventType::IntegrityCheckPassed as u8, 0);
        assert_eq!(TamperEventType::IntegrityCheckFailed as u8, 1);
        assert_eq!(TamperEventType::AnomalyDetected as u8, 2);
        assert_eq!(TamperEventType::BaselineUpdated as u8, 3);
        assert_eq!(TamperEventType::SecureBootVerified as u8, 4);
        assert_eq!(TamperEventType::TamperAlertCreated as u8, 5);
        assert_eq!(TamperEventType::TamperAlertResolved as u8, 6);
    }

    #[test]
    fn test_event_severity_enum() {
        assert_eq!(EventSeverity::Info as u8, 0);
        assert_eq!(EventSeverity::Warning as u8, 1);
        assert_eq!(EventSeverity::Error as u8, 2);
        assert_eq!(EventSeverity::Critical as u8, 3);
    }

    #[test]
    fn test_default_checks_initialization() {
        let mut state = TamperState::new();
        state.initialize_default_checks();

        assert!(!state.integrity_checks.is_empty());
        assert!(state.integrity_checks.contains_key("system32-integrity"));
        assert!(state.integrity_checks.contains_key("critical-process-integrity"));
        assert!(state.integrity_checks.contains_key("boot-config-integrity"));

        let system32_check = state.integrity_checks.get("system32-integrity").unwrap();
        assert_eq!(system32_check.check_type, IntegrityCheckType::DirectoryHash);
        assert_eq!(system32_check.check_interval, 3600);
        assert!(system32_check.enabled);
    }

    #[test]
    fn test_default_detectors_initialization() {
        let mut state = TamperState::new();
        state.initialize_default_detectors();

        assert!(!state.anomaly_detectors.is_empty());
        assert!(state.anomaly_detectors.contains_key("filesystem-anomaly"));
        assert!(state.anomaly_detectors.contains_key("network-anomaly"));
        assert!(state.anomaly_detectors.contains_key("process-anomaly"));

        let fs_detector = state.anomaly_detectors.get("filesystem-anomaly").unwrap();
        assert_eq!(fs_detector.detector_type, AnomalyType::FileSystemActivity);
        assert_eq!(fs_detector.threshold, 2.5);
        assert!(fs_detector.enabled);
    }
}