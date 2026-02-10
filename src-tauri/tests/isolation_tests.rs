// Cyber Security Prime - Isolation Module Tests

use chrono::Utc;
use std::collections::HashMap;
use cyber_security_prime::modules::isolation::{
    IsolationModule, IsolationState, Sandbox, Container, IsolationProfile,
    IsolatedProcess, IsolationEvent, ResourceLimits, NetworkAccess,
    IsolationLevel, SandboxStatus, ContainerStatus, PortMapping,
    VolumeMapping, ContainerSecurityProfile, IsolationSettings,
    SecurityPolicy, ProcessStatus, ResourceUsage, IsolationEventType,
    AnomalyDetector, AnomalyType, DetectorStatus, EventSeverity
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isolation_module_initialization() {
        let mut module = IsolationModule::default();
        assert_eq!(module.name(), "Process Isolation");
        assert_eq!(module.description(), "Sandboxing and containerization for enhanced security");
        assert!(module.is_active());

        // Test initialization
        let result = module.initialize();
        assert!(result.is_ok());
    }

    #[test]
    fn test_isolation_state_new() {
        let state = IsolationState::new();

        assert!(state.sandboxes.is_empty());
        assert!(state.containers.is_empty());
        assert!(!state.isolation_profiles.is_empty()); // Should have default profiles
        assert!(state.running_processes.is_empty());
        assert!(state.isolation_events.is_empty());

        // Check default profiles
        assert!(state.isolation_profiles.contains_key("web-browsing"));
        assert!(state.isolation_profiles.contains_key("file-analysis"));
        assert!(state.isolation_profiles.contains_key("development"));
    }

    #[test]
    fn test_sandbox_creation() {
        let sandbox = Sandbox {
            id: "sandbox-001".to_string(),
            name: "Test Sandbox".to_string(),
            isolation_level: IsolationLevel::Standard,
            status: SandboxStatus::Created,
            created_at: Utc::now(),
            last_used: Utc::now(),
            allowed_paths: vec!["/tmp".to_string()],
            blocked_paths: vec!["/system".to_string()],
            network_access: NetworkAccess::NAT,
            resource_limits: ResourceLimits {
                cpu_cores: Some(2.0),
                memory_mb: Some(1024),
                disk_mb: Some(512),
                network_mbps: Some(10),
            },
            processes: vec!["test.exe".to_string()],
        };

        assert_eq!(sandbox.name, "Test Sandbox");
        assert_eq!(sandbox.isolation_level, IsolationLevel::Standard);
        assert_eq!(sandbox.status, SandboxStatus::Created);
        assert_eq!(sandbox.allowed_paths.len(), 1);
        assert_eq!(sandbox.blocked_paths.len(), 1);
        assert_eq!(sandbox.network_access, NetworkAccess::NAT);
        assert_eq!(sandbox.resource_limits.cpu_cores, Some(2.0));
    }

    #[test]
    fn test_container_creation() {
        let container = Container {
            id: "container-001".to_string(),
            name: "Test Container".to_string(),
            image: "ubuntu:20.04".to_string(),
            status: ContainerStatus::Created,
            created_at: Utc::now(),
            ports: vec![
                PortMapping {
                    host_port: 8080,
                    container_port: 80,
                    protocol: "tcp".to_string(),
                }
            ],
            volumes: vec![
                VolumeMapping {
                    host_path: "/host/data".to_string(),
                    container_path: "/container/data".to_string(),
                    read_only: false,
                }
            ],
            environment: HashMap::from([
                ("ENV_VAR".to_string(), "value".to_string())
            ]),
            security_profile: ContainerSecurityProfile {
                privileged: false,
                apparmor_profile: Some("docker-default".to_string()),
                seccomp_profile: Some("docker-default".to_string()),
                capabilities: vec!["NET_BIND_SERVICE".to_string()],
                no_new_privileges: true,
            },
            processes: vec!["nginx".to_string()],
        };

        assert_eq!(container.image, "ubuntu:20.04");
        assert_eq!(container.ports.len(), 1);
        assert_eq!(container.volumes.len(), 1);
        assert_eq!(container.environment.len(), 1);
        assert!(!container.security_profile.privileged);
        assert_eq!(container.processes.len(), 1);
    }

    #[test]
    fn test_isolation_profile_creation() {
        let profile = IsolationProfile {
            id: "test-profile".to_string(),
            name: "Test Profile".to_string(),
            description: "A test isolation profile".to_string(),
            isolation_level: IsolationLevel::Strict,
            default_settings: IsolationSettings {
                network_isolation: true,
                filesystem_isolation: true,
                process_isolation: true,
                resource_limits: ResourceLimits {
                    cpu_cores: Some(1.0),
                    memory_mb: Some(512),
                    disk_mb: None,
                    network_mbps: None,
                },
            },
            allowed_applications: vec!["firefox".to_string(), "thunderbird".to_string()],
            security_policies: vec![
                SecurityPolicy {
                    id: "no-system-access".to_string(),
                    name: "No System Access".to_string(),
                    rules: vec![
                        "block /etc/passwd".to_string(),
                        "block /etc/shadow".to_string(),
                    ],
                }
            ],
        };

        assert_eq!(profile.isolation_level, IsolationLevel::Strict);
        assert!(profile.default_settings.network_isolation);
        assert!(profile.default_settings.filesystem_isolation);
        assert!(profile.default_settings.process_isolation);
        assert_eq!(profile.allowed_applications.len(), 2);
        assert_eq!(profile.security_policies.len(), 1);
    }

    #[test]
    fn test_isolated_process_creation() {
        let process = IsolatedProcess {
            id: "process-001".to_string(),
            process_id: 1234,
            name: "test_app.exe".to_string(),
            sandbox_id: Some("sandbox-001".to_string()),
            container_id: None,
            isolation_level: IsolationLevel::Basic,
            started_at: Utc::now(),
            status: ProcessStatus::Running,
            resource_usage: ResourceUsage {
                cpu_percent: 15.5,
                memory_mb: 256,
                disk_mb: 50,
                network_bytes: 1024,
            },
        };

        assert_eq!(process.process_id, 1234);
        assert_eq!(process.name, "test_app.exe");
        assert!(process.sandbox_id.is_some());
        assert!(process.container_id.is_none());
        assert_eq!(process.isolation_level, IsolationLevel::Basic);
        assert_eq!(process.status, ProcessStatus::Running);
        assert_eq!(process.resource_usage.cpu_percent, 15.5);
    }

    #[test]
    fn test_isolation_event_creation() {
        let event = IsolationEvent {
            id: "event-001".to_string(),
            timestamp: Utc::now(),
            event_type: IsolationEventType::SandboxCreated,
            sandbox_id: Some("sandbox-001".to_string()),
            container_id: None,
            process_id: None,
            description: "Sandbox created successfully".to_string(),
            severity: EventSeverity::Info,
            details: serde_json::json!({
                "profile": "web-browsing",
                "isolation_level": "Standard"
            }),
        };

        assert_eq!(event.event_type, IsolationEventType::SandboxCreated);
        assert!(event.sandbox_id.is_some());
        assert!(event.container_id.is_none());
        assert!(event.process_id.is_none());
        assert_eq!(event.severity, EventSeverity::Info);
        assert!(event.details.is_object());
    }

    #[test]
    fn test_anomaly_detector_creation() {
        let detector = AnomalyDetector {
            id: "detector-001".to_string(),
            name: "File System Monitor".to_string(),
            detector_type: AnomalyType::FileSystemActivity,
            target: "/home/user".to_string(),
            threshold: 2.5,
            baseline_values: vec![1.2, 1.5, 1.1, 1.8, 1.3],
            last_detection: Utc::now(),
            status: DetectorStatus::Active,
            sensitivity: 0.8,
            enabled: true,
        };

        assert_eq!(detector.detector_type, AnomalyType::FileSystemActivity);
        assert_eq!(detector.threshold, 2.5);
        assert_eq!(detector.baseline_values.len(), 5);
        assert_eq!(detector.status, DetectorStatus::Active);
        assert_eq!(detector.sensitivity, 0.8);
        assert!(detector.enabled);
    }

    #[test]
    fn test_resource_limits() {
        let limits = ResourceLimits {
            cpu_cores: Some(4.0),
            memory_mb: Some(8192),
            disk_mb: Some(10240),
            network_mbps: Some(100),
        };

        assert_eq!(limits.cpu_cores, Some(4.0));
        assert_eq!(limits.memory_mb, Some(8192));
        assert_eq!(limits.disk_mb, Some(10240));
        assert_eq!(limits.network_mbps, Some(100));
    }

    #[test]
    fn test_port_mapping() {
        let mapping = PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
        };

        assert_eq!(mapping.host_port, 8080);
        assert_eq!(mapping.container_port, 80);
        assert_eq!(mapping.protocol, "tcp");
    }

    #[test]
    fn test_volume_mapping() {
        let mapping = VolumeMapping {
            host_path: "/host/data".to_string(),
            container_path: "/container/data".to_string(),
            read_only: true,
        };

        assert_eq!(mapping.host_path, "/host/data");
        assert_eq!(mapping.container_path, "/container/data");
        assert!(mapping.read_only);
    }

    #[test]
    fn test_container_security_profile() {
        let profile = ContainerSecurityProfile {
            privileged: false,
            apparmor_profile: Some("custom-profile".to_string()),
            seccomp_profile: Some("custom-seccomp".to_string()),
            capabilities: vec!["CAP_NET_ADMIN".to_string(), "CAP_SYS_TIME".to_string()],
            no_new_privileges: true,
        };

        assert!(!profile.privileged);
        assert!(profile.apparmor_profile.is_some());
        assert!(profile.seccomp_profile.is_some());
        assert_eq!(profile.capabilities.len(), 2);
        assert!(profile.no_new_privileges);
    }

    #[test]
    fn test_isolation_settings() {
        let settings = IsolationSettings {
            network_isolation: true,
            filesystem_isolation: true,
            process_isolation: false,
            resource_limits: ResourceLimits {
                cpu_cores: Some(2.0),
                memory_mb: Some(2048),
                disk_mb: None,
                network_mbps: Some(50),
            },
        };

        assert!(settings.network_isolation);
        assert!(settings.filesystem_isolation);
        assert!(!settings.process_isolation);
        assert_eq!(settings.resource_limits.cpu_cores, Some(2.0));
    }

    #[test]
    fn test_security_policy() {
        let policy = SecurityPolicy {
            id: "policy-001".to_string(),
            name: "Access Control Policy".to_string(),
            rules: vec![
                "allow /home/user/*".to_string(),
                "block /etc/*".to_string(),
                "block /root/*".to_string(),
            ],
        };

        assert_eq!(policy.name, "Access Control Policy");
        assert_eq!(policy.rules.len(), 3);
    }

    #[test]
    fn test_isolation_level_enum() {
        assert_eq!(IsolationLevel::None as u8, 0);
        assert_eq!(IsolationLevel::Basic as u8, 1);
        assert_eq!(IsolationLevel::Standard as u8, 2);
        assert_eq!(IsolationLevel::Strict as u8, 3);
        assert_eq!(IsolationLevel::Maximum as u8, 4);
    }

    #[test]
    fn test_network_access_enum() {
        assert_eq!(NetworkAccess::None as u8, 0);
        assert_eq!(NetworkAccess::HostOnly as u8, 1);
        assert_eq!(NetworkAccess::NAT as u8, 2);
        assert_eq!(NetworkAccess::Bridged as u8, 3);
    }

    #[test]
    fn test_process_status_enum() {
        assert_eq!(ProcessStatus::Running as u8, 0);
        assert_eq!(ProcessStatus::Suspended as u8, 1);
        assert_eq!(ProcessStatus::Terminated as u8, 2);
        assert_eq!(ProcessStatus::Error as u8, 3);
    }

    #[test]
    fn test_default_profiles_loaded() {
        let state = IsolationState::new();

        // Check that default profiles are loaded
        let web_profile = state.isolation_profiles.get("web-browsing").unwrap();
        assert_eq!(web_profile.name, "Web Browsing");
        assert_eq!(web_profile.isolation_level, IsolationLevel::Standard);

        let analysis_profile = state.isolation_profiles.get("file-analysis").unwrap();
        assert_eq!(analysis_profile.name, "File Analysis");
        assert_eq!(analysis_profile.isolation_level, IsolationLevel::Strict);

        let dev_profile = state.isolation_profiles.get("development").unwrap();
        assert_eq!(dev_profile.name, "Development Environment");
        assert_eq!(dev_profile.isolation_level, IsolationLevel::Basic);
    }
}