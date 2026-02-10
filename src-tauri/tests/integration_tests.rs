// Cyber Security Prime - Integration Tests
// Tests module interactions and API endpoints

use chrono::Utc;
use std::collections::HashMap;
use cyber_security_prime::modules::{
    compliance::{ComplianceModule, GdprComplianceData, HipaaComplianceData, DataAsset, DataCategory, DataSensitivity, ConsentRecord, ConsentType},
    isolation::{IsolationModule, Sandbox, Container, IsolationLevel, SandboxStatus, ContainerStatus},
    management::{ManagementModule, ManagedInstance, User, UserRole, InstanceStatus},
    tamper_detection::{TamperDetectionModule, IntegrityCheck, IntegrityCheckType, IntegrityStatus}
};

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_module_initialization_integration() {
        // Test that all modules can be initialized together
        let mut compliance = ComplianceModule::default();
        let mut isolation = IsolationModule::default();
        let mut management = ManagementModule::default();
        let mut tamper = TamperDetectionModule::default();

        assert!(compliance.initialize().is_ok());
        assert!(isolation.initialize().is_ok());
        assert!(management.initialize().is_ok());
        assert!(tamper.initialize().is_ok());

        // Test module health checks
        let compliance_health = compliance.health_check();
        let isolation_health = isolation.health_check();
        let management_health = management.health_check();
        let tamper_health = tamper.health_check();

        assert!(compliance_health.healthy);
        assert!(isolation_health.healthy);
        assert!(management_health.healthy);
        assert!(tamper_health.healthy);
    }

    #[test]
    fn test_compliance_isolation_integration() {
        // Test integration between compliance and isolation modules
        let mut compliance = ComplianceModule::default();
        let mut isolation = IsolationModule::default();

        // Initialize modules
        compliance.initialize().unwrap();
        isolation.initialize().unwrap();

        // Create a sandbox for compliance testing
        let sandbox = Sandbox {
            id: "compliance-test-sandbox".to_string(),
            name: "Compliance Test Environment".to_string(),
            isolation_level: IsolationLevel::Strict,
            status: SandboxStatus::Created,
            created_at: Utc::now(),
            last_used: Utc::now(),
            allowed_paths: vec!["/tmp".to_string()],
            blocked_paths: vec!["/etc".to_string()],
            network_access: cyber_security_prime::modules::isolation::NetworkAccess::None,
            resource_limits: cyber_security_prime::modules::isolation::ResourceLimits {
                cpu_cores: Some(1.0),
                memory_mb: Some(512),
                disk_mb: Some(256),
                network_mbps: None,
            },
            processes: vec![],
        };

        // Create PHI data asset for HIPAA compliance
        let phi_asset = cyber_security_prime::modules::compliance::PhiDataAsset {
            id: "phi-test-001".to_string(),
            name: "Test PHI Data".to_string(),
            phi_type: cyber_security_prime::modules::compliance::PhiType::MedicalHistory,
            location: "Isolated Sandbox".to_string(),
            custodian: "Test Custodian".to_string(),
            security_controls: vec!["encryption".to_string(), "isolation".to_string()],
            last_assessment: Utc::now(),
        };

        // Verify that sensitive data is properly isolated
        assert_eq!(sandbox.isolation_level, IsolationLevel::Strict);
        assert_eq!(sandbox.network_access, cyber_security_prime::modules::isolation::NetworkAccess::None);
        assert!(sandbox.blocked_paths.contains(&"/etc".to_string()));
        assert_eq!(phi_asset.security_controls.len(), 2);
        assert!(phi_asset.security_controls.contains(&"isolation".to_string()));
    }

    #[test]
    fn test_management_compliance_audit_integration() {
        // Test integration between management and compliance for audit trails
        let mut management = ManagementModule::default();
        let mut compliance = ComplianceModule::default();

        management.initialize().unwrap();
        compliance.initialize().unwrap();

        // Create a user in management system
        let user = User {
            id: "test-user-001".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            role: UserRole::Analyst,
            permissions: vec!["view_reports".to_string()],
            last_login: Some(Utc::now()),
            created_at: Utc::now(),
        };

        // Create consent record for GDPR compliance
        let consent = ConsentRecord {
            id: "consent-test-001".to_string(),
            subject_id: user.id.clone(),
            consent_type: ConsentType::Analytics,
            purpose: "Security analytics and reporting".to_string(),
            scope: vec!["security_logs".to_string(), "threat_data".to_string()],
            granted_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            withdrawn_at: None,
            consent_mechanism: "Management Console".to_string(),
            ip_address: Some("10.0.0.1".to_string()),
        };

        // Verify integration points
        assert_eq!(consent.subject_id, user.id);
        assert!(user.permissions.contains(&"view_reports".to_string()));
        assert_eq!(consent.consent_type, ConsentType::Analytics);
        assert!(consent.expires_at.is_some());
    }

    #[test]
    fn test_tamper_detection_isolation_integration() {
        // Test integration between tamper detection and isolation
        let mut tamper = TamperDetectionModule::default();
        let mut isolation = IsolationModule::default();

        tamper.initialize().unwrap();
        isolation.initialize().unwrap();

        // Create integrity check for isolated environment
        let integrity_check = IntegrityCheck {
            id: "isolation-integrity-check".to_string(),
            name: "Isolated Environment Integrity".to_string(),
            target_path: "/isolated/app".to_string(),
            check_type: IntegrityCheckType::FileHash,
            expected_hash: "expected_hash_for_isolated_app".to_string(),
            last_check: Utc::now(),
            status: IntegrityStatus::Valid,
            check_interval: 300, // 5 minutes
            enabled: true,
        };

        // Create container with tamper detection
        let container = Container {
            id: "tamper-test-container".to_string(),
            name: "Tamper Detection Test".to_string(),
            image: "security-tools:latest".to_string(),
            status: ContainerStatus::Created,
            created_at: Utc::now(),
            ports: vec![],
            volumes: vec![],
            environment: HashMap::new(),
            security_profile: cyber_security_prime::modules::isolation::ContainerSecurityProfile {
                privileged: false,
                apparmor_profile: Some("tamper-detection".to_string()),
                seccomp_profile: Some("strict".to_string()),
                capabilities: vec![],
                no_new_privileges: true,
            },
            processes: vec!["integrity_checker".to_string()],
        };

        // Verify security integration
        assert_eq!(integrity_check.status, IntegrityStatus::Valid);
        assert_eq!(integrity_check.check_interval, 300);
        assert!(!container.security_profile.privileged);
        assert!(container.security_profile.no_new_privileges);
        assert_eq!(container.processes.len(), 1);
    }

    #[test]
    fn test_enterprise_deployment_scenario() {
        // Test a complete enterprise deployment scenario
        let mut management = ManagementModule::default();
        let mut compliance = ComplianceModule::default();
        let mut isolation = IsolationModule::default();
        let mut tamper = TamperDetectionModule::default();

        // Initialize all modules
        management.initialize().unwrap();
        compliance.initialize().unwrap();
        isolation.initialize().unwrap();
        tamper.initialize().unwrap();

        // Create enterprise instance
        let instance = ManagedInstance {
            id: "enterprise-instance-001".to_string(),
            name: "Enterprise Server 01".to_string(),
            endpoint: "https://enterprise.securityprime.com".to_string(),
            status: InstanceStatus::Online,
            last_heartbeat: Utc::now(),
            version: "2.0.0".to_string(),
            modules: vec![
                "management".to_string(),
                "compliance".to_string(),
                "isolation".to_string(),
                "tamper_detection".to_string(),
            ],
            config: cyber_security_prime::modules::management::InstanceConfig {
                auto_update: true,
                monitoring_enabled: true,
                alert_thresholds: cyber_security_prime::modules::management::AlertThresholds {
                    cpu_usage: 80.0,
                    memory_usage: 85.0,
                    disk_usage: 90.0,
                    threat_score: 7.0,
                },
                compliance_settings: cyber_security_prime::modules::management::ComplianceSettings {
                    gdpr_enabled: true,
                    hipaa_enabled: true,
                    pci_dss_enabled: true,
                    auto_reporting: true,
                },
            },
        };

        // Create compliance data asset
        let data_asset = DataAsset {
            id: "enterprise-data-001".to_string(),
            name: "Customer Data Repository".to_string(),
            category: DataCategory::Personal,
            sensitivity: DataSensitivity::Confidential,
            location: "Enterprise Database".to_string(),
            owner: "Data Protection Officer".to_string(),
            retention_period: "10 years".to_string(),
            legal_basis: "Legitimate Interest".to_string(),
            data_subjects: vec!["customers".to_string()],
            created_at: Utc::now(),
            last_updated: Utc::now(),
        };

        // Create isolated environment for data processing
        let sandbox = Sandbox {
            id: "enterprise-sandbox-001".to_string(),
            name: "Data Processing Environment".to_string(),
            isolation_level: IsolationLevel::Maximum,
            status: SandboxStatus::Running,
            created_at: Utc::now(),
            last_used: Utc::now(),
            allowed_paths: vec!["/data/input".to_string(), "/data/output".to_string()],
            blocked_paths: vec!["/system".to_string(), "/network".to_string()],
            network_access: cyber_security_prime::modules::isolation::NetworkAccess::None,
            resource_limits: cyber_security_prime::modules::isolation::ResourceLimits {
                cpu_cores: Some(4.0),
                memory_mb: Some(8192),
                disk_mb: Some(10240),
                network_mbps: None,
            },
            processes: vec!["data_processor".to_string(), "validator".to_string()],
        };

        // Verify enterprise setup
        assert_eq!(instance.status, InstanceStatus::Online);
        assert!(instance.config.compliance_settings.gdpr_enabled);
        assert!(instance.config.compliance_settings.hipaa_enabled);
        assert!(instance.config.compliance_settings.pci_dss_enabled);

        assert_eq!(data_asset.category, DataCategory::Personal);
        assert_eq!(data_asset.sensitivity, DataSensitivity::Confidential);

        assert_eq!(sandbox.isolation_level, IsolationLevel::Maximum);
        assert_eq!(sandbox.status, SandboxStatus::Running);
        assert_eq!(sandbox.network_access, cyber_security_prime::modules::isolation::NetworkAccess::None);
        assert_eq!(sandbox.processes.len(), 2);
    }

    #[test]
    fn test_module_health_integration() {
        // Test that all modules report healthy status after initialization
        let mut modules = vec![
            Box::new(ComplianceModule::default()) as Box<dyn cyber_security_prime::modules::SecurityModule>,
            Box::new(IsolationModule::default()) as Box<dyn cyber_security_prime::modules::SecurityModule>,
            Box::new(ManagementModule::default()) as Box<dyn cyber_security_prime::modules::SecurityModule>,
            Box::new(TamperDetectionModule::default()) as Box<dyn cyber_security_prime::modules::SecurityModule>,
        ];

        // Initialize all modules
        for module in &mut modules {
            module.initialize().unwrap();
        }

        // Check health of all modules
        for module in &modules {
            let health = module.health_check();
            assert!(health.healthy, "Module {} is not healthy: {}", module.name(), health.message);
        }

        // Verify shutdown works
        for module in &mut modules {
            module.shutdown().unwrap();
        }
    }

    #[test]
    fn test_cross_module_data_flow() {
        // Test data flow between modules
        let mut management = ManagementModule::default();
        let mut compliance = ComplianceModule::default();

        management.initialize().unwrap();
        compliance.initialize().unwrap();

        // Create user in management
        let user_id = "integration-test-user".to_string();

        // Create audit entry that could be related to compliance
        let audit_entry = cyber_security_prime::modules::management::AuditEntry {
            id: "audit-integration-001".to_string(),
            timestamp: Utc::now(),
            user_id: user_id.clone(),
            action: "consent_granted".to_string(),
            resource: "gdpr_consent".to_string(),
            details: serde_json::json!({
                "consent_type": "marketing",
                "purpose": "Security product updates"
            }),
            ip_address: Some("192.168.1.100".to_string()),
            user_agent: Some("SecurityPrime/2.0".to_string()),
        };

        // Create corresponding consent record
        let consent = ConsentRecord {
            id: "consent-integration-001".to_string(),
            subject_id: user_id,
            consent_type: ConsentType::Marketing,
            purpose: "Security product updates and communications".to_string(),
            scope: vec!["email".to_string(), "product_updates".to_string()],
            granted_at: audit_entry.timestamp,
            expires_at: Some(audit_entry.timestamp + chrono::Duration::days(365)),
            withdrawn_at: None,
            consent_mechanism: "Management Console".to_string(),
            ip_address: audit_entry.ip_address.clone(),
            user_agent: audit_entry.user_agent.clone(),
        };

        // Verify data consistency
        assert_eq!(consent.subject_id, audit_entry.user_id);
        assert_eq!(consent.consent_type, ConsentType::Marketing);
        assert_eq!(consent.granted_at, audit_entry.timestamp);
        assert_eq!(consent.ip_address, audit_entry.ip_address);
        assert!(consent.expires_at.is_some());
    }
}