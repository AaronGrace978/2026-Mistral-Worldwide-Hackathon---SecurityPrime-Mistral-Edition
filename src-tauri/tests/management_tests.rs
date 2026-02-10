// Cyber Security Prime - Management Module Tests

use chrono::Utc;
use cyber_security_prime::modules::management::{
    ManagementModule, ManagementState, ManagedInstance, User, AuditEntry,
    SecurityPolicy, ManagementAlert, InstanceStatus, UserRole, AlertLevel,
    PolicyRule, InstanceConfig, AlertThresholds, ComplianceSettings
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_management_module_initialization() {
        let mut module = ManagementModule::default();
        assert_eq!(module.name(), "Enterprise Management");
        assert_eq!(module.description(), "Centralized management console for enterprise deployments");
        assert!(module.is_active());

        // Test initialization
        let result = module.initialize();
        assert!(result.is_ok());
    }

    #[test]
    fn test_management_state_new() {
        let state = ManagementState::new();

        assert!(state.instances.is_empty());
        assert!(state.users.is_empty());
        assert!(state.audit_logs.is_empty());
        assert!(state.policies.is_empty());
        assert!(state.alerts.is_empty());
    }

    #[test]
    fn test_managed_instance_creation() {
        let config = InstanceConfig {
            auto_update: true,
            monitoring_enabled: true,
            alert_thresholds: AlertThresholds {
                cpu_usage: 80.0,
                memory_usage: 85.0,
                disk_usage: 90.0,
                threat_score: 7.0,
            },
            compliance_settings: ComplianceSettings {
                gdpr_enabled: true,
                hipaa_enabled: false,
                pci_dss_enabled: true,
                auto_reporting: true,
            },
        };

        let instance = ManagedInstance {
            id: "instance-001".to_string(),
            name: "Production Server 01".to_string(),
            endpoint: "https://prod-01.securityprime.com".to_string(),
            status: InstanceStatus::Online,
            last_heartbeat: Utc::now(),
            version: "1.2.3".to_string(),
            modules: vec!["scanner".to_string(), "firewall".to_string()],
            config,
        };

        assert_eq!(instance.name, "Production Server 01");
        assert_eq!(instance.status, InstanceStatus::Online);
        assert_eq!(instance.version, "1.2.3");
        assert_eq!(instance.modules.len(), 2);
        assert!(instance.config.auto_update);
        assert!(instance.config.monitoring_enabled);
        assert!(instance.config.compliance_settings.gdpr_enabled);
        assert!(!instance.config.compliance_settings.hipaa_enabled);
    }

    #[test]
    fn test_user_creation() {
        let user = User {
            id: "user-001".to_string(),
            username: "admin".to_string(),
            email: "admin@company.com".to_string(),
            role: UserRole::Admin,
            permissions: vec![
                "manage_users".to_string(),
                "manage_instances".to_string(),
                "view_audit_logs".to_string(),
            ],
            last_login: Some(Utc::now()),
            created_at: Utc::now(),
        };

        assert_eq!(user.username, "admin");
        assert_eq!(user.role, UserRole::Admin);
        assert_eq!(user.permissions.len(), 3);
        assert!(user.last_login.is_some());
    }

    #[test]
    fn test_audit_entry_creation() {
        let audit_entry = AuditEntry {
            id: "audit-001".to_string(),
            timestamp: Utc::now(),
            user_id: "user-001".to_string(),
            action: "user_login".to_string(),
            resource: "authentication".to_string(),
            details: serde_json::json!({
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0..."
            }),
            ip_address: Some("192.168.1.100".to_string()),
            user_agent: Some("Mozilla/5.0...".to_string()),
        };

        assert_eq!(audit_entry.action, "user_login");
        assert_eq!(audit_entry.resource, "authentication");
        assert!(audit_entry.details.is_object());
        assert!(audit_entry.ip_address.is_some());
        assert!(audit_entry.user_agent.is_some());
    }

    #[test]
    fn test_security_policy_creation() {
        let policy = SecurityPolicy {
            id: "password-policy".to_string(),
            name: "Password Security Policy".to_string(),
            description: "Enforces strong password requirements".to_string(),
            rules: vec![
                PolicyRule {
                    id: "min-length".to_string(),
                    condition: "password_length < 12".to_string(),
                    action: "reject".to_string(),
                    severity: "high".to_string(),
                    parameters: HashMap::new(),
                },
                PolicyRule {
                    id: "complexity".to_string(),
                    condition: "password_complexity < 3".to_string(),
                    action: "reject".to_string(),
                    severity: "medium".to_string(),
                    parameters: HashMap::new(),
                },
            ],
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(policy.name, "Password Security Policy");
        assert_eq!(policy.rules.len(), 2);
        assert!(policy.enabled);
    }

    #[test]
    fn test_management_alert_creation() {
        let alert = ManagementAlert {
            id: "alert-001".to_string(),
            timestamp: Utc::now(),
            level: AlertLevel::Critical,
            title: "Security Breach Detected".to_string(),
            message: "Unauthorized access attempt from unknown IP".to_string(),
            instance_id: Some("instance-001".to_string()),
            resolved: false,
            resolved_at: None,
        };

        assert_eq!(alert.level, AlertLevel::Critical);
        assert_eq!(alert.title, "Security Breach Detected");
        assert!(alert.instance_id.is_some());
        assert!(!alert.resolved);
        assert!(alert.resolved_at.is_none());
    }

    #[test]
    fn test_instance_config() {
        let config = InstanceConfig {
            auto_update: true,
            monitoring_enabled: true,
            alert_thresholds: AlertThresholds {
                cpu_usage: 85.0,
                memory_usage: 90.0,
                disk_usage: 95.0,
                threat_score: 8.0,
            },
            compliance_settings: ComplianceSettings {
                gdpr_enabled: true,
                hipaa_enabled: true,
                pci_dss_enabled: false,
                auto_reporting: true,
            },
        };

        assert!(config.auto_update);
        assert!(config.monitoring_enabled);
        assert_eq!(config.alert_thresholds.cpu_usage, 85.0);
        assert_eq!(config.alert_thresholds.memory_usage, 90.0);
        assert!(config.compliance_settings.gdpr_enabled);
        assert!(config.compliance_settings.hipaa_enabled);
        assert!(!config.compliance_settings.pci_dss_enabled);
        assert!(config.compliance_settings.auto_reporting);
    }

    #[test]
    fn test_policy_rule() {
        let rule = PolicyRule {
            id: "session-timeout".to_string(),
            condition: "session_duration > 480".to_string(), // 8 hours
            action: "force_logout".to_string(),
            severity: "medium".to_string(),
            parameters: HashMap::from([
                ("grace_period".to_string(), "300".to_string()), // 5 minutes
                ("warning_message".to_string(), "Session will expire soon".to_string()),
            ]),
        };

        assert_eq!(rule.condition, "session_duration > 480");
        assert_eq!(rule.action, "force_logout");
        assert_eq!(rule.severity, "medium");
        assert_eq!(rule.parameters.len(), 2);
    }

    #[test]
    fn test_user_role_permissions() {
        // Test Admin role
        let admin_user = User {
            id: "admin-001".to_string(),
            username: "admin".to_string(),
            email: "admin@company.com".to_string(),
            role: UserRole::Admin,
            permissions: vec![],
            last_login: None,
            created_at: Utc::now(),
        };

        // Permissions should be assigned based on role in real implementation
        // Here we just test the role enum
        assert_eq!(admin_user.role, UserRole::Admin);

        // Test other roles
        assert_eq!(UserRole::Manager as u8, 1);
        assert_eq!(UserRole::Analyst as u8, 2);
        assert_eq!(UserRole::Auditor as u8, 3);
        assert_eq!(UserRole::ReadOnly as u8, 4);
    }

    #[test]
    fn test_instance_status_enum() {
        assert_eq!(InstanceStatus::Online as u8, 0);
        assert_eq!(InstanceStatus::Offline as u8, 1);
        assert_eq!(InstanceStatus::Maintenance as u8, 2);
        assert_eq!(InstanceStatus::Error as u8, 3);
    }

    #[test]
    fn test_alert_level_enum() {
        assert_eq!(AlertLevel::Info as u8, 0);
        assert_eq!(AlertLevel::Warning as u8, 1);
        assert_eq!(AlertLevel::Error as u8, 2);
        assert_eq!(AlertLevel::Critical as u8, 3);
    }

    #[test]
    fn test_default_admin_creation() {
        let mut state = ManagementState::new();
        let module = ManagementModule::default();

        // Simulate initialization
        module.create_default_admin(&mut state);

        assert_eq!(state.users.len(), 1);
        let admin = state.users.values().next().unwrap();
        assert_eq!(admin.username, "admin");
        assert_eq!(admin.role, UserRole::Admin);
        assert!(admin.permissions.contains(&"manage_users".to_string()));
        assert!(admin.permissions.contains(&"manage_instances".to_string()));
    }

    #[test]
    fn test_default_policies_creation() {
        let mut state = ManagementState::new();
        let module = ManagementModule::default();

        // Simulate policy initialization
        module.initialize_default_policies(&mut state);

        assert!(!state.policies.is_empty());
        assert!(state.policies.contains_key("password-policy"));
        assert!(state.policies.contains_key("access-control"));

        let password_policy = state.policies.get("password-policy").unwrap();
        assert_eq!(password_policy.name, "Password Security Policy");
        assert!(password_policy.enabled);

        let access_policy = state.policies.get("access-control").unwrap();
        assert_eq!(access_policy.name, "Access Control Policy");
        assert!(access_policy.enabled);
    }
}