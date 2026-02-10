// Cyber Security Prime - Compliance Module Tests

use chrono::Utc;
use std::collections::HashMap;
use cyber_security_prime::modules::compliance::{
    ComplianceModule, ComplianceState, GdprComplianceData, HipaaComplianceData,
    DataAsset, DataCategory, DataSensitivity, ConsentRecord, ConsentType,
    BreachIncident, BreachSeverity, BreachStatus, RegulatoryNotification,
    SubjectRightsRequest, SubjectRightsType, RequestStatus,
    DataProcessingActivity, PhiDataAsset, PhiType, BaaRecord, BaaStatus,
    SecurityIncident, IncidentSeverity, IncidentStatus, RiskAssessment,
    RiskItem, MitigationPlan, RiskStatus, MitigationStatus,
    ComplianceAuditEntry, ComplianceFramework
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_module_initialization() {
        let mut module = ComplianceModule::default();
        assert_eq!(module.name(), "Compliance Management");
        assert_eq!(module.description(), "GDPR, HIPAA, and regulatory compliance reporting");
        assert!(module.is_active());

        // Test initialization
        let result = module.initialize();
        assert!(result.is_ok());
    }

    #[test]
    fn test_compliance_state_new() {
        let state = ComplianceState::new();

        assert!(state.data_inventory.is_empty());
        assert!(state.consent_records.is_empty());
        assert!(state.breach_incidents.is_empty());
        assert!(state.audit_trail.is_empty());

        // Check GDPR data initialization
        assert!(state.gdpr_data.data_processing_register.is_empty());
        assert!(state.gdpr_data.subject_rights_requests.is_empty());
        assert!(state.gdpr_data.data_protection_officer.is_none());
        assert_eq!(state.gdpr_data.privacy_policy_version, "1.0.0");
        assert_eq!(state.gdpr_data.compliance_score, 0.0);

        // Check HIPAA data initialization
        assert!(state.hipaa_data.phi_inventory.is_empty());
        assert!(state.hipaa_data.business_associate_agreements.is_empty());
        assert!(state.hipaa_data.security_incidents.is_empty());
        assert_eq!(state.hipaa_data.compliance_score, 0.0);
    }

    #[test]
    fn test_data_asset_creation() {
        let asset = DataAsset {
            id: "test-asset-1".to_string(),
            name: "Test User Database".to_string(),
            category: DataCategory::Personal,
            sensitivity: DataSensitivity::Confidential,
            location: "Primary Database".to_string(),
            owner: "Security Team".to_string(),
            retention_period: "7 years".to_string(),
            legal_basis: "Contract".to_string(),
            data_subjects: vec!["users".to_string()],
            created_at: Utc::now(),
            last_updated: Utc::now(),
        };

        assert_eq!(asset.name, "Test User Database");
        assert_eq!(asset.category, DataCategory::Personal);
        assert_eq!(asset.sensitivity, DataSensitivity::Confidential);
        assert_eq!(asset.owner, "Security Team");
    }

    #[test]
    fn test_consent_record_creation() {
        let consent = ConsentRecord {
            id: "consent-123".to_string(),
            subject_id: "user-456".to_string(),
            consent_type: ConsentType::Marketing,
            purpose: "Email marketing campaigns".to_string(),
            scope: vec!["email".to_string(), "sms".to_string()],
            granted_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            withdrawn_at: None,
            consent_mechanism: "Web interface".to_string(),
            ip_address: Some("192.168.1.100".to_string()),
        };

        assert_eq!(consent.consent_type, ConsentType::Marketing);
        assert!(consent.expires_at.is_some());
        assert!(consent.withdrawn_at.is_none());
        assert_eq!(consent.scope.len(), 2);
    }

    #[test]
    fn test_breach_incident_creation() {
        let breach = BreachIncident {
            id: "breach-001".to_string(),
            title: "Data Breach Incident".to_string(),
            description: "Unauthorized access to customer database".to_string(),
            affected_subjects: 1000,
            data_categories: vec!["personal".to_string(), "financial".to_string()],
            breach_date: Utc::now(),
            discovery_date: Utc::now(),
            reported_date: None,
            severity: BreachSeverity::High,
            status: BreachStatus::Investigating,
            mitigating_actions: vec!["Password reset".to_string()],
            regulatory_notifications: vec![],
        };

        assert_eq!(breach.affected_subjects, 1000);
        assert_eq!(breach.severity, BreachSeverity::High);
        assert_eq!(breach.status, BreachStatus::Investigating);
        assert!(breach.reported_date.is_none());
    }

    #[test]
    fn test_subject_rights_request() {
        let request = SubjectRightsRequest {
            id: "request-001".to_string(),
            subject_id: "user-123".to_string(),
            request_type: SubjectRightsType::Access,
            submitted_at: Utc::now(),
            status: RequestStatus::Received,
            response_deadline: Utc::now() + chrono::Duration::days(30),
            completed_at: None,
            response_details: None,
        };

        assert_eq!(request.request_type, SubjectRightsType::Access);
        assert_eq!(request.status, RequestStatus::Received);
        assert!(request.completed_at.is_none());
        assert!(request.response_details.is_none());
    }

    #[test]
    fn test_phi_data_asset() {
        let phi_asset = PhiDataAsset {
            id: "phi-001".to_string(),
            name: "Medical Records Database".to_string(),
            phi_type: PhiType::MedicalHistory,
            location: "Healthcare Database".to_string(),
            custodian: "Medical Team".to_string(),
            security_controls: vec!["encryption".to_string(), "access_control".to_string()],
            last_assessment: Utc::now(),
        };

        assert_eq!(phi_asset.phi_type, PhiType::MedicalHistory);
        assert_eq!(phi_asset.custodian, "Medical Team");
        assert_eq!(phi_asset.security_controls.len(), 2);
    }

    #[test]
    fn test_business_associate_agreement() {
        let baa = BaaRecord {
            id: "baa-001".to_string(),
            partner_name: "Cloud Provider Inc.".to_string(),
            agreement_date: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(365),
            phi_shared: vec!["medical_records".to_string()],
            status: BaaStatus::Active,
        };

        assert_eq!(baa.partner_name, "Cloud Provider Inc.");
        assert_eq!(baa.status, BaaStatus::Active);
        assert_eq!(baa.phi_shared.len(), 1);
    }

    #[test]
    fn test_security_incident() {
        let incident = SecurityIncident {
            id: "incident-001".to_string(),
            title: "PHI Access Violation".to_string(),
            description: "Unauthorized access to patient records".to_string(),
            incident_date: Utc::now(),
            affected_phi: vec!["medical_history".to_string()],
            severity: IncidentSeverity::High,
            status: IncidentStatus::Investigating,
            response_actions: vec!["Access revoked".to_string()],
        };

        assert_eq!(incident.severity, IncidentSeverity::High);
        assert_eq!(incident.status, IncidentStatus::Investigating);
        assert_eq!(incident.affected_phi.len(), 1);
    }

    #[test]
    fn test_risk_assessment() {
        let risk = RiskItem {
            id: "risk-001".to_string(),
            description: "Data breach risk".to_string(),
            likelihood: 0.3,
            impact: 0.8,
            risk_score: 0.24,
            status: RiskStatus::Identified,
        };

        let mitigation = MitigationPlan {
            id: "mitigation-001".to_string(),
            risk_id: "risk-001".to_string(),
            actions: vec!["Implement encryption".to_string()],
            responsible_party: "Security Team".to_string(),
            due_date: Utc::now() + chrono::Duration::days(30),
            status: MitigationStatus::Planned,
        };

        let assessment = RiskAssessment {
            last_assessment: Utc::now(),
            overall_risk_score: 0.4,
            identified_risks: vec![risk],
            mitigation_plans: vec![mitigation],
        };

        assert_eq!(assessment.overall_risk_score, 0.4);
        assert_eq!(assessment.identified_risks.len(), 1);
        assert_eq!(assessment.mitigation_plans.len(), 1);
    }

    #[test]
    fn test_compliance_scoring() {
        let mut state = ComplianceState::new();
        let module = ComplianceModule::default();

        // Test initial scoring (should be 0)
        module.calculate_compliance_scores(&mut state);
        assert_eq!(state.gdpr_data.compliance_score, 0.0);
        assert_eq!(state.hipaa_data.compliance_score, 0.0);

        // Add some data assets
        state.data_inventory.push(DataAsset {
            id: "test-1".to_string(),
            name: "Test Asset".to_string(),
            category: DataCategory::Personal,
            sensitivity: DataSensitivity::Internal,
            location: "Test".to_string(),
            owner: "Test".to_string(),
            retention_period: "1 year".to_string(),
            legal_basis: "Contract".to_string(),
            data_subjects: vec!["users".to_string()],
            created_at: Utc::now(),
            last_updated: Utc::now(),
        });

        // Recalculate scores
        module.calculate_compliance_scores(&mut state);

        // GDPR score should improve (data inventory contributes)
        assert!(state.gdpr_data.compliance_score > 0.0);
        // HIPAA score might still be 0 (needs PHI assets)
        assert_eq!(state.hipaa_data.compliance_score, 0.0);
    }

    #[test]
    fn test_audit_entry_creation() {
        let audit_entry = ComplianceAuditEntry {
            id: "audit-001".to_string(),
            timestamp: Utc::now(),
            action: "data_asset_created".to_string(),
            user: "admin".to_string(),
            resource: "data_asset".to_string(),
            details: serde_json::json!({
                "asset_id": "test-1",
                "asset_name": "Test Asset"
            }),
            compliance_framework: ComplianceFramework::Gdpr,
        };

        assert_eq!(audit_entry.action, "data_asset_created");
        assert_eq!(audit_entry.compliance_framework, ComplianceFramework::Gdpr);
        assert!(audit_entry.details.is_object());
    }

    #[test]
    fn test_data_processing_activity() {
        let activity = DataProcessingActivity {
            id: "dpa-001".to_string(),
            name: "User Authentication".to_string(),
            purpose: "User login and session management".to_string(),
            categories: vec!["personal".to_string(), "technical".to_string()],
            legal_basis: "Contract".to_string(),
            recipients: vec!["authentication_service".to_string()],
            retention: "Session duration + 30 days".to_string(),
            security_measures: vec!["encryption".to_string(), "access_control".to_string()],
            dpo_contact: Some("dpo@company.com".to_string()),
        };

        assert_eq!(activity.legal_basis, "Contract");
        assert_eq!(activity.categories.len(), 2);
        assert_eq!(activity.security_measures.len(), 2);
        assert!(activity.dpo_contact.is_some());
    }
}