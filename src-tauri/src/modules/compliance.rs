// Cyber Security Prime - Compliance Module
// Handles GDPR, HIPAA, and other regulatory compliance reporting

use crate::modules::{SecurityModule, ModuleHealth};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use uuid::Uuid;

// Global compliance state
static COMPLIANCE_STATE: Lazy<Mutex<ComplianceState>> = Lazy::new(|| Mutex::new(ComplianceState::new()));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceState {
    pub gdpr_data: GdprComplianceData,
    pub hipaa_data: HipaaComplianceData,
    pub data_inventory: Vec<DataAsset>,
    pub consent_records: Vec<ConsentRecord>,
    pub breach_incidents: Vec<BreachIncident>,
    pub audit_trail: Vec<ComplianceAuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdprComplianceData {
    pub data_processing_register: Vec<DataProcessingActivity>,
    pub subject_rights_requests: Vec<SubjectRightsRequest>,
    pub data_protection_officer: Option<DpoInfo>,
    pub privacy_policy_version: String,
    pub last_audit_date: Option<DateTime<Utc>>,
    pub compliance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipaaComplianceData {
    pub phi_inventory: Vec<PhiDataAsset>,
    pub business_associate_agreements: Vec<BaaRecord>,
    pub security_incidents: Vec<SecurityIncident>,
    pub risk_assessment: RiskAssessment,
    pub compliance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAsset {
    pub id: String,
    pub name: String,
    pub category: DataCategory,
    pub sensitivity: DataSensitivity,
    pub location: String,
    pub owner: String,
    pub retention_period: String,
    pub legal_basis: String,
    pub data_subjects: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DataCategory {
    Personal,
    Sensitive,
    Health,
    Financial,
    Contact,
    Behavioral,
    Technical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DataSensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub id: String,
    pub subject_id: String,
    pub consent_type: ConsentType,
    pub purpose: String,
    pub scope: Vec<String>,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub consent_mechanism: String,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConsentType {
    Marketing,
    Analytics,
    Processing,
    Profiling,
    ThirdPartySharing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachIncident {
    pub id: String,
    pub title: String,
    pub description: String,
    pub affected_subjects: u32,
    pub data_categories: Vec<String>,
    pub breach_date: DateTime<Utc>,
    pub discovery_date: DateTime<Utc>,
    pub reported_date: Option<DateTime<Utc>>,
    pub severity: BreachSeverity,
    pub status: BreachStatus,
    pub mitigating_actions: Vec<String>,
    pub regulatory_notifications: Vec<RegulatoryNotification>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BreachSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BreachStatus {
    Investigating,
    Contained,
    Resolved,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryNotification {
    pub authority: String,
    pub notification_date: DateTime<Utc>,
    pub reference_number: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProcessingActivity {
    pub id: String,
    pub name: String,
    pub purpose: String,
    pub categories: Vec<String>,
    pub legal_basis: String,
    pub recipients: Vec<String>,
    pub retention: String,
    pub security_measures: Vec<String>,
    pub dpo_contact: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectRightsRequest {
    pub id: String,
    pub subject_id: String,
    pub request_type: SubjectRightsType,
    pub submitted_at: DateTime<Utc>,
    pub status: RequestStatus,
    pub response_deadline: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub response_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SubjectRightsType {
    Access,
    Rectification,
    Erasure,
    Restriction,
    Portability,
    Objection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RequestStatus {
    Received,
    Processing,
    Completed,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpoInfo {
    pub name: String,
    pub email: String,
    pub phone: String,
    pub appointed_date: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhiDataAsset {
    pub id: String,
    pub name: String,
    pub phi_type: PhiType,
    pub location: String,
    pub custodian: String,
    pub security_controls: Vec<String>,
    pub last_assessment: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PhiType {
    Demographic,
    MedicalHistory,
    ClinicalData,
    PaymentInfo,
    Biometric,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaaRecord {
    pub id: String,
    pub partner_name: String,
    pub agreement_date: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub phi_shared: Vec<String>,
    pub status: BaaStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BaaStatus {
    Active,
    Expired,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncident {
    pub id: String,
    pub title: String,
    pub description: String,
    pub incident_date: DateTime<Utc>,
    pub affected_phi: Vec<String>,
    pub severity: IncidentSeverity,
    pub status: IncidentStatus,
    pub response_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentStatus {
    Reported,
    Investigating,
    Resolved,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub last_assessment: DateTime<Utc>,
    pub overall_risk_score: f32,
    pub identified_risks: Vec<RiskItem>,
    pub mitigation_plans: Vec<MitigationPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskItem {
    pub id: String,
    pub description: String,
    pub likelihood: f32,
    pub impact: f32,
    pub risk_score: f32,
    pub status: RiskStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationPlan {
    pub id: String,
    pub risk_id: String,
    pub actions: Vec<String>,
    pub responsible_party: String,
    pub due_date: DateTime<Utc>,
    pub status: MitigationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskStatus {
    Identified,
    Assessing,
    Mitigating,
    Mitigated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MitigationStatus {
    Planned,
    InProgress,
    Completed,
    Overdue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub user: String,
    pub resource: String,
    pub details: serde_json::Value,
    pub compliance_framework: ComplianceFramework,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceFramework {
    Gdpr,
    Hipaa,
    Pcidds,
    SoX,
    Other,
}

impl ComplianceState {
    fn new() -> Self {
        Self {
            gdpr_data: GdprComplianceData {
                data_processing_register: Vec::new(),
                subject_rights_requests: Vec::new(),
                data_protection_officer: None,
                privacy_policy_version: "1.0.0".to_string(),
                last_audit_date: None,
                compliance_score: 0.0,
            },
            hipaa_data: HipaaComplianceData {
                phi_inventory: Vec::new(),
                business_associate_agreements: Vec::new(),
                security_incidents: Vec::new(),
                risk_assessment: RiskAssessment {
                    last_assessment: Utc::now(),
                    overall_risk_score: 0.0,
                    identified_risks: Vec::new(),
                    mitigation_plans: Vec::new(),
                },
                compliance_score: 0.0,
            },
            data_inventory: Vec::new(),
            consent_records: Vec::new(),
            breach_incidents: Vec::new(),
            audit_trail: Vec::new(),
        }
    }
}

pub struct ComplianceModule {
    pub name: &'static str,
    pub description: &'static str,
    pub version: &'static str,
    pub active: bool,
}

impl Default for ComplianceModule {
    fn default() -> Self {
        Self {
            name: "Compliance Management",
            description: "GDPR, HIPAA, and regulatory compliance reporting",
            version: "1.0.0",
            active: true,
        }
    }
}

impl SecurityModule for ComplianceModule {
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
        // Initialize with sample compliance data
        let mut state = COMPLIANCE_STATE.lock();

        // Add sample data assets
        self.initialize_sample_data_inventory(&mut state);

        // Calculate initial compliance scores
        self.calculate_compliance_scores(&mut state);

        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn health_check(&self) -> ModuleHealth {
        let state = COMPLIANCE_STATE.lock();
        let gdpr_score = state.gdpr_data.compliance_score;
        let hipaa_score = state.hipaa_data.compliance_score;

        let healthy = gdpr_score > 70.0 && hipaa_score > 70.0;
        let message = if healthy {
            "Compliance module is operational with good compliance scores".to_string()
        } else {
            format!("Compliance scores need attention: GDPR: {:.1}%, HIPAA: {:.1}%", gdpr_score, hipaa_score)
        };

        ModuleHealth {
            healthy,
            message,
            last_check: Utc::now().to_rfc3339(),
        }
    }
}

impl ComplianceModule {
    fn initialize_sample_data_inventory(&self, state: &mut ComplianceState) {
        let sample_assets = vec![
            DataAsset {
                id: Uuid::new_v4().to_string(),
                name: "User Authentication Database".to_string(),
                category: DataCategory::Personal,
                sensitivity: DataSensitivity::Confidential,
                location: "Primary Database".to_string(),
                owner: "Security Team".to_string(),
                retention_period: "7 years".to_string(),
                legal_basis: "Contract".to_string(),
                data_subjects: vec!["users".to_string()],
                created_at: Utc::now(),
                last_updated: Utc::now(),
            },
            DataAsset {
                id: Uuid::new_v4().to_string(),
                name: "Security Logs".to_string(),
                category: DataCategory::Technical,
                sensitivity: DataSensitivity::Internal,
                location: "Log Storage".to_string(),
                owner: "IT Operations".to_string(),
                retention_period: "2 years".to_string(),
                legal_basis: "Legitimate Interest".to_string(),
                data_subjects: vec!["users".to_string(), "system".to_string()],
                created_at: Utc::now(),
                last_updated: Utc::now(),
            },
        ];

        state.data_inventory.extend(sample_assets);
    }

    fn calculate_compliance_scores(&self, state: &mut ComplianceState) {
        // Simple compliance scoring logic
        let gdpr_score = self.calculate_gdpr_score(&state);
        let hipaa_score = self.calculate_hipaa_score(&state);

        state.gdpr_data.compliance_score = gdpr_score;
        state.hipaa_data.compliance_score = hipaa_score;
    }

    fn calculate_gdpr_score(&self, state: &ComplianceState) -> f32 {
        let mut score = 0.0;
        let mut max_score = 0.0;

        // Data inventory completeness (25 points)
        max_score += 25.0;
        if !state.data_inventory.is_empty() {
            score += 25.0;
        }

        // Consent records (20 points)
        max_score += 20.0;
        if !state.consent_records.is_empty() {
            score += 20.0;
        }

        // Processing register (20 points)
        max_score += 20.0;
        if !state.gdpr_data.data_processing_register.is_empty() {
            score += 20.0;
        }

        // DPO appointment (15 points)
        max_score += 15.0;
        if state.gdpr_data.data_protection_officer.is_some() {
            score += 15.0;
        }

        // Breach handling (20 points)
        max_score += 20.0;
        if state.breach_incidents.iter().all(|b| b.reported_date.is_some()) {
            score += 20.0;
        }

        if max_score > 0.0 {
            (score / max_score) * 100.0
        } else {
            0.0
        }
    }

    fn calculate_hipaa_score(&self, state: &ComplianceState) -> f32 {
        let mut score = 0.0;
        let mut max_score = 0.0;

        // PHI inventory (30 points)
        max_score += 30.0;
        if !state.hipaa_data.phi_inventory.is_empty() {
            score += 30.0;
        }

        // Business associate agreements (25 points)
        max_score += 25.0;
        if !state.hipaa_data.business_associate_agreements.is_empty() {
            score += 25.0;
        }

        // Risk assessment (25 points)
        max_score += 25.0;
        if state.hipaa_data.risk_assessment.last_assessment > Utc::now() - chrono::Duration::days(365) {
            score += 25.0;
        }

        // Security incidents handling (20 points)
        max_score += 20.0;
        if state.hipaa_data.security_incidents.iter().all(|i| matches!(i.status, IncidentStatus::Resolved | IncidentStatus::Closed)) {
            score += 20.0;
        }

        if max_score > 0.0 {
            (score / max_score) * 100.0
        } else {
            0.0
        }
    }
}

// Tauri commands for compliance module
#[tauri::command]
pub fn get_gdpr_compliance_data() -> Result<GdprComplianceData, String> {
    let state = COMPLIANCE_STATE.lock();
    Ok(state.gdpr_data.clone())
}

#[tauri::command]
pub fn get_hipaa_compliance_data() -> Result<HipaaComplianceData, String> {
    let state = COMPLIANCE_STATE.lock();
    Ok(state.hipaa_data.clone())
}

#[tauri::command]
pub fn get_data_inventory() -> Result<Vec<DataAsset>, String> {
    let state = COMPLIANCE_STATE.lock();
    Ok(state.data_inventory.clone())
}

#[tauri::command]
pub fn add_data_asset(asset: DataAsset) -> Result<String, String> {
    let mut state = COMPLIANCE_STATE.lock();
    let asset_id = Uuid::new_v4().to_string();

    let new_asset = DataAsset {
        id: asset_id.clone(),
        ..asset
    };

    state.data_inventory.push(new_asset);
    Ok(asset_id)
}

#[tauri::command]
pub fn get_consent_records() -> Result<Vec<ConsentRecord>, String> {
    let state = COMPLIANCE_STATE.lock();
    Ok(state.consent_records.clone())
}

#[tauri::command]
pub fn record_consent(subject_id: String, consent_type: ConsentType, purpose: String, scope: Vec<String>, expires_at: Option<DateTime<Utc>>) -> Result<String, String> {
    let mut state = COMPLIANCE_STATE.lock();
    let consent_id = Uuid::new_v4().to_string();

    let consent = ConsentRecord {
        id: consent_id.clone(),
        subject_id,
        consent_type,
        purpose,
        scope,
        granted_at: Utc::now(),
        expires_at,
        withdrawn_at: None,
        consent_mechanism: "Web Interface".to_string(),
        ip_address: None,
    };

    state.consent_records.push(consent);
    Ok(consent_id)
}

#[tauri::command]
pub fn withdraw_consent(consent_id: String) -> Result<(), String> {
    let mut state = COMPLIANCE_STATE.lock();

    if let Some(consent) = state.consent_records.iter_mut().find(|c| c.id == consent_id) {
        consent.withdrawn_at = Some(Utc::now());
        Ok(())
    } else {
        Err(format!("Consent record {} not found", consent_id))
    }
}

#[tauri::command]
pub fn get_breach_incidents() -> Result<Vec<BreachIncident>, String> {
    let state = COMPLIANCE_STATE.lock();
    Ok(state.breach_incidents.clone())
}

#[tauri::command]
pub fn report_breach_incident(title: String, description: String, affected_subjects: u32, data_categories: Vec<String>, severity: BreachSeverity) -> Result<String, String> {
    let mut state = COMPLIANCE_STATE.lock();
    let breach_id = Uuid::new_v4().to_string();

    let breach = BreachIncident {
        id: breach_id.clone(),
        title,
        description,
        affected_subjects,
        data_categories,
        breach_date: Utc::now(),
        discovery_date: Utc::now(),
        reported_date: None,
        severity,
        status: BreachStatus::Investigating,
        mitigating_actions: Vec::new(),
        regulatory_notifications: Vec::new(),
    };

    state.breach_incidents.push(breach);

    // Recalculate compliance scores after breach
    let mut module = ComplianceModule::default();
    module.calculate_compliance_scores(&mut state);

    Ok(breach_id)
}

#[tauri::command]
pub fn update_breach_status(breach_id: String, status: BreachStatus, mitigating_actions: Vec<String>) -> Result<(), String> {
    let mut state = COMPLIANCE_STATE.lock();

    if let Some(breach) = state.breach_incidents.iter_mut().find(|b| b.id == breach_id) {
        let should_set_reported = matches!(status, BreachStatus::Resolved | BreachStatus::Closed) && breach.reported_date.is_none();
        breach.status = status;
        breach.mitigating_actions.extend(mitigating_actions);

        if should_set_reported {
            breach.reported_date = Some(Utc::now());
        }

        Ok(())
    } else {
        Err(format!("Breach incident {} not found", breach_id))
    }
}

#[tauri::command]
pub fn submit_subject_rights_request(subject_id: String, request_type: SubjectRightsType) -> Result<String, String> {
    let mut state = COMPLIANCE_STATE.lock();
    let request_id = Uuid::new_v4().to_string();

    let request = SubjectRightsRequest {
        id: request_id.clone(),
        subject_id,
        request_type,
        submitted_at: Utc::now(),
        status: RequestStatus::Received,
        response_deadline: Utc::now() + chrono::Duration::days(30),
        completed_at: None,
        response_details: None,
    };

    state.gdpr_data.subject_rights_requests.push(request);
    Ok(request_id)
}

#[tauri::command]
pub fn get_subject_rights_requests() -> Result<Vec<SubjectRightsRequest>, String> {
    let state = COMPLIANCE_STATE.lock();
    Ok(state.gdpr_data.subject_rights_requests.clone())
}

#[tauri::command]
pub fn generate_compliance_report(framework: ComplianceFramework) -> Result<serde_json::Value, String> {
    let state = COMPLIANCE_STATE.lock();

    let report = match framework {
        ComplianceFramework::Gdpr => {
            serde_json::json!({
                "framework": "GDPR",
                "generated_at": Utc::now().to_rfc3339(),
                "compliance_score": state.gdpr_data.compliance_score,
                "data_assets_count": state.data_inventory.len(),
                "processing_activities_count": state.gdpr_data.data_processing_register.len(),
                "consent_records_count": state.consent_records.len(),
                "subject_rights_requests_count": state.gdpr_data.subject_rights_requests.len(),
                "breach_incidents_count": state.breach_incidents.len(),
                "dpo_appointed": state.gdpr_data.data_protection_officer.is_some(),
                "last_audit": state.gdpr_data.last_audit_date.map(|d| d.to_rfc3339())
            })
        },
        ComplianceFramework::Hipaa => {
            serde_json::json!({
                "framework": "HIPAA",
                "generated_at": Utc::now().to_rfc3339(),
                "compliance_score": state.hipaa_data.compliance_score,
                "phi_assets_count": state.hipaa_data.phi_inventory.len(),
                "baa_count": state.hipaa_data.business_associate_agreements.len(),
                "security_incidents_count": state.hipaa_data.security_incidents.len(),
                "risk_assessment_date": state.hipaa_data.risk_assessment.last_assessment.to_rfc3339(),
                "overall_risk_score": state.hipaa_data.risk_assessment.overall_risk_score
            })
        },
        _ => return Err("Unsupported compliance framework".to_string()),
    };

    Ok(report)
}

#[tauri::command]
pub fn get_compliance_dashboard() -> Result<serde_json::Value, String> {
    let state = COMPLIANCE_STATE.lock();

    let dashboard = serde_json::json!({
        "gdpr_score": state.gdpr_data.compliance_score,
        "hipaa_score": state.hipaa_data.compliance_score,
        "total_data_assets": state.data_inventory.len(),
        "active_consents": state.consent_records.iter().filter(|c| c.withdrawn_at.is_none()).count(),
        "pending_subject_requests": state.gdpr_data.subject_rights_requests.iter().filter(|r| matches!(r.status, RequestStatus::Received | RequestStatus::Processing)).count(),
        "open_breaches": state.breach_incidents.iter().filter(|b| !matches!(b.status, BreachStatus::Resolved | BreachStatus::Closed)).count(),
        "phi_assets": state.hipaa_data.phi_inventory.len(),
        "active_baas": state.hipaa_data.business_associate_agreements.iter().filter(|b| matches!(b.status, BaaStatus::Active)).count()
    });

    Ok(dashboard)
}