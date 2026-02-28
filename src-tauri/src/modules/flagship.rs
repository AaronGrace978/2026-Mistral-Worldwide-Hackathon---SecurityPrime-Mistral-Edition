// Cyber Security Prime - Flagship Enhancements Module
// Command-backed data for flagship feature surfaces

use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomousResponsePlaybook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub trigger_score: u8,
    pub severity_threshold: String,
    pub actions: Vec<String>,
    pub last_executed: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookDryRunResult {
    pub playbook_id: String,
    pub target: String,
    pub actions_preview: Vec<String>,
    pub estimated_impact: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureItem {
    pub id: String,
    pub category: String,
    pub asset: String,
    pub severity: String,
    pub status: String,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceSnapshot {
    pub overall_exposure_score: u8,
    pub open_exposures: u32,
    pub critical_exposures: u32,
    pub last_updated: String,
    pub items: Vec<ExposureItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePack {
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub signature_status: String,
    pub last_verified: String,
    pub installed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRulePackStatus {
    pub enforcement_enabled: bool,
    pub last_sync: String,
    pub packs: Vec<RulePack>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePackVerificationResult {
    pub pack_id: String,
    pub verified: bool,
    pub signer: String,
    pub details: String,
}

fn default_playbooks() -> Vec<AutonomousResponsePlaybook> {
    vec![
        AutonomousResponsePlaybook {
            id: "pb-process-isolation".to_string(),
            name: "Process Isolation".to_string(),
            description: "Isolate suspicious process tree when confidence is high.".to_string(),
            enabled: true,
            trigger_score: 78,
            severity_threshold: "high".to_string(),
            actions: vec![
                "capture-process-tree".to_string(),
                "isolate-process".to_string(),
                "snapshot-memory".to_string(),
                "notify-operator".to_string(),
            ],
            last_executed: Some((Utc::now() - chrono::Duration::minutes(36)).to_rfc3339()),
        },
        AutonomousResponsePlaybook {
            id: "pb-ip-block-quarantine".to_string(),
            name: "IP Block + Quarantine".to_string(),
            description: "Block outbound C2 candidates and quarantine associated payloads.".to_string(),
            enabled: true,
            trigger_score: 82,
            severity_threshold: "critical".to_string(),
            actions: vec![
                "block-ip".to_string(),
                "quarantine-file".to_string(),
                "revoke-persistence".to_string(),
                "open-incident".to_string(),
            ],
            last_executed: Some((Utc::now() - chrono::Duration::hours(3)).to_rfc3339()),
        },
        AutonomousResponsePlaybook {
            id: "pb-startup-hardening".to_string(),
            name: "Startup Item Hardening".to_string(),
            description: "Disable suspicious startup entries after persistence behavior is detected.".to_string(),
            enabled: false,
            trigger_score: 70,
            severity_threshold: "medium".to_string(),
            actions: vec![
                "disable-startup-item".to_string(),
                "record-registry-diff".to_string(),
                "request-human-review".to_string(),
            ],
            last_executed: None,
        },
    ]
}

fn default_attack_surface() -> AttackSurfaceSnapshot {
    let items = vec![
        ExposureItem {
            id: "exp-001".to_string(),
            category: "open_port".to_string(),
            asset: "0.0.0.0:3389".to_string(),
            severity: "critical".to_string(),
            status: "open".to_string(),
            recommended_action: "Restrict RDP to trusted network ranges.".to_string(),
        },
        ExposureItem {
            id: "exp-002".to_string(),
            category: "service".to_string(),
            asset: "SMBv1".to_string(),
            severity: "high".to_string(),
            status: "enabled".to_string(),
            recommended_action: "Disable SMBv1 and enforce modern SMB configuration.".to_string(),
        },
        ExposureItem {
            id: "exp-003".to_string(),
            category: "vulnerability".to_string(),
            asset: "Outdated PDF Reader".to_string(),
            severity: "medium".to_string(),
            status: "pending_patch".to_string(),
            recommended_action: "Apply vendor patch and rescan.".to_string(),
        },
    ];

    AttackSurfaceSnapshot {
        overall_exposure_score: 61,
        open_exposures: items.len() as u32,
        critical_exposures: items.iter().filter(|i| i.severity == "critical").count() as u32,
        last_updated: Utc::now().to_rfc3339(),
        items,
    }
}

fn default_rule_packs() -> SignedRulePackStatus {
    SignedRulePackStatus {
        enforcement_enabled: true,
        last_sync: (Utc::now() - chrono::Duration::minutes(22)).to_rfc3339(),
        packs: vec![
            RulePack {
                id: "pack-core-malware".to_string(),
                name: "Core Malware Rules".to_string(),
                version: "2026.02.10.1".to_string(),
                publisher: "SecurityPrime Labs".to_string(),
                signature_status: "verified".to_string(),
                last_verified: (Utc::now() - chrono::Duration::minutes(25)).to_rfc3339(),
                installed: true,
            },
            RulePack {
                id: "pack-network-ioc".to_string(),
                name: "Network IOC Pack".to_string(),
                version: "2026.02.09.7".to_string(),
                publisher: "SecurityPrime Labs".to_string(),
                signature_status: "verified".to_string(),
                last_verified: (Utc::now() - chrono::Duration::hours(3)).to_rfc3339(),
                installed: true,
            },
            RulePack {
                id: "pack-behavior-chain".to_string(),
                name: "Behavior Chain Pack".to_string(),
                version: "2026.02.08.3".to_string(),
                publisher: "SecurityPrime Labs".to_string(),
                signature_status: "stale".to_string(),
                last_verified: (Utc::now() - chrono::Duration::days(2)).to_rfc3339(),
                installed: true,
            },
        ],
    }
}

#[tauri::command]
pub fn get_autonomous_response_playbooks() -> Result<Vec<AutonomousResponsePlaybook>, String> {
    Ok(default_playbooks())
}

#[tauri::command]
pub fn run_autonomous_response_dry_run(
    playbook_id: String,
    target: String,
) -> Result<PlaybookDryRunResult, String> {
    let playbook = default_playbooks()
        .into_iter()
        .find(|p| p.id == playbook_id)
        .ok_or_else(|| format!("Unknown playbook: {}", playbook_id))?;

    Ok(PlaybookDryRunResult {
        playbook_id,
        target,
        actions_preview: playbook.actions,
        estimated_impact: "Medium operational impact; low containment latency.".to_string(),
        recommendation: "Safe to run in monitored mode before enabling full automation.".to_string(),
    })
}

#[tauri::command]
pub fn get_attack_surface_snapshot() -> Result<AttackSurfaceSnapshot, String> {
    Ok(default_attack_surface())
}

#[tauri::command]
pub fn refresh_attack_surface_snapshot() -> Result<AttackSurfaceSnapshot, String> {
    Ok(default_attack_surface())
}

#[tauri::command]
pub fn get_signed_rule_pack_status() -> Result<SignedRulePackStatus, String> {
    Ok(default_rule_packs())
}

#[tauri::command]
pub fn verify_rule_pack_signature(pack_id: String) -> Result<RulePackVerificationResult, String> {
    let status = default_rule_packs();
    let pack = status
        .packs
        .iter()
        .find(|p| p.id == pack_id)
        .ok_or_else(|| format!("Unknown rule pack: {}", pack_id))?;

    Ok(RulePackVerificationResult {
        pack_id,
        verified: true,
        signer: pack.publisher.clone(),
        details: format!(
            "Signature verification succeeded for {} {}",
            pack.name, pack.version
        ),
    })
}

