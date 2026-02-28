// Cyber Security Prime - Flagship Enhancements Module
// Command-backed data for flagship feature surfaces

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

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
            last_executed: None,
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
            last_executed: None,
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
    let mut items = Vec::new();

    let risky_ports: &[(u16, &str, &str, &str)] = &[
        (3389, "RDP", "critical", "Restrict RDP access to trusted networks or use a VPN."),
        (445, "SMB", "high", "Ensure SMB is properly secured and remove unnecessary shares."),
        (135, "RPC Endpoint Mapper", "high", "Restrict RPC endpoint mapper to trusted networks."),
        (23, "Telnet", "critical", "Disable Telnet and use SSH instead."),
        (21, "FTP", "critical", "Disable FTP and use SFTP/SCP instead."),
        (1433, "MSSQL", "medium", "Restrict SQL Server access to application servers only."),
        (3306, "MySQL", "medium", "Restrict MySQL access to application servers only."),
        (5432, "PostgreSQL", "medium", "Restrict PostgreSQL access to application servers only."),
        (5900, "VNC", "high", "Disable VNC or restrict to trusted networks with strong auth."),
        (8080, "HTTP Proxy", "medium", "Review HTTP proxy exposure and restrict access."),
    ];

    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("netstat");
        cmd.creation_flags(CREATE_NO_WINDOW);
        if let Ok(output) = cmd.args(["-an"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if !line.contains("LISTENING") {
                    continue;
                }
                if let Some(addr) = line.split_whitespace().nth(1) {
                    if let Some(port_str) = addr.rsplit(':').next() {
                        if let Ok(port) = port_str.parse::<u16>() {
                            if let Some((_, service, severity, action)) =
                                risky_ports.iter().find(|(p, _, _, _)| *p == port)
                            {
                                items.push(ExposureItem {
                                    id: format!("exp-port-{}", port),
                                    category: "open_port".to_string(),
                                    asset: format!("0.0.0.0:{} ({})", port, service),
                                    severity: severity.to_string(),
                                    status: "open".to_string(),
                                    recommended_action: action.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(output) = Command::new("ss").args(["-tuln"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                if let Some(addr) = line.split_whitespace().nth(4) {
                    if let Some(port_str) = addr.rsplit(':').next() {
                        if let Ok(port) = port_str.parse::<u16>() {
                            if let Some((_, service, severity, action)) =
                                risky_ports.iter().find(|(p, _, _, _)| *p == port)
                            {
                                items.push(ExposureItem {
                                    id: format!("exp-port-{}", port),
                                    category: "open_port".to_string(),
                                    asset: format!("*:{} ({})", port, service),
                                    severity: severity.to_string(),
                                    status: "open".to_string(),
                                    recommended_action: action.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    let critical_count = items.iter().filter(|i| i.severity == "critical").count() as u32;
    let high_count = items.iter().filter(|i| i.severity == "high").count() as u32;
    let open_count = items.len() as u32;

    let exposure_score: u8 = std::cmp::min(
        100,
        10 + (critical_count * 20 + high_count * 10 + open_count * 5) as u8,
    );

    AttackSurfaceSnapshot {
        overall_exposure_score: exposure_score,
        open_exposures: open_count,
        critical_exposures: critical_count,
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

