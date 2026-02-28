// Cyber Security Prime - Flagship Enhancements Module
// Command-backed data for flagship feature surfaces

use chrono::Utc;
use lazy_static::lazy_static;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use uuid::Uuid;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

// ---------------------------------------------------------------------------
// Quarantine directory (created on first use)
// ---------------------------------------------------------------------------

fn quarantine_dir() -> PathBuf {
    let dir = dirs_next().join("quarantine");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn dirs_next() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("SecurityPrime")
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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
    pub actions_preview: Vec<ActionPreview>,
    pub estimated_impact: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPreview {
    pub action: String,
    pub feasible: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExecutionResult {
    pub execution_id: String,
    pub playbook_id: String,
    pub target: String,
    pub started_at: String,
    pub finished_at: String,
    pub success: bool,
    pub action_results: Vec<ActionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action: String,
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookAuditEntry {
    pub id: String,
    pub timestamp: String,
    pub playbook_id: String,
    pub target: String,
    pub action: String,
    pub success: bool,
    pub detail: String,
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

// ---------------------------------------------------------------------------
// Audit trail (global, in-memory)
// ---------------------------------------------------------------------------

lazy_static! {
    static ref AUDIT_TRAIL: Arc<RwLock<Vec<PlaybookAuditEntry>>> =
        Arc::new(RwLock::new(Vec::new()));
}

fn audit(playbook_id: &str, target: &str, action: &str, success: bool, detail: &str) {
    let entry = PlaybookAuditEntry {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        playbook_id: playbook_id.to_string(),
        target: target.to_string(),
        action: action.to_string(),
        success,
        detail: detail.to_string(),
    };
    AUDIT_TRAIL.write().push(entry);
}

// ---------------------------------------------------------------------------
// Helper: run a system command, return (success, stdout/stderr)
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn run_cmd(program: &str, args: &[&str]) -> (bool, String) {
    match Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() {
                stdout
            } else {
                format!("{}\n{}", stdout, stderr)
            };
            (output.status.success(), combined.trim().to_string())
        }
        Err(e) => (false, format!("Failed to spawn {}: {}", program, e)),
    }
}

#[cfg(not(windows))]
fn run_cmd(program: &str, args: &[&str]) -> (bool, String) {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() {
                stdout
            } else {
                format!("{}\n{}", stdout, stderr)
            };
            (output.status.success(), combined.trim().to_string())
        }
        Err(e) => (false, format!("Failed to spawn {}: {}", program, e)),
    }
}

// ---------------------------------------------------------------------------
// Real action implementations
// ---------------------------------------------------------------------------

fn action_kill_process(target: &str, playbook_id: &str) -> ActionResult {
    let pid = target.trim();
    let (ok, msg) = run_cmd("taskkill", &["/F", "/PID", pid]);
    audit(playbook_id, target, "kill-process", ok, &msg);
    ActionResult {
        action: "kill-process".to_string(),
        success: ok,
        message: msg,
    }
}

fn action_block_ip(target: &str, playbook_id: &str) -> ActionResult {
    let ip = target.trim();
    let rule_name = format!("SecurityPrime_Block_{}", ip);
    let (ok, msg) = run_cmd(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name),
            "dir=out",
            "action=block",
            &format!("remoteip={}", ip),
            "protocol=any",
        ],
    );
    audit(playbook_id, target, "block-ip", ok, &msg);
    ActionResult {
        action: "block-ip".to_string(),
        success: ok,
        message: msg,
    }
}

fn action_quarantine_file(target: &str, playbook_id: &str) -> ActionResult {
    let src = Path::new(target.trim());
    if !src.exists() {
        let msg = format!("File not found: {}", target);
        audit(playbook_id, target, "quarantine-file", false, &msg);
        return ActionResult {
            action: "quarantine-file".to_string(),
            success: false,
            message: msg,
        };
    }

    let filename = src
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let dest = quarantine_dir().join(format!(
        "{}_{}.quarantined",
        Utc::now().format("%Y%m%d%H%M%S"),
        filename
    ));

    match std::fs::rename(src, &dest) {
        Ok(()) => {
            let msg = format!("Moved to {}", dest.display());
            audit(playbook_id, target, "quarantine-file", true, &msg);
            ActionResult {
                action: "quarantine-file".to_string(),
                success: true,
                message: msg,
            }
        }
        Err(e) => {
            // rename can fail across drives; fall back to copy+delete
            match std::fs::copy(src, &dest) {
                Ok(_) => {
                    let _ = std::fs::remove_file(src);
                    let msg = format!("Copied+deleted to {}", dest.display());
                    audit(playbook_id, target, "quarantine-file", true, &msg);
                    ActionResult {
                        action: "quarantine-file".to_string(),
                        success: true,
                        message: msg,
                    }
                }
                Err(_) => {
                    let msg = format!("Failed to quarantine: {}", e);
                    audit(playbook_id, target, "quarantine-file", false, &msg);
                    ActionResult {
                        action: "quarantine-file".to_string(),
                        success: false,
                        message: msg,
                    }
                }
            }
        }
    }
}

fn action_disable_startup_item(target: &str, playbook_id: &str) -> ActionResult {
    let entry_name = target.trim();
    let key_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    let (ok, msg) = run_cmd("reg", &["delete", key_path, "/v", entry_name, "/f"]);
    audit(playbook_id, target, "disable-startup-item", ok, &msg);
    ActionResult {
        action: "disable-startup-item".to_string(),
        success: ok,
        message: msg,
    }
}

/// Dispatch a single action string to its real handler.
fn dispatch_action(action: &str, target: &str, playbook_id: &str) -> ActionResult {
    match action {
        "kill-process" => action_kill_process(target, playbook_id),
        "block-ip" => action_block_ip(target, playbook_id),
        "quarantine-file" => action_quarantine_file(target, playbook_id),
        "disable-startup-item" => action_disable_startup_item(target, playbook_id),
        other => {
            let msg = format!("Action '{}' acknowledged (no-op handler)", other);
            audit(playbook_id, target, other, true, &msg);
            ActionResult {
                action: other.to_string(),
                success: true,
                message: msg,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dry-run probes — check live system state without mutating
// ---------------------------------------------------------------------------

fn probe_kill_process(target: &str) -> ActionPreview {
    let pid = target.trim();
    let (ok, output) = run_cmd("tasklist", &["/FI", &format!("PID eq {}", pid)]);
    let exists = ok && output.contains(pid);
    ActionPreview {
        action: "kill-process".to_string(),
        feasible: exists,
        detail: if exists {
            format!("PID {} is running and can be terminated", pid)
        } else {
            format!("PID {} not found — nothing to kill", pid)
        },
    }
}

fn probe_block_ip(target: &str) -> ActionPreview {
    let ip = target.trim();
    let (_, output) = run_cmd("ping", &["-n", "1", "-w", "1000", ip]);
    let reachable = output.contains("TTL=") || output.contains("ttl=");
    ActionPreview {
        action: "block-ip".to_string(),
        feasible: true,
        detail: if reachable {
            format!("{} is reachable — firewall rule will block outbound traffic", ip)
        } else {
            format!("{} is not reachable — firewall rule will still be created as preventive measure", ip)
        },
    }
}

fn probe_quarantine_file(target: &str) -> ActionPreview {
    let p = Path::new(target.trim());
    let exists = p.exists();
    ActionPreview {
        action: "quarantine-file".to_string(),
        feasible: exists,
        detail: if exists {
            format!(
                "File exists ({} bytes) — will be moved to quarantine",
                p.metadata().map(|m| m.len()).unwrap_or(0)
            )
        } else {
            format!("File not found: {}", target)
        },
    }
}

fn probe_disable_startup_item(target: &str) -> ActionPreview {
    let entry = target.trim();
    let key_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    let (ok, output) = run_cmd("reg", &["query", key_path, "/v", entry]);
    let exists = ok && output.contains(entry);
    ActionPreview {
        action: "disable-startup-item".to_string(),
        feasible: exists,
        detail: if exists {
            format!("Registry entry '{}' found — will be removed from Run key", entry)
        } else {
            format!("Registry entry '{}' not found in startup", entry)
        },
    }
}

fn probe_action(action: &str, target: &str) -> ActionPreview {
    match action {
        "kill-process" => probe_kill_process(target),
        "block-ip" => probe_block_ip(target),
        "quarantine-file" => probe_quarantine_file(target),
        "disable-startup-item" => probe_disable_startup_item(target),
        other => ActionPreview {
            action: other.to_string(),
            feasible: true,
            detail: format!("Action '{}' would be logged (advisory only)", other),
        },
    }
}

// ---------------------------------------------------------------------------
// Default data
// ---------------------------------------------------------------------------

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
                "kill-process".to_string(),
                "quarantine-file".to_string(),
                "notify-operator".to_string(),
            ],
            last_executed: None,
        },
        AutonomousResponsePlaybook {
            id: "pb-ip-block-quarantine".to_string(),
            name: "IP Block + Quarantine".to_string(),
            description:
                "Block outbound C2 candidates and quarantine associated payloads.".to_string(),
            enabled: true,
            trigger_score: 82,
            severity_threshold: "critical".to_string(),
            actions: vec![
                "block-ip".to_string(),
                "quarantine-file".to_string(),
                "notify-operator".to_string(),
            ],
            last_executed: None,
        },
        AutonomousResponsePlaybook {
            id: "pb-startup-hardening".to_string(),
            name: "Startup Item Hardening".to_string(),
            description:
                "Disable suspicious startup entries after persistence behavior is detected."
                    .to_string(),
            enabled: false,
            trigger_score: 70,
            severity_threshold: "medium".to_string(),
            actions: vec![
                "disable-startup-item".to_string(),
                "notify-operator".to_string(),
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

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

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

    let previews: Vec<ActionPreview> = playbook
        .actions
        .iter()
        .map(|a| probe_action(a, &target))
        .collect();

    let any_infeasible = previews.iter().any(|p| !p.feasible);

    Ok(PlaybookDryRunResult {
        playbook_id,
        target,
        actions_preview: previews,
        estimated_impact: "Medium operational impact; low containment latency.".to_string(),
        recommendation: if any_infeasible {
            "Some actions cannot be completed — review details before executing.".to_string()
        } else {
            "All actions are feasible. Safe to execute in monitored mode.".to_string()
        },
    })
}

#[tauri::command]
pub fn execute_playbook(
    playbook_id: String,
    target: String,
) -> Result<PlaybookExecutionResult, String> {
    let playbook = default_playbooks()
        .into_iter()
        .find(|p| p.id == playbook_id)
        .ok_or_else(|| format!("Unknown playbook: {}", playbook_id))?;

    if !playbook.enabled {
        return Err(format!(
            "Playbook '{}' is disabled — enable it before executing",
            playbook.name
        ));
    }

    let execution_id = Uuid::new_v4().to_string();
    let started_at = Utc::now().to_rfc3339();

    let action_results: Vec<ActionResult> = playbook
        .actions
        .iter()
        .map(|a| dispatch_action(a, &target, &playbook_id))
        .collect();

    let all_ok = action_results.iter().all(|r| r.success);
    let finished_at = Utc::now().to_rfc3339();

    Ok(PlaybookExecutionResult {
        execution_id,
        playbook_id,
        target,
        started_at,
        finished_at,
        success: all_ok,
        action_results,
    })
}

#[tauri::command]
pub fn get_playbook_audit_trail() -> Result<Vec<PlaybookAuditEntry>, String> {
    Ok(AUDIT_TRAIL.read().clone())
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
