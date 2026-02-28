// Cyber Security Prime - Zero-Trust Application Control Module
// Real application hash verification, digital signature checking,
// parent process chain analysis, and policy-based enforcement for Windows.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use chrono::Utc;
use std::fs;
use std::io::Read as IoRead;
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppHashEntry {
    pub hash: String,
    pub path: String,
    pub signer: Option<String>,
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub path: String,
    pub is_signed: bool,
    pub signer: String,
    pub status: String,
    pub thumbprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessChainEntry {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub parent_pid: u32,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessChain {
    pub target_pid: u32,
    pub chain: Vec<ProcessChainEntry>,
    pub suspicious: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppControlPolicy {
    pub allowlist_hashes: Vec<String>,
    pub allowlist_signers: Vec<String>,
    pub allowlist_paths: Vec<String>,
    pub denylist_hashes: Vec<String>,
    pub enforcement_mode: String,
}

impl Default for AppControlPolicy {
    fn default() -> Self {
        Self {
            allowlist_hashes: Vec::new(),
            allowlist_signers: vec![
                "Microsoft Corporation".to_string(),
                "Microsoft Windows".to_string(),
            ],
            allowlist_paths: vec![
                r"C:\Windows\".to_string(),
                r"C:\Program Files\".to_string(),
                r"C:\Program Files (x86)\".to_string(),
            ],
            denylist_hashes: Vec::new(),
            enforcement_mode: "audit".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppControlStatus {
    pub total_processes: u32,
    pub verified: u32,
    pub unknown: u32,
    pub blocked: u32,
    pub unsigned: u32,
    pub policy: AppControlPolicy,
    pub last_scan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppVerificationResult {
    pub path: String,
    pub hash: String,
    pub signature: SignatureInfo,
    pub policy_decision: String,
    pub process_chain: Option<ProcessChain>,
}

// ============================================================================
// In-Memory State
// ============================================================================

lazy_static::lazy_static! {
    static ref HASH_DB: Arc<RwLock<HashMap<String, AppHashEntry>>> =
        Arc::new(RwLock::new(HashMap::new()));

    static ref POLICY: Arc<RwLock<AppControlPolicy>> =
        Arc::new(RwLock::new(AppControlPolicy::default()));
}

// ============================================================================
// Core Logic
// ============================================================================

fn compute_sha256(path: &str) -> Result<String, String> {
    let mut file = fs::File::open(path)
        .map_err(|e| format!("Cannot open file '{}': {}", path, e))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|e| format!("Read error: {}", e))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn query_authenticode_signature(path: &str) -> SignatureInfo {
    let script = format!(
        "$sig = Get-AuthenticodeSignature -FilePath '{}'; \
         $sig | Select-Object -Property Status, \
         @{{Name='Signer';Expression={{$_.SignerCertificate.Subject}}}}, \
         @{{Name='Thumbprint';Expression={{$_.SignerCertificate.Thumbprint}}}} \
         | ConvertTo-Json -Compress",
        path.replace('\'', "''")
    );

    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = match cmd.output() {
        Ok(o) => o,
        Err(_) => {
            return SignatureInfo {
                path: path.to_string(),
                is_signed: false,
                signer: String::new(),
                status: "Error".to_string(),
                thumbprint: String::new(),
            };
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_signature_json(&stdout, path)
}

fn parse_signature_json(json_str: &str, path: &str) -> SignatureInfo {
    let trimmed = json_str.trim();
    if trimmed.is_empty() {
        return SignatureInfo {
            path: path.to_string(),
            is_signed: false,
            signer: String::new(),
            status: "Unknown".to_string(),
            thumbprint: String::new(),
        };
    }

    #[derive(Deserialize)]
    struct PsSignature {
        #[serde(alias = "Status")]
        status: Option<serde_json::Value>,
        #[serde(alias = "Signer")]
        signer: Option<String>,
        #[serde(alias = "Thumbprint")]
        thumbprint: Option<String>,
    }

    match serde_json::from_str::<PsSignature>(trimmed) {
        Ok(ps) => {
            let status_str = match &ps.status {
                Some(serde_json::Value::Number(n)) => {
                    match n.as_u64().unwrap_or(99) {
                        0 => "Valid".to_string(),
                        1 => "UnknownError".to_string(),
                        2 => "NotSigned".to_string(),
                        3 => "HashMismatch".to_string(),
                        4 => "NotTrusted".to_string(),
                        5 => "NotSupportedFileFormat".to_string(),
                        _ => format!("Code({})", n),
                    }
                }
                Some(serde_json::Value::String(s)) => s.clone(),
                _ => "Unknown".to_string(),
            };

            let is_signed = status_str == "Valid";
            let signer_raw = ps.signer.unwrap_or_default();
            let signer = extract_cn(&signer_raw);

            SignatureInfo {
                path: path.to_string(),
                is_signed,
                signer,
                status: status_str,
                thumbprint: ps.thumbprint.unwrap_or_default(),
            }
        }
        Err(_) => SignatureInfo {
            path: path.to_string(),
            is_signed: false,
            signer: String::new(),
            status: "ParseError".to_string(),
            thumbprint: String::new(),
        },
    }
}

/// Extract the CN= value from a distinguished name string.
fn extract_cn(subject: &str) -> String {
    for part in subject.split(',') {
        let part = part.trim();
        if let Some(cn) = part.strip_prefix("CN=") {
            return cn.trim_matches('"').to_string();
        }
    }
    subject.to_string()
}

fn query_process_info(pid: u32) -> Option<(String, String, u32)> {
    let mut cmd = Command::new("wmic");
    cmd.args([
        "process",
        "where",
        &format!("ProcessId={}", pid),
        "get",
        "Name,ExecutablePath,ParentProcessId",
        "/format:csv",
    ]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = cmd.output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Node") {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        // CSV format: Node, ExecutablePath, Name, ParentProcessId
        if fields.len() >= 4 {
            let exe_path = fields[1].trim().to_string();
            let name = fields[2].trim().to_string();
            let ppid: u32 = fields[3].trim().parse().unwrap_or(0);
            return Some((name, exe_path, ppid));
        }
    }
    None
}

const SUSPICIOUS_PARENT_CHAINS: &[(&str, &str)] = &[
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("mshta.exe", "cmd.exe"),
    ("wscript.exe", "cmd.exe"),
    ("cscript.exe", "cmd.exe"),
    ("rundll32.exe", "cmd.exe"),
    ("regsvr32.exe", "cmd.exe"),
];

fn detect_suspicious_chain(chain: &[ProcessChainEntry]) -> (bool, String) {
    if chain.len() < 2 {
        return (false, String::new());
    }

    for window in chain.windows(2) {
        let child_name = window[0].name.to_lowercase();
        let parent_name = window[1].name.to_lowercase();

        for &(suspicious_parent, suspicious_child) in SUSPICIOUS_PARENT_CHAINS {
            if parent_name == suspicious_parent && child_name == suspicious_child {
                return (
                    true,
                    format!(
                        "{} spawned by {} (potential living-off-the-land attack)",
                        child_name, parent_name
                    ),
                );
            }
        }
    }

    // Flag deep nesting (>5 levels) as potentially suspicious
    if chain.len() > 5 {
        return (
            true,
            format!(
                "Deep process chain ({} levels) may indicate process injection",
                chain.len()
            ),
        );
    }

    (false, String::new())
}

fn build_process_chain(pid: u32) -> ProcessChain {
    let mut chain = Vec::new();
    let mut current_pid = pid;
    let mut depth = 0u32;
    let mut visited = std::collections::HashSet::new();

    while depth < 10 {
        if visited.contains(&current_pid) || current_pid == 0 {
            break;
        }
        visited.insert(current_pid);

        match query_process_info(current_pid) {
            Some((name, path, ppid)) => {
                chain.push(ProcessChainEntry {
                    pid: current_pid,
                    name,
                    path,
                    parent_pid: ppid,
                    depth,
                });
                current_pid = ppid;
                depth += 1;
            }
            None => break,
        }
    }

    let (suspicious, reason) = detect_suspicious_chain(&chain);
    ProcessChain {
        target_pid: pid,
        chain,
        suspicious,
        reason,
    }
}

fn evaluate_against_policy(
    hash: &str,
    sig: &SignatureInfo,
    path: &str,
    policy: &AppControlPolicy,
) -> String {
    if policy.denylist_hashes.contains(&hash.to_string()) {
        return "blocked".to_string();
    }

    if policy.allowlist_hashes.contains(&hash.to_string()) {
        return "allowed".to_string();
    }

    if sig.is_signed
        && policy
            .allowlist_signers
            .iter()
            .any(|s| sig.signer.contains(s))
    {
        return "allowed".to_string();
    }

    let normalized = path.replace('/', r"\");
    if policy
        .allowlist_paths
        .iter()
        .any(|p| normalized.to_lowercase().starts_with(&p.to_lowercase()))
    {
        return "allowed".to_string();
    }

    "unknown".to_string()
}

fn list_running_processes() -> Vec<(u32, String, String)> {
    let mut cmd = Command::new("wmic");
    cmd.args([
        "process",
        "get",
        "ProcessId,Name,ExecutablePath",
        "/format:csv",
    ]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = match cmd.output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut processes = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Node") {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        // CSV: Node, ExecutablePath, Name, ProcessId
        if fields.len() >= 4 {
            let exe_path = fields[1].trim().to_string();
            let name = fields[2].trim().to_string();
            let pid: u32 = fields[3].trim().parse().unwrap_or(0);
            if pid > 0 {
                processes.push((pid, name, exe_path));
            }
        }
    }
    processes
}

// ============================================================================
// Tauri Commands
// ============================================================================

#[tauri::command]
pub fn verify_application(path: String) -> Result<AppVerificationResult, String> {
    let hash = compute_sha256(&path)?;
    let signature = query_authenticode_signature(&path);

    let policy = POLICY.read().clone();
    let policy_decision = evaluate_against_policy(&hash, &signature, &path, &policy);

    let now = Utc::now().to_rfc3339();
    {
        let mut db = HASH_DB.write();
        let entry = db.entry(hash.clone()).or_insert_with(|| AppHashEntry {
            hash: hash.clone(),
            path: path.clone(),
            signer: if signature.is_signed {
                Some(signature.signer.clone())
            } else {
                None
            },
            status: policy_decision.clone(),
            first_seen: now.clone(),
            last_seen: now.clone(),
        });
        entry.last_seen = now;
        entry.status = policy_decision.clone();
    }

    Ok(AppVerificationResult {
        path,
        hash,
        signature,
        policy_decision,
        process_chain: None,
    })
}

#[tauri::command]
pub fn check_app_signature(path: String) -> Result<SignatureInfo, String> {
    if !std::path::Path::new(&path).exists() {
        return Err(format!("File not found: {}", path));
    }
    Ok(query_authenticode_signature(&path))
}

#[tauri::command]
pub fn get_process_chain(pid: u32) -> Result<ProcessChain, String> {
    if pid == 0 {
        return Err("Invalid PID".to_string());
    }
    Ok(build_process_chain(pid))
}

#[tauri::command]
pub fn get_app_control_status() -> Result<AppControlStatus, String> {
    let processes = list_running_processes();
    let total = processes.len() as u32;

    let policy = POLICY.read().clone();
    let db = HASH_DB.read();

    let mut verified = 0u32;
    let mut unknown = 0u32;
    let mut blocked = 0u32;
    let mut unsigned = 0u32;

    for (_pid, _name, exe_path) in &processes {
        if exe_path.is_empty() {
            unknown += 1;
            continue;
        }

        match compute_sha256(exe_path) {
            Ok(hash) => {
                if let Some(entry) = db.get(&hash) {
                    match entry.status.as_str() {
                        "allowed" => verified += 1,
                        "blocked" => blocked += 1,
                        _ => unknown += 1,
                    }
                    if entry.signer.is_none() {
                        unsigned += 1;
                    }
                } else {
                    let sig = query_authenticode_signature(exe_path);
                    let decision =
                        evaluate_against_policy(&hash, &sig, exe_path, &policy);
                    match decision.as_str() {
                        "allowed" => verified += 1,
                        "blocked" => blocked += 1,
                        _ => unknown += 1,
                    }
                    if !sig.is_signed {
                        unsigned += 1;
                    }
                }
            }
            Err(_) => {
                unknown += 1;
            }
        }
    }

    Ok(AppControlStatus {
        total_processes: total,
        verified,
        unknown,
        blocked,
        unsigned,
        policy,
        last_scan: Utc::now().to_rfc3339(),
    })
}

#[tauri::command]
pub fn add_to_allowlist(hash: String) -> Result<(), String> {
    let mut policy = POLICY.write();
    if !policy.allowlist_hashes.contains(&hash) {
        policy.allowlist_hashes.push(hash);
    }
    Ok(())
}

#[tauri::command]
pub fn add_to_denylist(hash: String) -> Result<(), String> {
    let mut policy = POLICY.write();
    policy.allowlist_hashes.retain(|h| h != &hash);
    if !policy.denylist_hashes.contains(&hash) {
        policy.denylist_hashes.push(hash);
    }
    Ok(())
}
