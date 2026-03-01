// Cyber Security Prime - Advanced Malware Scanner Module
// Provides memory forensics, behavioral detection, and YARA rule integration

use crate::utils::{generate_id, now, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use sysinfo::System;

// ============================================================================
// Cached System for Scanner (avoids expensive System::new_all() calls)
// ============================================================================

struct ScannerSystemCache {
    system: System,
    last_refresh: std::time::Instant,
}

impl ScannerSystemCache {
    fn new() -> Self {
        Self {
            system: System::new_all(),
            last_refresh: std::time::Instant::now(),
        }
    }

    /// Get system with processes refreshed if stale (older than 5 seconds)
    fn get_with_processes(&mut self) -> &System {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_refresh).as_secs() >= 5 {
            self.system.refresh_processes();
            self.last_refresh = now;
        }
        &self.system
    }
}

static SCANNER_SYSTEM: Lazy<Arc<RwLock<ScannerSystemCache>>> = Lazy::new(|| {
    Arc::new(RwLock::new(ScannerSystemCache::new()))
});

// ============================================================================
// Global Scan State
// ============================================================================

#[derive(Debug, Clone)]
struct ScanStateInner {
    id: String,
    scan_type: String,
    status: String, // "counting", "scanning", "completed", "stopped"
    started_at: DateTime<Utc>,
    total_files: u64,
    scanned_files: u64,
    threats: Vec<ThreatInfo>,
    current_file: Option<String>,
    stop_requested: bool,
    completed_at: Option<DateTime<Utc>>,
}

static ACTIVE_SCAN: Lazy<Arc<RwLock<Option<ScanStateInner>>>> = Lazy::new(|| {
    Arc::new(RwLock::new(None))
});

const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    "exe", "dll", "bat", "cmd", "ps1", "vbs", "vbe",
    "wsf", "wsh", "scr", "pif", "com", "hta", "msi",
];

const SUSPICIOUS_FILE_NAMES: &[&str] = &[
    "mimikatz", "lazagne", "procdump", "psexec", "keylogger",
    "trojan", "backdoor", "rootkit", "exploit", "payload",
    "reverse_shell", "meterpreter", "cobaltstrike", "beacon",
    "havoc", "bruteforce", "hashcat",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    pub id: String,
    pub scan_type: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub total_files: u64,
    pub scanned_files: u64,
    pub threats_found: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub id: String,
    pub status: String,
    pub progress: f32,
    pub current_file: Option<String>,
    pub scanned_files: u64,
    pub threats_found: u32,
    pub estimated_time_remaining: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanResults {
    pub id: String,
    pub scan_type: String,
    pub status: String,
    #[serde(default = "default_datetime")]
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub total_files: u64,
    pub scanned_files: u64,
    pub threats: Vec<ThreatInfo>,
    pub duration_seconds: u64,
}

fn default_datetime() -> DateTime<Utc> {
    Utc::now()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub id: String,
    pub name: String,
    pub threat_type: String,
    pub severity: Severity,
    pub file_path: String,
    pub detected_at: DateTime<Utc>,
    pub status: String,
    pub description: String,
}

// ============================================================================
// Advanced Scanning Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    Basic,
    MemoryForensics,
    BehavioralAnalysis,
    YaraScan,
    Comprehensive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanResult {
    pub process_id: u32,
    pub process_name: String,
    pub memory_regions: Vec<MemoryRegion>,
    pub detected_signatures: Vec<MemorySignature>,
    pub suspicious_patterns: Vec<String>,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: usize,
    pub protection: String,
    pub allocation_type: String,
    pub suspicious: bool,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySignature {
    pub signature_id: String,
    pub name: String,
    pub offset: u64,
    pub pattern: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalysis {
    pub process_id: u32,
    pub process_name: String,
    pub behavior_score: f64,
    pub anomalies: Vec<BehavioralAnomaly>,
    pub risk_level: String,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnomaly {
    pub anomaly_type: String,
    pub severity: Severity,
    pub description: String,
    pub confidence: f64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub condition: String,
    pub strings: Vec<YaraString>,
    pub metadata: HashMap<String, String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraString {
    pub identifier: String,
    pub pattern: String,
    pub modifiers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanResult {
    pub rule_id: String,
    pub rule_name: String,
    pub matches: Vec<YaraMatch>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub file_path: String,
    pub offset: u64,
    pub string_identifier: String,
    pub string_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedScanResults {
    pub basic_results: Option<ScanResults>,
    pub memory_results: Option<Vec<MemoryScanResult>>,
    pub behavioral_results: Option<Vec<BehavioralAnalysis>>,
    pub yara_results: Option<Vec<YaraScanResult>>,
    pub comprehensive_score: u8,
    pub overall_risk_assessment: String,
}

// ============================================================================
// Real File Scanning
// ============================================================================

/// Start a new scan session — spawns a background thread that walks real files
pub fn start_scan(scan_type: &str) -> Result<ScanSession, String> {
    // Cancel any running scan first
    {
        let mut guard = ACTIVE_SCAN.write();
        if let Some(ref mut existing) = *guard {
            existing.stop_requested = true;
        }
    }

    let id = generate_id();
    let started_at = now();

    *ACTIVE_SCAN.write() = Some(ScanStateInner {
        id: id.clone(),
        scan_type: scan_type.to_string(),
        status: "counting".to_string(),
        started_at,
        total_files: 0,
        scanned_files: 0,
        threats: Vec::new(),
        current_file: Some("Counting files...".to_string()),
        stop_requested: false,
        completed_at: None,
    });

    let scan_type_owned = scan_type.to_string();
    let scan_id = id.clone();
    std::thread::spawn(move || {
        run_scan_background(&scan_type_owned, &scan_id);
    });

    Ok(ScanSession {
        id,
        scan_type: scan_type.to_string(),
        status: "running".to_string(),
        started_at,
        total_files: 0,
        scanned_files: 0,
        threats_found: 0,
    })
}

/// Start a custom scan on user-specified directories
pub fn start_custom_scan(target_paths: Vec<String>) -> Result<ScanSession, String> {
    if target_paths.is_empty() {
        return Err("No target paths provided".to_string());
    }
    {
        let mut guard = ACTIVE_SCAN.write();
        if let Some(ref mut existing) = *guard {
            existing.stop_requested = true;
        }
    }

    let id = generate_id();
    let started_at = now();

    *ACTIVE_SCAN.write() = Some(ScanStateInner {
        id: id.clone(),
        scan_type: "custom".to_string(),
        status: "counting".to_string(),
        started_at,
        total_files: 0,
        scanned_files: 0,
        threats: Vec::new(),
        current_file: Some("Counting files...".to_string()),
        stop_requested: false,
        completed_at: None,
    });

    let scan_id = id.clone();
    std::thread::spawn(move || {
        run_custom_scan_background(&target_paths, &scan_id);
    });

    Ok(ScanSession {
        id,
        scan_type: "custom".to_string(),
        status: "running".to_string(),
        started_at,
        total_files: 0,
        scanned_files: 0,
        threats_found: 0,
    })
}

/// Get real-time status of the active scan
pub fn get_scan_status(scan_id: &str) -> Result<ScanStatus, String> {
    let guard = ACTIVE_SCAN.read();
    match &*guard {
        Some(scan) if scan.id == scan_id || scan_id == "last" => {
            let progress = if scan.total_files > 0 {
                (scan.scanned_files as f32 / scan.total_files as f32 * 100.0).min(100.0)
            } else {
                0.0
            };

            let elapsed = (Utc::now() - scan.started_at).num_seconds().max(1);
            let estimated_remaining = if progress > 1.0 && progress < 100.0 {
                let total_est = elapsed as f64 / (progress as f64 / 100.0);
                let remaining = (total_est - elapsed as f64).max(0.0);
                Some(format_duration(remaining as u64))
            } else {
                None
            };

            Ok(ScanStatus {
                id: scan.id.clone(),
                status: scan.status.clone(),
                progress,
                current_file: scan.current_file.clone(),
                scanned_files: scan.scanned_files,
                threats_found: scan.threats.len() as u32,
                estimated_time_remaining: estimated_remaining,
            })
        }
        _ => Err("No active scan found".to_string()),
    }
}

/// Get the results of a completed (or in-progress) scan
pub fn get_scan_results(scan_id: &str) -> Result<ScanResults, String> {
    let guard = ACTIVE_SCAN.read();
    match &*guard {
        Some(scan) if scan.id == scan_id || scan_id == "last" => {
            let duration = if let Some(completed) = scan.completed_at {
                (completed - scan.started_at).num_seconds().unsigned_abs()
            } else {
                (Utc::now() - scan.started_at).num_seconds().unsigned_abs()
            };

            Ok(ScanResults {
                id: scan.id.clone(),
                scan_type: scan.scan_type.clone(),
                status: scan.status.clone(),
                started_at: scan.started_at,
                completed_at: scan.completed_at,
                total_files: scan.total_files,
                scanned_files: scan.scanned_files,
                threats: scan.threats.clone(),
                duration_seconds: duration,
            })
        }
        _ => Err("No scan results available".to_string()),
    }
}

/// Stop an ongoing scan via the shared flag
pub fn stop_scan(scan_id: &str) -> Result<bool, String> {
    let mut guard = ACTIVE_SCAN.write();
    if let Some(ref mut scan) = *guard {
        if scan.id == scan_id || scan_id == "any" {
            scan.stop_requested = true;
            scan.status = "stopped".to_string();
            scan.current_file = None;
            scan.completed_at = Some(now());
            return Ok(true);
        }
    }
    Ok(false)
}

/// Quarantine detected threats by moving files to a secure directory
pub fn quarantine_threats(threat_ids: Vec<String>) -> Result<u32, String> {
    let quarantine_dir = {
        let base = std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string()));
        let dir = PathBuf::from(base).join("CyberSecurityPrime").join("quarantine");
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create quarantine dir: {}", e))?;
        dir
    };

    let all = threat_ids.is_empty();
    let mut quarantined = 0u32;

    let mut guard = ACTIVE_SCAN.write();
    if let Some(ref mut scan) = *guard {
        for threat in &mut scan.threats {
            if !(all || threat_ids.contains(&threat.id)) {
                continue;
            }
            if threat.status == "quarantined" {
                continue;
            }

            let source = Path::new(&threat.file_path);
            if !source.exists() {
                continue;
            }

            let filename = source
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            let dest = quarantine_dir.join(format!("{}.quarantined", filename));

            let moved = std::fs::rename(source, &dest).is_ok()
                || (std::fs::copy(source, &dest).is_ok() && std::fs::remove_file(source).is_ok());

            if moved {
                threat.status = "quarantined".to_string();
                quarantined += 1;
            }
        }
    }

    Ok(quarantined)
}

// ============================================================================
// Background Scan Engine
// ============================================================================

fn run_scan_background(scan_type: &str, scan_id: &str) {
    let dirs = get_scan_directories(scan_type);

    // Phase 1 — count files
    let mut total: u64 = 0;
    for dir in &dirs {
        if is_stopped(scan_id) { return; }
        total += count_files_recursive(dir, scan_id);
    }

    {
        let mut guard = ACTIVE_SCAN.write();
        if let Some(ref mut scan) = *guard {
            if scan.id != scan_id { return; }
            scan.total_files = total.max(1);
            scan.status = "scanning".to_string();
            scan.current_file = Some("Starting scan...".to_string());
        }
    }

    // Phase 2 — scan files
    for dir in &dirs {
        if is_stopped(scan_id) { return; }
        scan_files_recursive(dir, scan_id);
    }

    // Phase 3 — mark complete
    let mut guard = ACTIVE_SCAN.write();
    if let Some(ref mut scan) = *guard {
        if scan.id != scan_id { return; }
        if !scan.stop_requested {
            scan.status = "completed".to_string();
        }
        scan.completed_at = Some(now());
        scan.current_file = None;
    }
}

fn run_custom_scan_background(target_paths: &[String], scan_id: &str) {
    let dirs: Vec<PathBuf> = target_paths
        .iter()
        .map(|p| PathBuf::from(p))
        .filter(|p| p.exists())
        .collect();

    let mut total: u64 = 0;
    for dir in &dirs {
        if is_stopped(scan_id) { return; }
        total += count_files_recursive(dir, scan_id);
    }

    {
        let mut guard = ACTIVE_SCAN.write();
        if let Some(ref mut scan) = *guard {
            if scan.id != scan_id { return; }
            scan.total_files = total.max(1);
            scan.status = "scanning".to_string();
            scan.current_file = Some("Starting scan...".to_string());
        }
    }

    for dir in &dirs {
        if is_stopped(scan_id) { return; }
        scan_files_recursive(dir, scan_id);
    }

    let mut guard = ACTIVE_SCAN.write();
    if let Some(ref mut scan) = *guard {
        if scan.id != scan_id { return; }
        if !scan.stop_requested {
            scan.status = "completed".to_string();
        }
        scan.completed_at = Some(now());
        scan.current_file = None;
    }
}

fn is_stopped(scan_id: &str) -> bool {
    ACTIVE_SCAN
        .read()
        .as_ref()
        .map_or(true, |s| s.stop_requested || s.id != scan_id)
}

fn get_scan_directories(scan_type: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    match scan_type {
        "quick" => {
            if let Ok(user) = std::env::var("USERPROFILE") {
                let user = PathBuf::from(user);
                for sub in &["Downloads", "Desktop", "Documents"] {
                    let d = user.join(sub);
                    if d.exists() {
                        dirs.push(d);
                    }
                }
            }
            if let Ok(temp) = std::env::var("TEMP") {
                let d = PathBuf::from(temp);
                if d.exists() {
                    dirs.push(d);
                }
            }
        }
        "full" => {
            for letter in b'C'..=b'Z' {
                let drive = format!("{}:\\", letter as char);
                let path = PathBuf::from(&drive);
                if path.exists() {
                    dirs.push(path);
                }
            }
        }
        _ => {
            if let Ok(user) = std::env::var("USERPROFILE") {
                dirs.push(PathBuf::from(user));
            }
        }
    }
    dirs
}

fn should_skip_directory(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    matches!(
        name.as_str(),
        "node_modules"
            | ".git"
            | ".svn"
            | "target"
            | ".cargo"
            | "$recycle.bin"
            | "system volume information"
            | "windows"
            | "program files"
            | "program files (x86)"
            | "programdata"
            | ".vs"
            | ".idea"
            | ".vscode"
            | "appdata"
    )
}

fn count_files_recursive(dir: &Path, scan_id: &str) -> u64 {
    if is_stopped(scan_id) {
        return 0;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    let mut count = 0u64;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_dir() {
            if !should_skip_directory(&path) {
                count += count_files_recursive(&path, scan_id);
            }
        } else {
            count += 1;
        }
    }
    count
}

fn scan_files_recursive(dir: &Path, scan_id: &str) {
    if is_stopped(scan_id) {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries {
        if is_stopped(scan_id) {
            return;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_dir() {
            if !should_skip_directory(&path) {
                scan_files_recursive(&path, scan_id);
            }
        } else {
            analyze_single_file(&path, scan_id);
        }
    }
}

fn analyze_single_file(path: &Path, scan_id: &str) {
    // Update progress
    {
        let mut guard = ACTIVE_SCAN.write();
        if let Some(ref mut scan) = *guard {
            if scan.id != scan_id {
                return;
            }
            scan.scanned_files += 1;
            if scan.scanned_files % 50 == 0 {
                scan.current_file = Some(path.display().to_string());
            }
        }
    }

    let filename = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_string(),
        None => return,
    };
    let filename_lower = filename.to_lowercase();
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // 1. Double extensions (e.g. report.pdf.exe)
    if has_double_extension(&filename_lower) {
        add_threat(
            scan_id,
            &format!("Suspicious.DoubleExt.{}", filename),
            "Suspicious",
            Severity::High,
            path,
            "File has a double extension commonly used to disguise malicious files",
        );
        return;
    }

    // 2. Known malicious tool names
    for pattern in SUSPICIOUS_FILE_NAMES {
        if filename_lower.contains(pattern) {
            add_threat(
                scan_id,
                &format!("HackTool.{}", filename),
                "HackTool",
                Severity::High,
                path,
                &format!("File name matches known attack tool pattern: {}", pattern),
            );
            return;
        }
    }

    // 3. Executable in temp directory
    if SUSPICIOUS_EXTENSIONS.contains(&extension.as_str()) {
        let path_lower = path.display().to_string().to_lowercase();
        if path_lower.contains("\\temp\\") || path_lower.contains("\\tmp\\") {
            add_threat(
                scan_id,
                &format!("Suspicious.TempExec.{}", filename),
                "Suspicious",
                Severity::Medium,
                path,
                "Executable file found in temporary directory — common malware staging location",
            );
            return;
        }
    }

    // 4. PE header hidden inside non-executable extension (< 10 MB)
    if !SUSPICIOUS_EXTENSIONS.contains(&extension.as_str()) && !extension.is_empty() {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > 0 && meta.len() < 10_000_000 {
                if let Ok(mut f) = std::fs::File::open(path) {
                    let mut header = [0u8; 2];
                    if std::io::Read::read_exact(&mut f, &mut header).is_ok() && &header == b"MZ" {
                        add_threat(
                            scan_id,
                            &format!("Disguised.PE.{}", filename),
                            "Disguised Executable",
                            Severity::High,
                            path,
                            &format!(
                                "File has .{} extension but contains a PE executable header (MZ)",
                                extension
                            ),
                        );
                    }
                }
            }
        }
    }
}

fn has_double_extension(filename: &str) -> bool {
    let parts: Vec<&str> = filename.rsplitn(3, '.').collect();
    if parts.len() < 3 {
        return false;
    }
    let outer = parts[0];
    let inner = parts[1];

    let executable = [
        "exe", "scr", "bat", "cmd", "pif", "com", "vbs", "js", "ps1", "hta", "msi",
    ];
    let document = [
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png",
        "gif", "bmp", "mp3", "mp4", "avi", "mov", "zip", "rar", "7z",
    ];

    executable.contains(&outer) && document.contains(&inner)
}

fn add_threat(scan_id: &str, name: &str, threat_type: &str, severity: Severity, path: &Path, description: &str) {
    let mut guard = ACTIVE_SCAN.write();
    if let Some(ref mut scan) = *guard {
        if scan.id == scan_id {
            scan.threats.push(ThreatInfo {
                id: generate_id(),
                name: name.to_string(),
                threat_type: threat_type.to_string(),
                severity,
                file_path: path.display().to_string(),
                detected_at: now(),
                status: "detected".to_string(),
                description: description.to_string(),
            });
        }
    }
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{} seconds", secs)
    } else {
        format!("{} min {} sec", secs / 60, secs % 60)
    }
}

#[allow(dead_code)]
fn compute_file_sha256(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > 50_000_000 {
        return None;
    }
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = std::io::Read::read(&mut reader, &mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

// ============================================================================
// Memory Forensics Scanning
// ============================================================================

/// Perform memory forensics scanning on running processes
pub async fn scan_memory_forensics() -> Result<Vec<MemoryScanResult>, String> {
    let mut results = Vec::new();

    let process_info: Vec<(u32, String)> = {
        let mut cached = SCANNER_SYSTEM.write();
        let sys = cached.get_with_processes();

        sys.processes()
            .iter()
            .filter(|(_, process)| {
                let name = process.name().to_lowercase();
                !name.contains("system") && !name.contains("svchost") && !name.contains("lsass")
            })
            .take(50)
            .map(|(pid, process)| (pid.as_u32(), process.name().to_string()))
            .collect()
    };

    for (process_id, process_name) in process_info {
        let start_time = std::time::Instant::now();

        let memory_regions = analyze_memory_regions(process_id);
        let detected_signatures = scan_memory_signatures(process_id).await;
        let suspicious_patterns = detect_suspicious_patterns(process_id);

        let scan_duration = start_time.elapsed().as_millis() as u64;

        results.push(MemoryScanResult {
            process_id,
            process_name,
            memory_regions,
            detected_signatures,
            suspicious_patterns,
            scan_duration_ms: scan_duration,
        });
    }

    Ok(results)
}

/// Enumerate real memory regions of a process using Windows VirtualQueryEx API
fn analyze_memory_regions(process_id: u32) -> Vec<MemoryRegion> {
    #[cfg(windows)]
    {
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION,
            MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
            PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_NOACCESS, PAGE_GUARD,
        };
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
        use windows::Win32::Foundation::CloseHandle;

        let mut regions = Vec::new();

        let handle = unsafe {
            match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process_id) {
                Ok(h) => h,
                Err(_) => return Vec::new(),
            }
        };

        let mut address: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        loop {
            let result = unsafe {
                VirtualQueryEx(
                    handle,
                    Some(address as *const std::ffi::c_void),
                    &mut mbi,
                    mbi_size,
                )
            };

            if result == 0 {
                break;
            }

            if mbi.State == MEM_COMMIT {
                let protection = {
                    let p = mbi.Protect;
                    let mut parts = Vec::new();
                    if p.contains(PAGE_EXECUTE_READWRITE) {
                        parts.push("READ|WRITE|EXECUTE");
                    } else if p.contains(PAGE_EXECUTE_READ) {
                        parts.push("READ|EXECUTE");
                    } else if p.contains(PAGE_EXECUTE_WRITECOPY) {
                        parts.push("WRITECOPY|EXECUTE");
                    } else if p.contains(PAGE_EXECUTE) {
                        parts.push("EXECUTE");
                    } else if p.contains(PAGE_READWRITE) {
                        parts.push("READ|WRITE");
                    } else if p.contains(PAGE_WRITECOPY) {
                        parts.push("WRITECOPY");
                    } else if p.contains(PAGE_READONLY) {
                        parts.push("READ");
                    } else if p.contains(PAGE_NOACCESS) {
                        parts.push("NOACCESS");
                    }
                    if p.contains(PAGE_GUARD) {
                        parts.push("GUARD");
                    }
                    if parts.is_empty() {
                        format!("0x{:X}", p.0)
                    } else {
                        parts.join("|")
                    }
                };

                let allocation_type = {
                    let t = mbi.Type;
                    if t == MEM_IMAGE { "MEM_IMAGE".to_string() }
                    else if t == MEM_MAPPED { "MEM_MAPPED".to_string() }
                    else if t == MEM_PRIVATE { "MEM_PRIVATE".to_string() }
                    else { format!("0x{:X}", t.0) }
                };

                let is_rwx = mbi.Protect.contains(PAGE_EXECUTE_READWRITE);
                let is_exec_private = mbi.Protect.contains(PAGE_EXECUTE_READ) && mbi.Type == MEM_PRIVATE;
                let suspicious = is_rwx || is_exec_private;

                let entropy = if mbi.RegionSize > 0 && mbi.RegionSize < 4_194_304 {
                    compute_region_entropy(handle, mbi.BaseAddress as usize, mbi.RegionSize)
                } else if is_rwx {
                    7.5
                } else {
                    0.0
                };

                regions.push(MemoryRegion {
                    base_address: mbi.BaseAddress as u64,
                    size: mbi.RegionSize,
                    protection,
                    allocation_type,
                    suspicious,
                    entropy,
                });
            }

            address = mbi.BaseAddress as usize + mbi.RegionSize;
            if address == 0 { break; }
        }

        unsafe { let _ = CloseHandle(handle); }

        // Collapse small regions to keep result manageable — keep suspicious + largest
        if regions.len() > 100 {
            regions.sort_by(|a, b| b.size.cmp(&a.size));
            let suspicious: Vec<_> = regions.iter().filter(|r| r.suspicious).cloned().collect();
            regions.truncate(80);
            for s in suspicious {
                if !regions.iter().any(|r| r.base_address == s.base_address) {
                    regions.push(s);
                }
            }
        }

        regions
    }

    #[cfg(not(windows))]
    {
        let _ = process_id;
        Vec::new()
    }
}

/// Compute Shannon entropy of a memory region by reading its bytes
#[cfg(windows)]
fn compute_region_entropy(handle: windows::Win32::Foundation::HANDLE, base: usize, size: usize) -> f64 {
    let sample_size = size.min(65536);
    let mut buffer = vec![0u8; sample_size];
    let mut bytes_read: usize = 0;

    let ok = unsafe {
        windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            handle,
            base as *const std::ffi::c_void,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            sample_size,
            Some(&mut bytes_read),
        )
    };

    if ok.is_err() || bytes_read == 0 {
        return 0.0;
    }

    let data = &buffer[..bytes_read];
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &f in &freq {
        if f > 0 {
            let p = f as f64 / len;
            entropy -= p * p.log2();
        }
    }
    (entropy * 100.0).round() / 100.0
}

/// Scan real running processes for known malicious tool names & suspicious paths
async fn scan_memory_signatures(process_id: u32) -> Vec<MemorySignature> {
    let mut cached = SCANNER_SYSTEM.write();
    let sys = cached.get_with_processes();
    let pid = sysinfo::Pid::from(process_id as usize);

    let process = match sys.process(pid) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let name_lower = process.name().to_lowercase();
    let exe_lower = process.exe().map(|p| p.display().to_string().to_lowercase()).unwrap_or_default();

    let mut signatures = Vec::new();

    let checks: &[(&str, &str, Severity)] = &[
        ("mimikatz", "Credential Dumping Tool", Severity::Critical),
        ("lazagne", "Password Recovery Tool", Severity::Critical),
        ("psexec", "Remote Execution Tool", Severity::High),
        ("netcat", "Network Utility (Netcat)", Severity::High),
        ("ncat", "Network Utility (Ncat)", Severity::High),
        ("keylogger", "Potential Keylogger", Severity::Critical),
        ("meterpreter", "Metasploit Payload", Severity::Critical),
        ("cobaltstrike", "Cobalt Strike Beacon", Severity::Critical),
        ("beacon", "Potential C2 Beacon", Severity::High),
    ];

    for (pattern, desc, severity) in checks {
        if name_lower.contains(pattern) || exe_lower.contains(pattern) {
            signatures.push(MemorySignature {
                signature_id: format!("SIG_{}", pattern.to_uppercase()),
                name: desc.to_string(),
                offset: 0,
                pattern: pattern.to_string(),
                severity: severity.clone(),
                description: format!("{} detected (PID {})", desc, process_id),
            });
        }
    }

    if exe_lower.contains("\\temp\\")
        || exe_lower.contains("\\tmp\\")
        || exe_lower.contains("\\appdata\\local\\temp")
    {
        signatures.push(MemorySignature {
            signature_id: "SIG_TEMP_EXEC".to_string(),
            name: "Execution from Temp Directory".to_string(),
            offset: 0,
            pattern: "TEMP_EXEC".to_string(),
            severity: Severity::Medium,
            description: format!("Process running from temp directory: {}", exe_lower),
        });
    }

    signatures
}

/// Check real process characteristics for suspicious patterns
fn detect_suspicious_patterns(process_id: u32) -> Vec<String> {
    let mut cached = SCANNER_SYSTEM.write();
    let sys = cached.get_with_processes();
    let pid = sysinfo::Pid::from(process_id as usize);

    let process = match sys.process(pid) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let mut patterns = Vec::new();

    let cpu = process.cpu_usage();
    if cpu > 80.0 {
        patterns.push(format!(
            "High CPU usage: {:.1}% — possible cryptominer or malware",
            cpu
        ));
    }

    let mem_mb = process.memory() as f64 / 1_048_576.0;
    if mem_mb > 1000.0 {
        patterns.push(format!("Excessive memory usage: {:.0} MB", mem_mb));
    }

    let exe_path = process.exe().map(|p| p.display().to_string().to_lowercase()).unwrap_or_default();
    if exe_path.contains("\\temp\\") || exe_path.contains("\\tmp\\") {
        patterns.push(format!("Running from temp directory: {}", exe_path));
    }

    let name_lower = process.name().to_lowercase();
    if name_lower.ends_with(".tmp") || name_lower.ends_with(".dat") {
        patterns.push("Process has unusual file extension".to_string());
    }

    patterns
}

// ============================================================================
// Behavioral Malware Detection
// ============================================================================

/// Perform behavioral analysis on running processes
pub async fn analyze_behavioral_patterns() -> Result<Vec<BehavioralAnalysis>, String> {
    let mut results = Vec::new();

    let process_data: Vec<(u32, String, f64, Vec<BehavioralAnomaly>)> = {
        let mut cached = SCANNER_SYSTEM.write();
        let sys = cached.get_with_processes();

        sys.processes()
            .iter()
            .filter(|(_, process)| {
                let name = process.name().to_lowercase();
                !name.contains("system") && !name.contains("svchost")
            })
            .take(50)
            .map(|(pid, process)| {
                let process_id = pid.as_u32();
                let process_name = process.name().to_string();
                let behavior_score = calculate_behavior_score(process);
                let anomalies = detect_behavioral_anomalies(process);
                (process_id, process_name, behavior_score, anomalies)
            })
            .collect()
    };

    for (process_id, process_name, behavior_score, anomalies) in process_data {
        let risk_level = assess_risk_level(behavior_score);
        let recommendations = generate_recommendations(&anomalies);

        results.push(BehavioralAnalysis {
            process_id,
            process_name,
            behavior_score,
            anomalies,
            risk_level,
            recommendations,
        });
    }

    Ok(results)
}

/// Calculate behavior score based on various factors
fn calculate_behavior_score(process: &sysinfo::Process) -> f64 {
    let mut score: f64 = 0.0;

    let cpu_usage = process.cpu_usage() as f64;
    if cpu_usage > 80.0 {
        score += 30.0;
    } else if cpu_usage > 50.0 {
        score += 15.0;
    }

    let memory_mb = process.memory() as f64 / 1_048_576.0;
    if memory_mb > 1000.0 {
        score += 25.0;
    } else if memory_mb > 500.0 {
        score += 10.0;
    }

    // Flag processes running from temp directories
    if let Some(exe) = process.exe() {
        let path_lower = exe.to_string_lossy().to_lowercase();
        if path_lower.contains("\\temp\\") || path_lower.contains("\\tmp\\") || path_lower.contains("/tmp/") {
            score += 15.0;
        }
    }

    score.min(100.0)
}

/// Detect behavioral anomalies
fn detect_behavioral_anomalies(process: &sysinfo::Process) -> Vec<BehavioralAnomaly> {
    let mut anomalies = Vec::new();

    let cpu_usage = process.cpu_usage() as f64;
    if cpu_usage > 80.0 {
        anomalies.push(BehavioralAnomaly {
            anomaly_type: "High CPU Usage".to_string(),
            severity: Severity::Medium,
            description: format!("Process using {:.1}% CPU, which is unusually high", cpu_usage),
            confidence: 0.85,
            timestamp: now(),
        });
    }

    let memory_mb = process.memory() as f64 / 1_048_576.0;
    if memory_mb > 1000.0 {
        anomalies.push(BehavioralAnomaly {
            anomaly_type: "High Memory Usage".to_string(),
            severity: Severity::Medium,
            description: format!(
                "Process using {:.1} MB memory, which is unusually high",
                memory_mb
            ),
            confidence: 0.75,
            timestamp: now(),
        });
    }

    // Only flag Notepad if it has suspiciously high CPU (>5%) suggesting code injection
    if process.name().to_lowercase().contains("notepad") && process.cpu_usage() > 5.0 {
        anomalies.push(BehavioralAnomaly {
            anomaly_type: "Suspicious Process Behavior".to_string(),
            severity: Severity::Medium,
            description: format!("Notepad.exe showing unusual CPU activity ({:.1}%), possible code injection", process.cpu_usage()),
            confidence: 0.70,
            timestamp: now(),
        });
    }

    anomalies
}

/// Assess overall risk level
fn assess_risk_level(score: f64) -> String {
    match score {
        s if s >= 70.0 => "HIGH RISK".to_string(),
        s if s >= 40.0 => "MEDIUM RISK".to_string(),
        s if s >= 20.0 => "LOW RISK".to_string(),
        _ => "SAFE".to_string(),
    }
}

/// Generate recommendations based on anomalies
fn generate_recommendations(anomalies: &[BehavioralAnomaly]) -> Vec<String> {
    let mut recommendations = Vec::new();

    for anomaly in anomalies {
        match anomaly.anomaly_type.as_str() {
            "High CPU Usage" => {
                recommendations.push("Monitor CPU usage closely".to_string());
                recommendations.push("Consider terminating suspicious processes".to_string());
            }
            "High Memory Usage" => {
                recommendations.push("Check for memory leaks".to_string());
                recommendations.push("Consider restarting the application".to_string());
            }
            "Unexpected Network Activity" => {
                recommendations.push("Block network access for this process".to_string());
                recommendations.push("Scan system for malware".to_string());
            }
            _ => {}
        }
    }

    if recommendations.is_empty() {
        recommendations.push("No specific recommendations - system appears normal".to_string());
    }

    recommendations
}

// ============================================================================
// YARA Rule Integration (powered by yara-x engine)
// ============================================================================

static YARA_RULES: Lazy<Arc<RwLock<Vec<YaraRule>>>> = Lazy::new(|| {
    Arc::new(RwLock::new(Vec::new()))
});

/// Default YARA rule source for built-in detection
const DEFAULT_YARA_SOURCE: &str = r#"
rule PE_Executable {
    meta:
        author = "SecurityPrime"
        description = "Detects PE (Windows executable) files"
        severity = "info"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}

rule Suspicious_Shellcode {
    meta:
        author = "SecurityPrime"
        description = "Detects common shellcode patterns"
        severity = "critical"
    strings:
        $api_call1 = { 64 A1 30 00 00 00 }
        $api_call2 = { 64 8B 0D 30 00 00 00 }
        $ws2_32 = "ws2_32" nocase
        $wininet = "WinINet" nocase
        $urlmon = "URLDownloadToFile" nocase
    condition:
        ($api_call1 or $api_call2) or (2 of ($ws2_32, $wininet, $urlmon))
}

rule Suspicious_PowerShell_Invocation {
    meta:
        author = "SecurityPrime"
        description = "Detects obfuscated or suspicious PowerShell execution"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-EncodedCommand" nocase
        $ps3 = "-ExecutionPolicy Bypass" nocase
        $ps4 = "Invoke-Expression" nocase
        $ps5 = "IEX" nocase
        $ps6 = "FromBase64String" nocase
        $ps7 = "New-Object System.Net.WebClient" nocase
        $ps8 = "DownloadString" nocase
        $ps9 = "-WindowStyle Hidden" nocase
    condition:
        $ps1 and (2 of ($ps2, $ps3, $ps4, $ps5, $ps6, $ps7, $ps8, $ps9))
}

rule Credential_Harvesting_Tool {
    meta:
        author = "SecurityPrime"
        description = "Detects known credential harvesting tools"
        severity = "critical"
    strings:
        $mimikatz1 = "mimikatz" nocase
        $mimikatz2 = "sekurlsa::logonpasswords" nocase
        $lazagne = "lazagne" nocase
        $procdump = "procdump" nocase
        $lsass = "lsass.exe" nocase
        $sam_dump = "SAM" wide
    condition:
        any of ($mimikatz*, $lazagne) or ($procdump and $lsass) or ($sam_dump and $lsass)
}

rule Reverse_Shell_Indicators {
    meta:
        author = "SecurityPrime"
        description = "Detects reverse shell payloads and indicators"
        severity = "critical"
    strings:
        $nc1 = "nc.exe" nocase
        $nc2 = "ncat" nocase
        $bind = "/bin/sh" nocase
        $sock = "socket" nocase
        $connect = "connect" nocase
        $meterpreter = "meterpreter" nocase
        $cobalt = "cobaltstrike" nocase
        $beacon = "beacon.dll" nocase
    condition:
        $meterpreter or $cobalt or $beacon or ($nc1 and $sock) or ($nc2 and $connect)
}

rule Ransomware_Indicators {
    meta:
        author = "SecurityPrime"
        description = "Detects ransomware behavioral strings"
        severity = "critical"
    strings:
        $ransom1 = "Your files have been encrypted" nocase
        $ransom2 = "bitcoin" nocase
        $ransom3 = "decrypt" nocase
        $ransom4 = ".onion" nocase
        $ransom5 = "HOW_TO_RECOVER" nocase
        $ransom6 = "DECRYPT_INSTRUCTIONS" nocase
        $crypto1 = "CryptEncrypt" nocase
        $crypto2 = "CryptGenKey" nocase
    condition:
        2 of ($ransom*) or (1 of ($ransom*) and 1 of ($crypto*))
}

rule Packed_Or_Encrypted_Binary {
    meta:
        author = "SecurityPrime"
        description = "Detects UPX-packed or heavily obfuscated binaries"
        severity = "medium"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
        $aspack = ".aspack"
        $themida = "Themida"
    condition:
        ($upx0 and $upx1) or $upx2 or $aspack or $themida
}

rule Suspicious_Script_Content {
    meta:
        author = "SecurityPrime"
        description = "Detects suspicious script content in non-script files"
        severity = "high"
    strings:
        $vbs1 = "CreateObject" nocase
        $vbs2 = "WScript.Shell" nocase
        $vbs3 = "Scripting.FileSystemObject" nocase
        $js1 = "eval(" nocase
        $js2 = "ActiveXObject" nocase
        $bat1 = "reg add" nocase
        $bat2 = "schtasks /create" nocase
    condition:
        2 of them
}
"#;

/// Compile YARA source into a compiled ruleset using yara-x
fn compile_yara_rules_source(source: &str) -> Result<yara_x::Rules, String> {
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(source)
        .map_err(|e| format!("YARA compilation error: {}", e))?;
    Ok(compiler.build())
}

/// Initialize default YARA rules (also compiles to validate)
pub fn initialize_yara_rules() -> Result<(), String> {
    let mut rules = YARA_RULES.write();

    compile_yara_rules_source(DEFAULT_YARA_SOURCE)?;

    rules.push(YaraRule {
        id: "BUILTIN_RULES".to_string(),
        name: "SecurityPrime Built-in Rules (8 rules, yara-x engine)".to_string(),
        namespace: "malware".to_string(),
        condition: "see individual rules".to_string(),
        strings: vec![],
        metadata: HashMap::from([
            ("author".to_string(), "SecurityPrime".to_string()),
            ("engine".to_string(), "yara-x".to_string()),
            ("description".to_string(), "PE detection, shellcode, PowerShell, credentials, reverse shells, ransomware, packers, suspicious scripts".to_string()),
        ]),
        enabled: true,
    });

    Ok(())
}

/// Get all YARA rules
pub fn get_yara_rules() -> Result<Vec<YaraRule>, String> {
    let rules = YARA_RULES.read();
    Ok(rules.clone())
}

/// Add a custom YARA rule (validates by compiling)
pub fn add_yara_rule(rule: YaraRule) -> Result<(), String> {
    if !rule.condition.is_empty() && !rule.strings.is_empty() {
        let mut source = format!("rule {} {{\n  strings:\n", rule.id);
        for s in &rule.strings {
            if s.modifiers.iter().any(|m| m == "nocase") {
                source.push_str(&format!("    {} = \"{}\" nocase\n", s.identifier, s.pattern));
            } else {
                source.push_str(&format!("    {} = \"{}\"\n", s.identifier, s.pattern));
            }
        }
        source.push_str(&format!("  condition:\n    {}\n}}\n", rule.condition));
        compile_yara_rules_source(&source)?;
    }
    let mut rules = YARA_RULES.write();
    rules.push(rule);
    Ok(())
}

/// Scan files using the real yara-x engine
pub async fn scan_with_yara(file_paths: Vec<String>) -> Result<Vec<YaraScanResult>, String> {
    let compiled = compile_yara_rules_source(DEFAULT_YARA_SOURCE)?;

    let custom_rules_source: Option<String> = {
        let rules = YARA_RULES.read();
        let custom: Vec<&YaraRule> = rules.iter()
            .filter(|r| r.enabled && r.id != "BUILTIN_RULES" && !r.strings.is_empty())
            .collect();
        if custom.is_empty() {
            None
        } else {
            let mut src = String::new();
            for rule in custom {
                src.push_str(&format!("rule {} {{\n  strings:\n", rule.id));
                for s in &rule.strings {
                    if s.modifiers.iter().any(|m| m == "nocase") {
                        src.push_str(&format!("    {} = \"{}\" nocase\n", s.identifier, s.pattern));
                    } else {
                        src.push_str(&format!("    {} = \"{}\"\n", s.identifier, s.pattern));
                    }
                }
                src.push_str(&format!("  condition:\n    {}\n}}\n", rule.condition));
            }
            Some(src)
        }
    };

    let custom_compiled = if let Some(ref src) = custom_rules_source {
        Some(compile_yara_rules_source(src)?)
    } else {
        None
    };

    let mut results: Vec<YaraScanResult> = Vec::new();

    for file_path in &file_paths {
        let path = Path::new(file_path);
        if !path.exists() || !path.is_file() {
            continue;
        }

        let content = match std::fs::read(path) {
            Ok(data) => {
                if data.len() > 10_485_760 {
                    data[..10_485_760].to_vec()
                } else {
                    data
                }
            }
            Err(_) => continue,
        };

        let rulesets: Vec<&yara_x::Rules> = if let Some(ref cr) = custom_compiled {
            vec![&compiled, cr]
        } else {
            vec![&compiled]
        };

        for ruleset in &rulesets {
            let mut scanner = yara_x::Scanner::new(ruleset);
            let scan_results = scanner.scan(&content)
                .map_err(|e| format!("YARA scan error on {}: {}", file_path, e))?;

            for matched_rule in scan_results.matching_rules() {
                let rule_name = matched_rule.identifier().to_string();
                let severity_str = matched_rule.metadata()
                    .into_iter()
                    .find(|(id, _)| *id == "severity")
                    .and_then(|(_, val)| match val {
                        yara_x::MetaValue::String(s) => Some(s.to_string()),
                        _ => None,
                    })
                    .unwrap_or_else(|| "medium".to_string());

                let severity = match severity_str.as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "info" | "low" => Severity::Low,
                    _ => Severity::Medium,
                };

                let mut matches = Vec::new();
                for pattern in matched_rule.patterns() {
                    for m in pattern.matches() {
                        matches.push(YaraMatch {
                            file_path: file_path.clone(),
                            offset: m.range().start as u64,
                            string_identifier: pattern.identifier().to_string(),
                            string_data: format!("{} bytes at offset 0x{:X}", m.range().len(), m.range().start),
                        });
                    }
                }

                let existing = results.iter_mut().find(|r| r.rule_id == rule_name);
                if let Some(existing) = existing {
                    existing.matches.extend(matches);
                } else {
                    results.push(YaraScanResult {
                        rule_id: rule_name.clone(),
                        rule_name,
                        matches,
                        severity,
                    });
                }
            }
        }
    }

    Ok(results)
}

// ============================================================================
// Comprehensive Advanced Scanning
// ============================================================================

/// Perform comprehensive advanced scanning
pub async fn perform_advanced_scan(
    scan_type: ScanType,
    target_paths: Option<Vec<String>>,
) -> Result<AdvancedScanResults, String> {
    let mut results = AdvancedScanResults {
        basic_results: None,
        memory_results: None,
        behavioral_results: None,
        yara_results: None,
        comprehensive_score: 0,
        overall_risk_assessment: "UNKNOWN".to_string(),
    };

    match scan_type {
        ScanType::Basic => {
            results.basic_results = Some(get_scan_results("last").unwrap_or_default());
        }
        ScanType::MemoryForensics => {
            results.memory_results = Some(scan_memory_forensics().await?);
        }
        ScanType::BehavioralAnalysis => {
            results.behavioral_results = Some(analyze_behavioral_patterns().await?);
        }
        ScanType::YaraScan => {
            if let Some(paths) = target_paths {
                results.yara_results = Some(scan_with_yara(paths).await?);
            }
        }
        ScanType::Comprehensive => {
            results.basic_results = Some(get_scan_results("last").unwrap_or_default());
            results.memory_results = Some(scan_memory_forensics().await?);
            results.behavioral_results = Some(analyze_behavioral_patterns().await?);

            if let Some(paths) = target_paths {
                results.yara_results = Some(scan_with_yara(paths).await?);
            }
        }
    }

    let (score, assessment) = calculate_comprehensive_score(&results);
    results.comprehensive_score = score;
    results.overall_risk_assessment = assessment;

    Ok(results)
}

/// Calculate comprehensive security score
fn calculate_comprehensive_score(results: &AdvancedScanResults) -> (u8, String) {
    let mut total_score = 0u32;
    let mut components = 0u32;

    if let Some(ref basic) = results.basic_results {
        let basic_score = if basic.threats.is_empty() { 90 } else { 60 };
        total_score += basic_score;
        components += 1;
    }

    if let Some(ref memory) = results.memory_results {
        let memory_score = memory
            .iter()
            .map(|r| {
                if r.detected_signatures.is_empty() {
                    85
                } else {
                    40
                }
            })
            .sum::<u32>()
            / memory.len().max(1) as u32;
        total_score += memory_score;
        components += 1;
    }

    if let Some(ref behavioral) = results.behavioral_results {
        let behavioral_score = behavioral
            .iter()
            .map(|r| (100.0 - r.behavior_score) as u32)
            .sum::<u32>()
            / behavioral.len().max(1) as u32;
        total_score += behavioral_score;
        components += 1;
    }

    if let Some(ref yara) = results.yara_results {
        let yara_score = if yara.is_empty() { 95 } else { 70 };
        total_score += yara_score;
        components += 1;
    }

    let final_score = if components > 0 {
        (total_score / components) as u8
    } else {
        85
    };

    let assessment = match final_score {
        90..=100 => "VERY LOW RISK".to_string(),
        80..=89 => "LOW RISK".to_string(),
        70..=79 => "MODERATE RISK".to_string(),
        60..=69 => "HIGH RISK".to_string(),
        _ => "CRITICAL RISK".to_string(),
    };

    (final_score, assessment)
}
