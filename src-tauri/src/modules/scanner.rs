// Cyber Security Prime - Advanced Malware Scanner Module
// Provides memory forensics, behavioral detection, and YARA rule integration

use crate::utils::{generate_id, now, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

/// Start a new scan session
pub fn start_scan(scan_type: &str) -> Result<ScanSession, String> {
    let session = ScanSession {
        id: generate_id(),
        scan_type: scan_type.to_string(),
        status: "running".to_string(),
        started_at: now(),
        total_files: 15000, // Placeholder
        scanned_files: 0,
        threats_found: 0,
    };
    
    Ok(session)
}

/// Get the status of an ongoing scan
pub fn get_scan_status(scan_id: &str) -> Result<ScanStatus, String> {
    // Placeholder implementation - in production, this would track real scan progress
    Ok(ScanStatus {
        id: scan_id.to_string(),
        status: "running".to_string(),
        progress: 45.5,
        current_file: Some("C:\\Users\\Documents\\file.pdf".to_string()),
        scanned_files: 6825,
        threats_found: 0,
        estimated_time_remaining: Some("2 minutes 30 seconds".to_string()),
    })
}

/// Get the results of a completed scan
pub fn get_scan_results(scan_id: &str) -> Result<ScanResults, String> {
    // Placeholder implementation with mock data
    Ok(ScanResults {
        id: scan_id.to_string(),
        scan_type: "full".to_string(),
        status: "completed".to_string(),
        started_at: now(),
        completed_at: Some(now()),
        total_files: 15000,
        scanned_files: 15000,
        threats: vec![
            ThreatInfo {
                id: generate_id(),
                name: "Trojan.GenericKD.46584903".to_string(),
                threat_type: "Trojan".to_string(),
                severity: Severity::High,
                file_path: "C:\\Users\\Downloads\\suspicious_file.exe".to_string(),
                detected_at: now(),
                status: "quarantined".to_string(),
                description: "Detected malicious executable attempting to modify system files".to_string(),
            },
            ThreatInfo {
                id: generate_id(),
                name: "PUP.Optional.BundleInstaller".to_string(),
                threat_type: "PUP".to_string(),
                severity: Severity::Low,
                file_path: "C:\\Users\\Downloads\\free_software_installer.exe".to_string(),
                detected_at: now(),
                status: "detected".to_string(),
                description: "Potentially unwanted program that may install additional software".to_string(),
            },
        ],
        duration_seconds: 180,
    })
}

/// Stop an ongoing scan
pub fn stop_scan(scan_id: &str) -> Result<bool, String> {
    // Placeholder - would stop actual scan process
    println!("Stopping scan: {}", scan_id);
    Ok(true)
}

// ============================================================================
// Memory Forensics Scanning
// ============================================================================

/// Perform memory forensics scanning on running processes
pub async fn scan_memory_forensics() -> Result<Vec<MemoryScanResult>, String> {
    let mut results = Vec::new();

    // Collect process info while holding the lock briefly
    let process_info: Vec<(u32, String)> = {
        let mut cached = SCANNER_SYSTEM.write();
        let sys = cached.get_with_processes();
        
        sys.processes()
            .iter()
            .filter(|(_, process)| {
                let name = process.name().to_lowercase();
                // Skip system processes
                !name.contains("system") && !name.contains("svchost") && !name.contains("lsass")
            })
            .take(50) // Limit to 50 processes to avoid performance issues
            .map(|(pid, process)| (pid.as_u32(), process.name().to_string()))
            .collect()
    };

    // Process each without holding the system lock
    for (process_id, process_name) in process_info {
        let start_time = std::time::Instant::now();

        // Simulate memory region analysis
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

/// Analyze memory regions of a process
fn analyze_memory_regions(process_id: u32) -> Vec<MemoryRegion> {
    // In a real implementation, this would use Windows API (ReadProcessMemory, VirtualQueryEx)
    // or platform-specific memory reading libraries

    vec![
        MemoryRegion {
            base_address: 0x0000000000400000,
            size: 4096,
            protection: "READ|WRITE|EXECUTE".to_string(),
            allocation_type: "MEM_COMMIT".to_string(),
            suspicious: true, // RWX is suspicious
            entropy: 7.85,
        },
        MemoryRegion {
            base_address: 0x0000000000500000,
            size: 8192,
            protection: "READ|WRITE".to_string(),
            allocation_type: "MEM_COMMIT".to_string(),
            suspicious: false,
            entropy: 3.24,
        },
        MemoryRegion {
            base_address: 0x00007FF000000000,
            size: 65536,
            protection: "READ|EXECUTE".to_string(),
            allocation_type: "MEM_IMAGE".to_string(),
            suspicious: false,
            entropy: 5.67,
        },
    ]
}

/// Scan memory for known malware signatures
async fn scan_memory_signatures(process_id: u32) -> Vec<MemorySignature> {
    // In a real implementation, this would read process memory and scan for signatures
    // For now, return mock suspicious signatures

    vec![
        MemorySignature {
            signature_id: "MEM_SIG_001".to_string(),
            name: "Potential Shellcode Pattern".to_string(),
            offset: 0x0000000000401000,
            pattern: "\\x90\\x90\\x90\\x90".to_string(),
            severity: Severity::High,
            description: "Detected NOP sled pattern commonly used in shellcode".to_string(),
        },
    ]
}

/// Detect suspicious memory patterns
fn detect_suspicious_patterns(process_id: u32) -> Vec<String> {
    vec![
        "High entropy region with RWX permissions".to_string(),
        "Injected DLL detected".to_string(),
        "Unusual memory allocation pattern".to_string(),
    ]
}

// ============================================================================
// Behavioral Malware Detection
// ============================================================================

/// Perform behavioral analysis on running processes
pub async fn analyze_behavioral_patterns() -> Result<Vec<BehavioralAnalysis>, String> {
    let mut results = Vec::new();

    // Collect process data while holding the lock briefly
    let process_data: Vec<(u32, String, f64, Vec<BehavioralAnomaly>)> = {
        let mut cached = SCANNER_SYSTEM.write();
        let sys = cached.get_with_processes();

        sys.processes()
            .iter()
            .filter(|(_, process)| {
                let name = process.name().to_lowercase();
                // Skip system processes
                !name.contains("system") && !name.contains("svchost")
            })
            .take(50) // Limit to 50 processes
            .map(|(pid, process)| {
                let process_id = pid.as_u32();
                let process_name = process.name().to_string();
                let behavior_score = calculate_behavior_score(process);
                let anomalies = detect_behavioral_anomalies(process);
                (process_id, process_name, behavior_score, anomalies)
            })
            .collect()
    };

    // Build results without holding the lock
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

    // CPU usage factor
    let cpu_usage = process.cpu_usage() as f64;
    if cpu_usage > 80.0 {
        score += 30.0;
    } else if cpu_usage > 50.0 {
        score += 15.0;
    }

    // Memory usage factor
    let memory_mb = process.memory() as f64 / 1_048_576.0; // Convert to MB
    if memory_mb > 1000.0 {
        score += 25.0;
    } else if memory_mb > 500.0 {
        score += 10.0;
    }

    // Network connections (simulated)
    if process.name().to_lowercase().contains("chrome") {
        score += 5.0; // Browsers are expected to have network activity
    }

    // File system access patterns (simulated)
    score += 8.0; // Some baseline suspicious activity

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
            description: format!("Process using {:.1} MB memory, which is unusually high", memory_mb),
            confidence: 0.75,
            timestamp: now(),
        });
    }

    // Simulated network anomaly detection
    if process.name().to_lowercase().contains("notepad") {
        anomalies.push(BehavioralAnomaly {
            anomaly_type: "Unexpected Network Activity".to_string(),
            severity: Severity::High,
            description: "Notepad.exe making network connections, which is suspicious".to_string(),
            confidence: 0.95,
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
// YARA Rule Integration
// ============================================================================

static YARA_RULES: Lazy<Arc<RwLock<Vec<YaraRule>>>> = Lazy::new(|| {
    Arc::new(RwLock::new(Vec::new()))
});

/// Initialize default YARA rules
pub fn initialize_yara_rules() -> Result<(), String> {
    let mut rules = YARA_RULES.write();

    // Add some default YARA rules
    rules.push(YaraRule {
        id: "MALWARE_PE_HEADER".to_string(),
        name: "PE File Header Signature".to_string(),
        namespace: "malware".to_string(),
        condition: "pe.is_pe and pe.entry_point > 0".to_string(),
        strings: vec![
            YaraString {
                identifier: "$mz".to_string(),
                pattern: "MZ".to_string(),
                modifiers: vec![],
            },
        ],
        metadata: HashMap::from([
            ("author".to_string(), "Security Prime".to_string()),
            ("description".to_string(), "Detects PE file headers".to_string()),
        ]),
        enabled: true,
    });

    rules.push(YaraRule {
        id: "SUSPICIOUS_STRINGS".to_string(),
        name: "Suspicious String Patterns".to_string(),
        namespace: "suspicious".to_string(),
        condition: "any of them".to_string(),
        strings: vec![
            YaraString {
                identifier: "$cmd".to_string(),
                pattern: "cmd.exe".to_string(),
                modifiers: vec!["nocase".to_string()],
            },
            YaraString {
                identifier: "$powershell".to_string(),
                pattern: "powershell.exe".to_string(),
                modifiers: vec!["nocase".to_string()],
            },
        ],
        metadata: HashMap::from([
            ("author".to_string(), "Security Prime".to_string()),
            ("description".to_string(), "Detects suspicious command execution".to_string()),
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

/// Add a custom YARA rule
pub fn add_yara_rule(rule: YaraRule) -> Result<(), String> {
    let mut rules = YARA_RULES.write();
    rules.push(rule);
    Ok(())
}

/// Scan files using YARA rules
pub async fn scan_with_yara(file_paths: Vec<String>) -> Result<Vec<YaraScanResult>, String> {
    let rules = YARA_RULES.read();
    let mut results = Vec::new();

    // In a real implementation, this would compile YARA rules and scan files
    // For now, return mock results

    for rule in rules.iter().filter(|r| r.enabled) {
        let mut matches = Vec::new();

        for file_path in &file_paths {
            // Simulate YARA scanning
            if file_path.ends_with(".exe") || file_path.ends_with(".dll") {
                matches.push(YaraMatch {
                    file_path: file_path.clone(),
                    offset: 0x1000,
                    string_identifier: "$mz".to_string(),
                    string_data: "MZ".to_string(),
                });
            }
        }

        if !matches.is_empty() {
            results.push(YaraScanResult {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                matches,
                severity: Severity::Medium,
            });
        }
    }

    Ok(results)
}

/// Perform comprehensive advanced scanning
pub async fn perform_advanced_scan(scan_type: ScanType, target_paths: Option<Vec<String>>) -> Result<AdvancedScanResults, String> {
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
            // Perform basic file scanning
            results.basic_results = Some(get_scan_results("advanced").unwrap_or_default());
        }
        ScanType::MemoryForensics => {
            // Perform memory forensics
            results.memory_results = Some(scan_memory_forensics().await?);
        }
        ScanType::BehavioralAnalysis => {
            // Perform behavioral analysis
            results.behavioral_results = Some(analyze_behavioral_patterns().await?);
        }
        ScanType::YaraScan => {
            // Perform YARA scanning
            if let Some(paths) = target_paths {
                results.yara_results = Some(scan_with_yara(paths).await?);
            }
        }
        ScanType::Comprehensive => {
            // Perform all scanning types
            results.basic_results = Some(get_scan_results("comprehensive").unwrap_or_default());
            results.memory_results = Some(scan_memory_forensics().await?);
            results.behavioral_results = Some(analyze_behavioral_patterns().await?);

            if let Some(paths) = target_paths {
                results.yara_results = Some(scan_with_yara(paths).await?);
            }
        }
    }

    // Calculate comprehensive score and risk assessment
    let (score, assessment) = calculate_comprehensive_score(&results);
    results.comprehensive_score = score;
    results.overall_risk_assessment = assessment;

    Ok(results)
}

/// Calculate comprehensive security score
fn calculate_comprehensive_score(results: &AdvancedScanResults) -> (u8, String) {
    let mut total_score = 0u32;
    let mut components = 0u32;

    // Basic scan score
    if let Some(ref basic) = results.basic_results {
        let basic_score = if basic.threats.is_empty() { 90 } else { 60 };
        total_score += basic_score;
        components += 1;
    }

    // Memory scan score
    if let Some(ref memory) = results.memory_results {
        let memory_score = memory.iter()
            .map(|r| if r.detected_signatures.is_empty() { 85 } else { 40 })
            .sum::<u32>() / memory.len().max(1) as u32;
        total_score += memory_score;
        components += 1;
    }

    // Behavioral analysis score
    if let Some(ref behavioral) = results.behavioral_results {
        let behavioral_score = behavioral.iter()
            .map(|r| (100.0 - r.behavior_score) as u32)
            .sum::<u32>() / behavioral.len().max(1) as u32;
        total_score += behavioral_score;
        components += 1;
    }

    // YARA scan score
    if let Some(ref yara) = results.yara_results {
        let yara_score = if yara.is_empty() { 95 } else { 70 };
        total_score += yara_score;
        components += 1;
    }

    let final_score = if components > 0 {
        (total_score / components) as u8
    } else {
        85 // Default safe score
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

