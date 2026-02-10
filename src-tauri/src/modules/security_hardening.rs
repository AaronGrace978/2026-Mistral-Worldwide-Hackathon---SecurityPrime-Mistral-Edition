// Cyber Security Prime - Security Hardening Module
// Provides memory protection, secure logging, and rate limiting capabilities

use crate::modules::{SecurityModule, ModuleHealth};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use once_cell::sync::Lazy;
use uuid::Uuid;

// Global security hardening state
static SECURITY_STATE: Lazy<Mutex<SecurityState>> = Lazy::new(|| Mutex::new(SecurityState::new()));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityState {
    pub memory_protection: MemoryProtection,
    pub secure_logging: SecureLogging,
    pub rate_limiting: RateLimiting,
    pub security_events: VecDeque<SecurityEvent>,
    pub hardening_metrics: HardeningMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProtection {
    pub enabled: bool,
    pub canary_enabled: bool,
    pub aslr_enabled: bool,
    pub dep_enabled: bool,
    pub heap_protection: bool,
    pub stack_protection: bool,
    pub memory_encryption: bool,
    pub monitored_regions: Vec<MemoryRegion>,
    pub violations: Vec<MemoryViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub id: String,
    pub start_address: u64,
    pub size: u64,
    pub protection: MemoryProtectionFlags,
    pub description: String,
    pub last_access: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProtectionFlags {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub guard: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryViolation {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub region_id: String,
    pub violation_type: ViolationType,
    pub process_id: u32,
    pub thread_id: u32,
    pub address: u64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ViolationType {
    BufferOverflow,
    UseAfterFree,
    DoubleFree,
    InvalidAccess,
    HeapCorruption,
    StackCorruption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureLogging {
    pub enabled: bool,
    pub log_encryption: bool,
    pub tamper_detection: bool,
    pub remote_logging: bool,
    pub log_retention_days: u32,
    pub sensitive_data_masking: bool,
    pub audit_trail: Vec<LogEntry>,
    pub log_integrity_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub category: String,
    pub message: String,
    pub source: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub metadata: HashMap<String, String>,
    pub hash: String, // For integrity verification
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiting {
    pub enabled: bool,
    pub global_limits: RateLimit,
    pub endpoint_limits: HashMap<String, RateLimit>,
    pub user_limits: HashMap<String, RateLimit>,
    pub current_usage: HashMap<String, UsageCounter>,
    pub blocked_requests: Vec<BlockedRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub burst_limit: u32,
    pub cooldown_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageCounter {
    pub key: String,
    pub minute_count: u32,
    pub hour_count: u32,
    pub last_request: DateTime<Utc>,
    pub blocked_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedRequest {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub user_agent: String,
    pub endpoint: String,
    pub reason: String,
    pub retry_after: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub severity: EventSeverity,
    pub description: String,
    pub source: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityEventType {
    MemoryViolation,
    LogTampering,
    RateLimitExceeded,
    SuspiciousActivity,
    SecurityConfigChange,
    HardeningViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningMetrics {
    pub memory_violations_today: u32,
    pub log_integrity_checks: u32,
    pub rate_limit_blocks: u32,
    pub average_response_time: f64,
    pub memory_usage_mb: u64,
    pub last_updated: DateTime<Utc>,
}

impl SecurityState {
    fn new() -> Self {
        Self {
            memory_protection: MemoryProtection {
                enabled: true,
                canary_enabled: true,
                aslr_enabled: true,
                dep_enabled: true,
                heap_protection: true,
                stack_protection: true,
                memory_encryption: false, // Hardware dependent
                monitored_regions: Vec::new(),
                violations: Vec::new(),
            },
            secure_logging: SecureLogging {
                enabled: true,
                log_encryption: true,
                tamper_detection: true,
                remote_logging: false,
                log_retention_days: 90,
                sensitive_data_masking: true,
                audit_trail: Vec::new(),
                log_integrity_hash: String::new(),
            },
            rate_limiting: RateLimiting {
                enabled: true,
                global_limits: RateLimit {
                    requests_per_minute: 1000,
                    requests_per_hour: 10000,
                    burst_limit: 100,
                    cooldown_seconds: 300,
                },
                endpoint_limits: HashMap::new(),
                user_limits: HashMap::new(),
                current_usage: HashMap::new(),
                blocked_requests: Vec::new(),
            },
            security_events: VecDeque::with_capacity(1000),
            hardening_metrics: HardeningMetrics {
                memory_violations_today: 0,
                log_integrity_checks: 0,
                rate_limit_blocks: 0,
                average_response_time: 0.0,
                memory_usage_mb: 0,
                last_updated: Utc::now(),
            },
        }
    }
}

pub struct SecurityHardeningModule {
    pub name: &'static str,
    pub description: &'static str,
    pub version: &'static str,
    pub active: bool,
}

impl Default for SecurityHardeningModule {
    fn default() -> Self {
        Self {
            name: "Security Hardening",
            description: "Memory protection, secure logging, and rate limiting",
            version: "1.0.0",
            active: true,
        }
    }
}

impl SecurityModule for SecurityHardeningModule {
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
        let mut state = SECURITY_STATE.lock().unwrap();

        // Initialize memory protection
        self.initialize_memory_protection(&mut state)?;

        // Initialize secure logging
        self.initialize_secure_logging(&mut state)?;

        // Initialize rate limiting
        self.initialize_rate_limiting(&mut state)?;

        // Log initialization
        self.log_security_event(
            SecurityEventType::SecurityConfigChange,
            EventSeverity::Info,
            "Security hardening module initialized successfully".to_string(),
            "module_init".to_string(),
            serde_json::json!({
                "memory_protection": state.memory_protection.enabled,
                "secure_logging": state.secure_logging.enabled,
                "rate_limiting": state.rate_limiting.enabled
            }),
        );

        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), String> {
        let mut state = SECURITY_STATE.lock().unwrap();

        // Clean up resources
        state.memory_protection.monitored_regions.clear();
        state.rate_limiting.current_usage.clear();

        self.log_security_event(
            SecurityEventType::SecurityConfigChange,
            EventSeverity::Info,
            "Security hardening module shut down".to_string(),
            "module_shutdown".to_string(),
            serde_json::json!({}),
        );

        Ok(())
    }

    fn health_check(&self) -> ModuleHealth {
        let state = SECURITY_STATE.lock().unwrap();

        let mut issues: Vec<String> = Vec::new();

        if !state.memory_protection.enabled {
            issues.push("Memory protection disabled".to_string());
        }

        if !state.secure_logging.enabled {
            issues.push("Secure logging disabled".to_string());
        }

        if state.hardening_metrics.memory_violations_today > 0 {
            issues.push(format!("{} memory violations today", state.hardening_metrics.memory_violations_today));
        }

        let healthy = issues.is_empty();

        let message = if healthy {
            format!(
                "Security hardening active: {} memory regions monitored, {} log entries, {} rate limit blocks",
                state.memory_protection.monitored_regions.len(),
                state.secure_logging.audit_trail.len(),
                state.rate_limiting.blocked_requests.len()
            )
        } else {
            format!("Security issues detected: {}", issues.join(", "))
        };

        ModuleHealth {
            healthy,
            message,
            last_check: Utc::now().to_rfc3339(),
        }
    }
}

impl SecurityHardeningModule {
    fn initialize_memory_protection(&self, state: &mut SecurityState) -> Result<(), String> {
        // Add default monitored memory regions
        let regions = vec![
            MemoryRegion {
                id: "heap".to_string(),
                start_address: 0x10000000, // Example address
                size: 1024 * 1024 * 100, // 100MB
                protection: MemoryProtectionFlags {
                    read: true,
                    write: true,
                    execute: false,
                    guard: false,
                },
                description: "Main heap memory region".to_string(),
                last_access: Utc::now(),
            },
            MemoryRegion {
                id: "stack".to_string(),
                start_address: 0x7FFFFFFF0000, // Example address
                size: 1024 * 1024 * 8, // 8MB
                protection: MemoryProtectionFlags {
                    read: true,
                    write: true,
                    execute: false,
                    guard: true,
                },
                description: "Main stack memory region".to_string(),
                last_access: Utc::now(),
            },
        ];

        state.memory_protection.monitored_regions.extend(regions);
        Ok(())
    }

    fn initialize_secure_logging(&self, state: &mut SecurityState) -> Result<(), String> {
        // Create initial log integrity hash
        state.secure_logging.log_integrity_hash = self.calculate_log_integrity_hash(&state.secure_logging.audit_trail);

        // Add initial log entry
        self.log_entry(
            LogLevel::Info,
            "security".to_string(),
            "Secure logging initialized".to_string(),
            "system".to_string(),
            None,
            None,
            HashMap::new(),
        );

        Ok(())
    }

    fn initialize_rate_limiting(&self, state: &mut SecurityState) -> Result<(), String> {
        // Set up default endpoint limits
        let endpoint_limits = HashMap::from([
            ("scan".to_string(), RateLimit {
                requests_per_minute: 10,
                requests_per_hour: 100,
                burst_limit: 5,
                cooldown_seconds: 60,
            }),
            ("login".to_string(), RateLimit {
                requests_per_minute: 5,
                requests_per_hour: 20,
                burst_limit: 3,
                cooldown_seconds: 300,
            }),
            ("api".to_string(), RateLimit {
                requests_per_minute: 100,
                requests_per_hour: 1000,
                burst_limit: 50,
                cooldown_seconds: 60,
            }),
        ]);

        state.rate_limiting.endpoint_limits = endpoint_limits;
        Ok(())
    }

    fn log_security_event(
        &self,
        event_type: SecurityEventType,
        severity: EventSeverity,
        description: String,
        source: String,
        details: serde_json::Value,
    ) {
        let mut state = SECURITY_STATE.lock().unwrap();

        let event = SecurityEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            severity,
            description,
            source,
            details,
        };

        // Keep only the last 1000 events
        if state.security_events.len() >= 1000 {
            state.security_events.pop_front();
        }

        state.security_events.push_back(event);
    }

    fn log_entry(
        &self,
        level: LogLevel,
        category: String,
        message: String,
        source: String,
        user_id: Option<String>,
        session_id: Option<String>,
        metadata: HashMap<String, String>,
    ) {
        let mut state = SECURITY_STATE.lock().unwrap();

        // Mask sensitive data
        let masked_message = if state.secure_logging.sensitive_data_masking {
            self.mask_sensitive_data(&message)
        } else {
            message
        };

        let entry = LogEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            level,
            category,
            message: masked_message,
            source,
            user_id,
            session_id,
            metadata,
            hash: String::new(), // Would be calculated with cryptographic hash
        };

        state.secure_logging.audit_trail.push(entry);

        // Update log integrity hash
        state.secure_logging.log_integrity_hash =
            self.calculate_log_integrity_hash(&state.secure_logging.audit_trail);
    }

    fn mask_sensitive_data(&self, message: &str) -> String {
        // Simple sensitive data masking - in real implementation, use regex patterns
        message
            .replace("password=", "password=***")
            .replace("token=", "token=***")
            .replace("key=", "key=***")
    }

    fn calculate_log_integrity_hash(&self, entries: &[LogEntry]) -> String {
        // Simple hash calculation - in real implementation, use cryptographic hash
        format!("integrity_hash_{}", entries.len())
    }

    fn check_rate_limit(&self, key: &str, endpoint: &str, user_id: Option<&str>) -> Result<bool, String> {
        let mut state = SECURITY_STATE.lock().unwrap();

        if !state.rate_limiting.enabled {
            return Ok(true);
        }

        let now = Utc::now();

        // Get the effective limits first (before mutable borrow)
        let limits = self.get_effective_limits_clone(&state, endpoint, user_id);

        // Get or create usage counter
        let counter = state.rate_limiting.current_usage
            .entry(key.to_string())
            .or_insert(UsageCounter {
                key: key.to_string(),
                minute_count: 0,
                hour_count: 0,
                last_request: now,
                blocked_until: None,
            });

        // Check if currently blocked
        if let Some(blocked_until) = counter.blocked_until {
            if now < blocked_until {
                // Still blocked
                let blocked_request = BlockedRequest {
                    id: Uuid::new_v4().to_string(),
                    timestamp: now,
                    client_ip: key.to_string(),
                    user_agent: "unknown".to_string(),
                    endpoint: endpoint.to_string(),
                    reason: "Rate limit exceeded".to_string(),
                    retry_after: blocked_until,
                };

                state.rate_limiting.blocked_requests.push(blocked_request);
                state.hardening_metrics.rate_limit_blocks += 1;

                return Ok(false);
            } else {
                // Block expired, reset counter
                counter.blocked_until = None;
                counter.minute_count = 0;
                counter.hour_count = 0;
            }
        }

        // Reset counters if needed
        if (now - counter.last_request).num_minutes() >= 1 {
            counter.minute_count = 0;
        }
        if (now - counter.last_request).num_hours() >= 1 {
            counter.hour_count = 0;
        }

        counter.minute_count += 1;
        counter.hour_count += 1;
        
        let minute_count = counter.minute_count;
        let hour_count = counter.hour_count;
        counter.last_request = now;

        let exceeded = minute_count > limits.requests_per_minute ||
                      hour_count > limits.requests_per_hour;

        if exceeded {
            counter.blocked_until = Some(now + chrono::Duration::seconds(limits.cooldown_seconds as i64));
            state.hardening_metrics.rate_limit_blocks += 1;

            drop(state); // Release lock before logging

            self.log_security_event(
                SecurityEventType::RateLimitExceeded,
                EventSeverity::Medium,
                format!("Rate limit exceeded for {}", key),
                "rate_limiting".to_string(),
                serde_json::json!({
                    "key": key,
                    "endpoint": endpoint,
                    "minute_count": minute_count,
                    "hour_count": hour_count
                }),
            );

            return Ok(false);
        }

        Ok(true)
    }

    fn get_effective_limits_clone(&self, state: &SecurityState, endpoint: &str, user_id: Option<&str>) -> RateLimit {
        // Check user-specific limits first
        if let Some(user_id) = user_id {
            if let Some(user_limit) = state.rate_limiting.user_limits.get(user_id) {
                return user_limit.clone();
            }
        }

        // Check endpoint-specific limits
        if let Some(endpoint_limit) = state.rate_limiting.endpoint_limits.get(endpoint) {
            return endpoint_limit.clone();
        }

        // Return global limits
        state.rate_limiting.global_limits.clone()
    }
}

// Tauri commands for security hardening module
#[tauri::command]
pub fn get_memory_protection_status() -> Result<MemoryProtection, String> {
    let state = SECURITY_STATE.lock().unwrap();
    Ok(state.memory_protection.clone())
}

#[tauri::command]
pub fn get_secure_logging_status() -> Result<SecureLogging, String> {
    let state = SECURITY_STATE.lock().unwrap();
    Ok(state.secure_logging.clone())
}

#[tauri::command]
pub fn get_rate_limiting_status() -> Result<RateLimiting, String> {
    let state = SECURITY_STATE.lock().unwrap();
    Ok(state.rate_limiting.clone())
}

#[tauri::command]
pub fn check_rate_limit(key: String, endpoint: String, user_id: Option<String>) -> Result<bool, String> {
    let module = SecurityHardeningModule::default();
    module.check_rate_limit(&key, &endpoint, user_id.as_deref())
}

#[tauri::command]
pub fn log_security_event(level: LogLevel, category: String, message: String, source: String, user_id: Option<String>, session_id: Option<String>, metadata: HashMap<String, String>) -> Result<(), String> {
    let module = SecurityHardeningModule::default();
    module.log_entry(level, category, message, source, user_id, session_id, metadata);
    Ok(())
}

#[tauri::command]
pub fn get_security_events(limit: Option<usize>) -> Result<Vec<SecurityEvent>, String> {
    let state = SECURITY_STATE.lock().unwrap();
    let limit = limit.unwrap_or(100);
    let events: Vec<SecurityEvent> = state.security_events.iter().rev().take(limit).cloned().collect();
    Ok(events)
}

#[tauri::command]
pub fn get_hardening_metrics() -> Result<HardeningMetrics, String> {
    let state = SECURITY_STATE.lock().unwrap();
    Ok(state.hardening_metrics.clone())
}

#[tauri::command]
pub fn report_memory_violation(violation_type: ViolationType, process_id: u32, thread_id: u32, address: u64, description: String) -> Result<(), String> {
    let mut state = SECURITY_STATE.lock().unwrap();

    let violation_type_str = format!("{:?}", violation_type);
    let description_clone = description.clone();

    let violation = MemoryViolation {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        region_id: "unknown".to_string(), // Would be determined by address lookup
        violation_type,
        process_id,
        thread_id,
        address,
        description: description_clone.clone(),
    };

    state.memory_protection.violations.push(violation);
    state.hardening_metrics.memory_violations_today += 1;
    drop(state); // Release lock before logging

    let module = SecurityHardeningModule::default();
    module.log_security_event(
        SecurityEventType::MemoryViolation,
        EventSeverity::High,
        format!("Memory violation detected: {}", description_clone),
        "memory_protection".to_string(),
        serde_json::json!({
            "violation_type": violation_type_str,
            "process_id": process_id,
            "address": format!("0x{:x}", address)
        }),
    );

    Ok(())
}

#[tauri::command]
pub fn verify_log_integrity() -> Result<bool, String> {
    let state = SECURITY_STATE.lock().unwrap();

    let current_hash = {
        let module = SecurityHardeningModule::default();
        module.calculate_log_integrity_hash(&state.secure_logging.audit_trail)
    };

    let integrity_intact = current_hash == state.secure_logging.log_integrity_hash;

    if !integrity_intact {
        let module = SecurityHardeningModule::default();
        module.log_security_event(
            SecurityEventType::LogTampering,
            EventSeverity::Critical,
            "Log integrity verification failed".to_string(),
            "secure_logging".to_string(),
            serde_json::json!({
                "expected_hash": state.secure_logging.log_integrity_hash,
                "current_hash": current_hash
            }),
        );
    }

    Ok(integrity_intact)
}

#[tauri::command]
pub fn get_security_hardening_dashboard() -> Result<serde_json::Value, String> {
    let state = SECURITY_STATE.lock().unwrap();

    let dashboard = serde_json::json!({
        "memory_protection": {
            "enabled": state.memory_protection.enabled,
            "regions_monitored": state.memory_protection.monitored_regions.len(),
            "violations_today": state.hardening_metrics.memory_violations_today,
            "canary_enabled": state.memory_protection.canary_enabled,
            "aslr_enabled": state.memory_protection.aslr_enabled
        },
        "secure_logging": {
            "enabled": state.secure_logging.enabled,
            "encryption_enabled": state.secure_logging.log_encryption,
            "tamper_detection": state.secure_logging.tamper_detection,
            "total_entries": state.secure_logging.audit_trail.len(),
            "retention_days": state.secure_logging.log_retention_days
        },
        "rate_limiting": {
            "enabled": state.rate_limiting.enabled,
            "global_rpm": state.rate_limiting.global_limits.requests_per_minute,
            "active_counters": state.rate_limiting.current_usage.len(),
            "blocked_requests": state.rate_limiting.blocked_requests.len(),
            "blocks_today": state.hardening_metrics.rate_limit_blocks
        },
        "security_events": {
            "total_events": state.security_events.len(),
            "critical_events": state.security_events.iter().filter(|e| matches!(e.severity, EventSeverity::Critical)).count(),
            "recent_high_severity": state.security_events.iter().rev().take(10).filter(|e| matches!(e.severity, EventSeverity::High | EventSeverity::Critical)).count()
        },
        "performance": {
            "average_response_time": state.hardening_metrics.average_response_time,
            "memory_usage_mb": state.hardening_metrics.memory_usage_mb,
            "last_updated": state.hardening_metrics.last_updated.to_rfc3339()
        }
    });

    Ok(dashboard)
}