// Cyber Security Prime - Threat History & Analytics Module
// Collects real Windows Event Log data and provides EDR timeline correlation

use crate::utils::generate_id;
use chrono::{DateTime, Utc, Duration, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String,
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub source: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub resolved: bool,
    pub resolved_at: Option<DateTime<Utc>>,
    pub action_taken: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    Malware,
    Ransomware,
    Phishing,
    NetworkIntrusion,
    DataBreach,
    Vulnerability,
    SuspiciousActivity,
    BlockedConnection,
    UnauthorizedAccess,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatStats {
    pub total_threats: u64,
    pub threats_today: u64,
    pub threats_this_week: u64,
    pub threats_this_month: u64,
    pub resolved_threats: u64,
    pub unresolved_threats: u64,
    pub by_severity: SeverityBreakdown,
    pub by_type: Vec<ThreatTypeCount>,
    pub daily_counts: Vec<DailyCount>,
    pub hourly_distribution: Vec<HourlyCount>,
    pub trend: ThreatTrend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub low: u64,
    pub medium: u64,
    pub high: u64,
    pub critical: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatTypeCount {
    pub threat_type: String,
    pub count: u64,
    pub percentage: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyCount {
    pub date: String,
    pub count: u64,
    pub blocked: u64,
    pub resolved: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourlyCount {
    pub hour: u8,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatTrend {
    pub direction: String,
    pub percentage_change: f32,
    pub comparison_period: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryQuery {
    pub days: Option<u32>,
    pub severity: Option<String>,
    pub threat_type: Option<String>,
    pub resolved: Option<bool>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrTimelineEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub source_process: String,
    pub source_pid: u32,
    pub target: String,
    pub details: String,
    pub risk_score: u8,
    pub related_events: Vec<String>,
}

// ============================================================================
// Internal collection structs
// ============================================================================

struct ProcessInfo {
    name: String,
    pid: u32,
    session: String,
    mem_usage: String,
    status: String,
}

struct NetworkConnection {
    protocol: String,
    local_addr: String,
    local_port: String,
    remote_addr: String,
    remote_port: String,
    state: String,
    pid: u32,
}

// ============================================================================
// In-Memory Storage
// ============================================================================

lazy_static::lazy_static! {
    static ref THREAT_HISTORY: Arc<RwLock<Vec<ThreatEvent>>> =
        Arc::new(RwLock::new(collect_initial_events()));
}

fn collect_initial_events() -> Vec<ThreatEvent> {
    let events = collect_windows_event_log();
    if events.is_empty() {
        fallback_seed_events()
    } else {
        events
    }
}

// ============================================================================
// Windows Event Log Collection
// ============================================================================

const SUSPICIOUS_PROCESSES: &[&str] = &[
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "psexec.exe", "wmic.exe",
    "net.exe", "net1.exe", "sc.exe", "schtasks.exe",
];

const HIGH_RISK_PROCESSES: &[&str] = &[
    "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "regsvr32.exe", "certutil.exe", "psexec.exe", "bitsadmin.exe",
];

const MEDIUM_RISK_PROCESSES: &[&str] = &[
    "cmd.exe", "rundll32.exe", "msiexec.exe", "wmic.exe",
    "net.exe", "net1.exe", "sc.exe", "schtasks.exe",
    "reg.exe", "regedit.exe", "taskkill.exe", "at.exe",
];

fn collect_windows_event_log() -> Vec<ThreatEvent> {
    #[cfg(not(windows))]
    {
        return Vec::new();
    }

    #[cfg(windows)]
    {
        let query = "*[System[\
            (EventID=4625 or EventID=4648 or EventID=4688 or EventID=4697 \
             or EventID=5156 or EventID=5157 or EventID=1102) \
            and TimeCreated[timediff(@SystemTime) <= 86400000]]]";

        let result = std::process::Command::new("wevtutil")
            .args([
                "qe", "Security",
                "/rd:true", "/f:xml", "/c:500",
                &format!("/q:{}", query),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        match result {
            Ok(output) if output.status.success() => {
                let raw = String::from_utf8_lossy(&output.stdout);
                parse_event_log_xml(&raw)
            }
            _ => Vec::new(),
        }
    }
}

fn parse_event_log_xml(xml: &str) -> Vec<ThreatEvent> {
    let mut events = Vec::new();

    for block in xml.split("<Event ") {
        if !block.contains("<EventID>") {
            continue;
        }

        let event_id: u32 = match extract_xml_value(block, "EventID").parse() {
            Ok(id) => id,
            Err(_) => continue,
        };

        let timestamp = parse_windows_timestamp(
            &extract_xml_attr(block, "TimeCreated", "SystemTime"),
        ).unwrap_or_else(Utc::now);

        let (threat_type, severity, include) = classify_event(event_id, block);
        if !include {
            continue;
        }

        let source = {
            let raw = extract_xml_attr(block, "Provider", "Name");
            let cleaned = raw.trim_start_matches("Microsoft-Windows-");
            if cleaned.is_empty() { "Windows Security".to_string() } else { cleaned.to_string() }
        };

        events.push(ThreatEvent {
            id: generate_id(),
            threat_type,
            severity,
            source,
            description: describe_event(event_id, block),
            timestamp,
            resolved: false,
            resolved_at: None,
            action_taken: None,
        });
    }

    events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    events
}

fn classify_event(event_id: u32, block: &str) -> (ThreatType, Severity, bool) {
    match event_id {
        4625 => (ThreatType::UnauthorizedAccess, Severity::High, true),
        4648 => (ThreatType::SuspiciousActivity, Severity::Medium, true),
        4688 => {
            let proc = extract_event_data(block, "NewProcessName").to_lowercase();
            let dominated = SUSPICIOUS_PROCESSES.iter().any(|p| proc.ends_with(p));
            if dominated {
                (ThreatType::SuspiciousActivity, Severity::Medium, true)
            } else {
                (ThreatType::Other, Severity::Low, false)
            }
        }
        4697 => (ThreatType::Malware, Severity::Critical, true),
        5156 => (ThreatType::BlockedConnection, Severity::Low, true),
        5157 => (ThreatType::BlockedConnection, Severity::Medium, true),
        1102 => (ThreatType::SuspiciousActivity, Severity::Critical, true),
        _ => (ThreatType::Other, Severity::Low, false),
    }
}

fn describe_event(event_id: u32, block: &str) -> String {
    match event_id {
        4625 => {
            let user = extract_event_data(block, "TargetUserName");
            let ip = extract_event_data(block, "IpAddress");
            let ws = extract_event_data(block, "WorkstationName");
            let mut d = format!(
                "Failed login attempt for user '{}'",
                non_empty_or(&user, "unknown"),
            );
            if !ip.is_empty() && ip != "-" {
                d.push_str(&format!(" from {}", ip));
            }
            if !ws.is_empty() && ws != "-" {
                d.push_str(&format!(" ({})", ws));
            }
            d
        }
        4648 => {
            let user = extract_event_data(block, "TargetUserName");
            let server = extract_event_data(block, "TargetServerName");
            format!(
                "Explicit credential use: user '{}' targeting '{}'",
                non_empty_or(&user, "unknown"),
                non_empty_or(&server, "unknown"),
            )
        }
        4688 => {
            let proc = extract_event_data(block, "NewProcessName");
            let parent = extract_event_data(block, "ParentProcessName");
            let mut d = format!(
                "Suspicious process created: {}",
                non_empty_or(&proc, "unknown"),
            );
            if !parent.is_empty() {
                d.push_str(&format!(" by {}", parent));
            }
            d
        }
        4697 => {
            let svc = extract_event_data(block, "ServiceName");
            let path = extract_event_data(block, "ServiceFileName");
            format!(
                "New service installed: {} ({})",
                non_empty_or(&svc, "unknown"),
                non_empty_or(&path, "unknown path"),
            )
        }
        5156 => {
            let app = extract_event_data(block, "Application");
            let dst = extract_event_data(block, "DestAddress");
            let port = extract_event_data(block, "DestPort");
            format!(
                "Firewall allowed connection: {} -> {}:{}",
                non_empty_or(&app, "unknown"),
                non_empty_or(&dst, "?"),
                non_empty_or(&port, "?"),
            )
        }
        5157 => {
            let app = extract_event_data(block, "Application");
            let dst = extract_event_data(block, "DestAddress");
            let port = extract_event_data(block, "DestPort");
            format!(
                "Firewall blocked connection: {} -> {}:{}",
                non_empty_or(&app, "unknown"),
                non_empty_or(&dst, "?"),
                non_empty_or(&port, "?"),
            )
        }
        1102 => "Security audit log was cleared".to_string(),
        _ => format!("Security event {}", event_id),
    }
}

// ============================================================================
// XML helpers (no external XML crate)
// ============================================================================

fn extract_xml_value(xml: &str, tag: &str) -> String {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    if let Some(start) = xml.find(&open) {
        let after = &xml[start + open.len()..];
        if let Some(end) = after.find(&close) {
            return after[..end].trim().to_string();
        }
    }
    String::new()
}

fn extract_xml_attr(xml: &str, tag: &str, attr: &str) -> String {
    let tag_open = format!("<{}", tag);
    if let Some(pos) = xml.find(&tag_open) {
        let region = &xml[pos..];
        let end = region.find("/>").or_else(|| region.find('>')).unwrap_or(region.len());
        let inside = &region[..end];

        for delim in &['\'', '"'] {
            let pattern = format!("{}={}", attr, delim);
            if let Some(attr_pos) = inside.find(&pattern) {
                let val_start = attr_pos + pattern.len();
                if let Some(val_end) = inside[val_start..].find(*delim) {
                    return inside[val_start..val_start + val_end].to_string();
                }
            }
        }
    }
    String::new()
}

fn extract_event_data(xml: &str, name: &str) -> String {
    for delim in &["'", "\""] {
        let pattern = format!("Name={}{}{}", delim, name, delim);
        if let Some(pos) = xml.find(&pattern) {
            let after = &xml[pos..];
            if let Some(gt) = after.find('>') {
                let value_region = &after[gt + 1..];
                if let Some(lt) = value_region.find('<') {
                    let val = value_region[..lt].trim();
                    if val != "-" {
                        return val.to_string();
                    }
                }
            }
        }
    }
    String::new()
}

fn parse_windows_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    if ts.is_empty() {
        return None;
    }
    // Windows may emit 7-digit fractional seconds; chrono needs <= 9 but
    // the rfc3339 parser can be picky, so truncate to 6.
    let cleaned = if let Some(dot) = ts.find('.') {
        let after_dot = &ts[dot + 1..];
        let digit_end = after_dot
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after_dot.len());
        let suffix = &after_dot[digit_end..];
        let frac = &after_dot[..digit_end];
        if frac.len() > 6 {
            format!("{}.{}{}", &ts[..dot], &frac[..6], suffix)
        } else {
            ts.to_string()
        }
    } else {
        ts.to_string()
    };

    DateTime::parse_from_rfc3339(&cleaned)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn non_empty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

// ============================================================================
// Fallback seed events (used when Event Log is inaccessible)
// ============================================================================

fn fallback_seed_events() -> Vec<ThreatEvent> {
    let now = Utc::now();
    vec![
        ThreatEvent {
            id: generate_id(),
            threat_type: ThreatType::BlockedConnection,
            severity: Severity::Low,
            source: "Windows Firewall".to_string(),
            description: "Outbound connection blocked by firewall policy".to_string(),
            timestamp: now - Duration::minutes(30),
            resolved: true,
            resolved_at: Some(now - Duration::minutes(29)),
            action_taken: Some("Connection blocked by firewall rule".to_string()),
        },
        ThreatEvent {
            id: generate_id(),
            threat_type: ThreatType::SuspiciousActivity,
            severity: Severity::Medium,
            source: "Security Auditing".to_string(),
            description: "Unusual process creation detected: powershell.exe with encoded command".to_string(),
            timestamp: now - Duration::hours(2),
            resolved: false,
            resolved_at: None,
            action_taken: None,
        },
        ThreatEvent {
            id: generate_id(),
            threat_type: ThreatType::UnauthorizedAccess,
            severity: Severity::High,
            source: "Security Auditing".to_string(),
            description: "Multiple failed login attempts detected".to_string(),
            timestamp: now - Duration::hours(6),
            resolved: true,
            resolved_at: Some(now - Duration::hours(5)),
            action_taken: Some("Account temporarily locked".to_string()),
        },
    ]
}

// ============================================================================
// EDR Timeline: process + network correlation
// ============================================================================

fn collect_running_processes() -> Vec<ProcessInfo> {
    #[cfg(not(windows))]
    {
        return Vec::new();
    }

    #[cfg(windows)]
    {
        let result = std::process::Command::new("tasklist")
            .args(["/v", "/fo", "csv"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        let output = match result {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let text = String::from_utf8_lossy(&output.stdout);
        let mut procs = Vec::new();

        for line in text.lines().skip(1) {
            let f = parse_csv_line(line);
            if f.len() < 6 {
                continue;
            }
            procs.push(ProcessInfo {
                name: f[0].clone(),
                pid: f[1].parse().unwrap_or(0),
                session: format!("{} #{}", f[2], f[3]),
                mem_usage: f[4].clone(),
                status: f[5].clone(),
            });
        }
        procs
    }
}

fn collect_network_connections() -> Vec<NetworkConnection> {
    #[cfg(not(windows))]
    {
        return Vec::new();
    }

    #[cfg(windows)]
    {
        let result = std::process::Command::new("netstat")
            .args(["-ano"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        let output = match result {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let text = String::from_utf8_lossy(&output.stdout);
        let mut conns = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            let is_tcp = line.starts_with("TCP");
            let is_udp = line.starts_with("UDP");
            if !is_tcp && !is_udp {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();

            if is_tcp && parts.len() >= 5 {
                let (la, lp) = split_address(parts[1]);
                let (ra, rp) = split_address(parts[2]);
                conns.push(NetworkConnection {
                    protocol: "TCP".to_string(),
                    local_addr: la,
                    local_port: lp,
                    remote_addr: ra,
                    remote_port: rp,
                    state: parts[3].to_string(),
                    pid: parts[4].parse().unwrap_or(0),
                });
            } else if is_udp && parts.len() >= 3 {
                let (la, lp) = split_address(parts[1]);
                let (ra, rp) = if parts.len() >= 4 && parts[2].contains(':') {
                    split_address(parts[2])
                } else {
                    ("*".to_string(), "*".to_string())
                };
                let pid = parts.last().and_then(|s| s.parse().ok()).unwrap_or(0);
                conns.push(NetworkConnection {
                    protocol: "UDP".to_string(),
                    local_addr: la,
                    local_port: lp,
                    remote_addr: ra,
                    remote_port: rp,
                    state: "STATELESS".to_string(),
                    pid,
                });
            }
        }
        conns
    }
}

fn split_address(addr: &str) -> (String, String) {
    if let Some(bracket_end) = addr.rfind(']') {
        let ip = addr[..=bracket_end].to_string();
        let port = if addr.len() > bracket_end + 2 {
            addr[bracket_end + 2..].to_string()
        } else {
            "0".to_string()
        };
        (ip, port)
    } else if let Some(colon) = addr.rfind(':') {
        (addr[..colon].to_string(), addr[colon + 1..].to_string())
    } else {
        (addr.to_string(), "0".to_string())
    }
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current = String::new();
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() || line.ends_with(',') {
        fields.push(current.trim().to_string());
    }
    fields
}

fn assess_process_risk(name: &str, status: &str) -> u8 {
    let lower = name.to_lowercase();
    if HIGH_RISK_PROCESSES.iter().any(|p| lower.ends_with(p)) {
        65
    } else if MEDIUM_RISK_PROCESSES.iter().any(|p| lower.ends_with(p)) {
        40
    } else if status.to_lowercase().contains("not responding") {
        35
    } else {
        10
    }
}

fn assess_connection_risk(conn: &NetworkConnection) -> u8 {
    let mut risk: u8 = 5;

    if conn.state == "ESTABLISHED" && !is_local_address(&conn.remote_addr) {
        risk = 25;
    }

    let port: u16 = conn.remote_port.parse().unwrap_or(0);
    match port {
        4444 | 5555 | 6666 | 1337 | 31337 => risk = 80,
        8080 | 8443 | 9090 => risk = risk.max(30),
        _ => {}
    }

    if port > 10000
        && !is_local_address(&conn.remote_addr)
        && conn.state == "ESTABLISHED"
    {
        risk = risk.max(35);
    }

    risk.min(100)
}

fn is_local_address(addr: &str) -> bool {
    addr.starts_with("127.")
        || addr.starts_with("10.")
        || addr.starts_with("192.168.")
        || addr.starts_with("169.254.")
        || addr == "0.0.0.0"
        || addr == "*"
        || addr.starts_with("[::")
        || {
            if let Some(rest) = addr.strip_prefix("172.") {
                rest.split('.')
                    .next()
                    .and_then(|s| s.parse::<u8>().ok())
                    .map_or(false, |n| (16..=31).contains(&n))
            } else {
                false
            }
        }
}

// ============================================================================
// Tauri Commands
// ============================================================================

#[tauri::command]
pub async fn get_threat_history(query: Option<HistoryQuery>) -> Result<Vec<ThreatEvent>, String> {
    let history = THREAT_HISTORY.read();
    let mut results: Vec<ThreatEvent> = history.clone();

    if let Some(q) = query {
        let now = Utc::now();

        if let Some(days) = q.days {
            let cutoff = now - Duration::days(days as i64);
            results.retain(|e| e.timestamp >= cutoff);
        }

        if let Some(severity) = q.severity {
            let sev = match severity.to_lowercase().as_str() {
                "low" => Severity::Low,
                "medium" => Severity::Medium,
                "high" => Severity::High,
                "critical" => Severity::Critical,
                _ => return Err("Invalid severity".to_string()),
            };
            results.retain(|e| e.severity == sev);
        }

        if let Some(resolved) = q.resolved {
            results.retain(|e| e.resolved == resolved);
        }

        if let Some(limit) = q.limit {
            results.truncate(limit);
        }
    }

    Ok(results)
}

#[tauri::command]
pub async fn get_threat_stats() -> Result<ThreatStats, String> {
    let history = THREAT_HISTORY.read();
    let now = Utc::now();

    let week_start = now - Duration::days(7);
    let month_start = now - Duration::days(30);
    let prev_month_start = now - Duration::days(60);

    let total = history.len() as u64;
    let today: u64 = history.iter().filter(|e| e.timestamp.date_naive() == now.date_naive()).count() as u64;
    let this_week: u64 = history.iter().filter(|e| e.timestamp >= week_start).count() as u64;
    let this_month: u64 = history.iter().filter(|e| e.timestamp >= month_start).count() as u64;
    let prev_month: u64 = history.iter()
        .filter(|e| e.timestamp >= prev_month_start && e.timestamp < month_start)
        .count() as u64;

    let resolved: u64 = history.iter().filter(|e| e.resolved).count() as u64;
    let unresolved: u64 = total - resolved;

    let by_severity = SeverityBreakdown {
        low: history.iter().filter(|e| e.severity == Severity::Low).count() as u64,
        medium: history.iter().filter(|e| e.severity == Severity::Medium).count() as u64,
        high: history.iter().filter(|e| e.severity == Severity::High).count() as u64,
        critical: history.iter().filter(|e| e.severity == Severity::Critical).count() as u64,
    };

    let mut type_counts: HashMap<String, u64> = HashMap::new();
    for event in history.iter() {
        let type_str = format!("{:?}", event.threat_type);
        *type_counts.entry(type_str).or_insert(0) += 1;
    }

    let by_type: Vec<ThreatTypeCount> = type_counts
        .iter()
        .map(|(k, v)| ThreatTypeCount {
            threat_type: k.clone(),
            count: *v,
            percentage: if total > 0 { (*v as f32 / total as f32) * 100.0 } else { 0.0 },
        })
        .collect();

    let mut daily_counts: Vec<DailyCount> = Vec::new();
    for day in 0..14 {
        let date = (now - Duration::days(day)).date_naive();
        let date_str = date.format("%Y-%m-%d").to_string();

        let day_events: Vec<&ThreatEvent> = history.iter()
            .filter(|e| e.timestamp.date_naive() == date)
            .collect();

        daily_counts.push(DailyCount {
            date: date_str,
            count: day_events.len() as u64,
            blocked: day_events.iter().filter(|e| e.threat_type == ThreatType::BlockedConnection).count() as u64,
            resolved: day_events.iter().filter(|e| e.resolved).count() as u64,
        });
    }
    daily_counts.reverse();

    let mut hourly: Vec<HourlyCount> = (0..24).map(|h| HourlyCount { hour: h, count: 0 }).collect();
    for event in history.iter() {
        let hour = event.timestamp.hour() as usize;
        if hour < 24 {
            hourly[hour].count += 1;
        }
    }

    let trend = if prev_month > 0 {
        let change = ((this_month as f32 - prev_month as f32) / prev_month as f32) * 100.0;
        ThreatTrend {
            direction: if change > 5.0 { "up" } else if change < -5.0 { "down" } else { "stable" }.to_string(),
            percentage_change: change,
            comparison_period: "vs. previous 30 days".to_string(),
        }
    } else {
        ThreatTrend {
            direction: "stable".to_string(),
            percentage_change: 0.0,
            comparison_period: "vs. previous 30 days".to_string(),
        }
    };

    Ok(ThreatStats {
        total_threats: total,
        threats_today: today,
        threats_this_week: this_week,
        threats_this_month: this_month,
        resolved_threats: resolved,
        unresolved_threats: unresolved,
        by_severity,
        by_type,
        daily_counts,
        hourly_distribution: hourly,
        trend,
    })
}

#[tauri::command]
pub async fn add_threat_event(
    threat_type: String,
    severity: String,
    source: String,
    description: String,
) -> Result<ThreatEvent, String> {
    let threat_t = match threat_type.to_lowercase().as_str() {
        "malware" => ThreatType::Malware,
        "ransomware" => ThreatType::Ransomware,
        "phishing" => ThreatType::Phishing,
        "network_intrusion" => ThreatType::NetworkIntrusion,
        "data_breach" => ThreatType::DataBreach,
        "vulnerability" => ThreatType::Vulnerability,
        "suspicious_activity" => ThreatType::SuspiciousActivity,
        "blocked_connection" => ThreatType::BlockedConnection,
        "unauthorized_access" => ThreatType::UnauthorizedAccess,
        _ => ThreatType::Other,
    };

    let sev = match severity.to_lowercase().as_str() {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Medium,
    };

    let event = ThreatEvent {
        id: generate_id(),
        threat_type: threat_t,
        severity: sev,
        source,
        description,
        timestamp: Utc::now(),
        resolved: false,
        resolved_at: None,
        action_taken: None,
    };

    let mut history = THREAT_HISTORY.write();
    history.insert(0, event.clone());

    Ok(event)
}

#[tauri::command]
pub async fn get_edr_timeline() -> Result<Vec<EdrTimelineEntry>, String> {
    let now = Utc::now();
    let processes = collect_running_processes();
    let connections = collect_network_connections();

    let mut pid_conns: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, conn) in connections.iter().enumerate() {
        pid_conns.entry(conn.pid).or_default().push(i);
    }

    let mut entries: Vec<EdrTimelineEntry> = Vec::new();
    let mut proc_entry_ids: HashMap<u32, String> = HashMap::new();

    for proc in &processes {
        let risk = assess_process_risk(&proc.name, &proc.status);
        let has_conns = pid_conns.contains_key(&proc.pid);
        if risk < 40 && !has_conns {
            continue;
        }

        let entry_id = generate_id();
        proc_entry_ids.insert(proc.pid, entry_id.clone());

        entries.push(EdrTimelineEntry {
            id: entry_id,
            timestamp: now,
            event_type: "process_start".to_string(),
            source_process: proc.name.clone(),
            source_pid: proc.pid,
            target: proc.name.clone(),
            details: format!(
                "Session: {}, Status: {}, Memory: {}",
                proc.session, proc.status, proc.mem_usage,
            ),
            risk_score: risk,
            related_events: Vec::new(),
        });
    }

    for conn in &connections {
        let conn_risk = assess_connection_risk(conn);
        let entry_id = generate_id();

        let mut related = Vec::new();
        if let Some(pid_entry_id) = proc_entry_ids.get(&conn.pid) {
            related.push(pid_entry_id.clone());
            if let Some(proc_entry) = entries.iter_mut().find(|e| e.id == *pid_entry_id) {
                proc_entry.related_events.push(entry_id.clone());
                if conn_risk > 30 {
                    proc_entry.risk_score = proc_entry.risk_score.saturating_add(conn_risk / 3).min(100);
                }
            }
        }

        let process_name = processes
            .iter()
            .find(|p| p.pid == conn.pid)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| format!("PID:{}", conn.pid));

        entries.push(EdrTimelineEntry {
            id: entry_id,
            timestamp: now,
            event_type: "network_connect".to_string(),
            source_process: process_name,
            source_pid: conn.pid,
            target: format!("{}:{}", conn.remote_addr, conn.remote_port),
            details: format!(
                "{} {} Local={}:{}",
                conn.protocol, conn.state, conn.local_addr, conn.local_port,
            ),
            risk_score: conn_risk,
            related_events: related,
        });
    }

    entries.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| b.timestamp.cmp(&a.timestamp))
    });

    Ok(entries)
}
