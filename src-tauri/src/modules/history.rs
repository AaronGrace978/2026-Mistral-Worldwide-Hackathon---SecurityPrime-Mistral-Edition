// Cyber Security Prime - Threat History & Analytics Module
// Provides historical threat data for charts and analysis

use crate::utils::generate_id;
use chrono::{DateTime, Utc, Duration, Datelike, Timelike};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use parking_lot::RwLock;

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
    pub direction: String, // "up", "down", "stable"
    pub percentage_change: f32,
    pub comparison_period: String,
}

// ============================================================================
// In-Memory Storage (would use SQLite in production)
// ============================================================================

lazy_static::lazy_static! {
    static ref THREAT_HISTORY: Arc<RwLock<Vec<ThreatEvent>>> = Arc::new(RwLock::new(generate_sample_history()));
}

fn generate_sample_history() -> Vec<ThreatEvent> {
    let now = Utc::now();
    let mut events = Vec::new();
    
    // Generate realistic historical data for the past 30 days
    let threat_types = vec![
        (ThreatType::BlockedConnection, Severity::Low, "Firewall"),
        (ThreatType::SuspiciousActivity, Severity::Medium, "Network Monitor"),
        (ThreatType::Malware, Severity::High, "Scanner"),
        (ThreatType::Phishing, Severity::Medium, "Web Protection"),
        (ThreatType::Vulnerability, Severity::High, "Vulnerability Scanner"),
        (ThreatType::NetworkIntrusion, Severity::Critical, "Firewall"),
        (ThreatType::UnauthorizedAccess, Severity::High, "Access Monitor"),
    ];
    
    // Generate events with realistic distribution
    for day in 0..30 {
        let date = now - Duration::days(day);
        
        // More events on weekdays, fewer on weekends
        let base_count = if date.weekday().num_days_from_monday() < 5 { 8 } else { 3 };
        let event_count = base_count + (day % 5) as i32;
        
        for i in 0..event_count {
            let (threat_type, severity, source) = &threat_types[i as usize % threat_types.len()];
            let hour = (i * 3 + day as i32) % 24;
            let event_time = date
                .with_hour(hour as u32).unwrap_or(date)
                .with_minute((i * 17) as u32 % 60).unwrap_or(date);
            
            let resolved = day > 0 || i < event_count / 2;
            
            events.push(ThreatEvent {
                id: generate_id(),
                threat_type: threat_type.clone(),
                severity: severity.clone(),
                source: source.to_string(),
                description: get_threat_description(threat_type),
                timestamp: event_time,
                resolved,
                resolved_at: if resolved { Some(event_time + Duration::hours(1)) } else { None },
                action_taken: if resolved { Some("Automatically blocked and quarantined".to_string()) } else { None },
            });
        }
    }
    
    // Sort by timestamp descending
    events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    events
}

fn get_threat_description(threat_type: &ThreatType) -> String {
    match threat_type {
        ThreatType::Malware => "Potential malware detected in downloaded file".to_string(),
        ThreatType::Ransomware => "Ransomware-like behavior detected".to_string(),
        ThreatType::Phishing => "Phishing attempt blocked".to_string(),
        ThreatType::NetworkIntrusion => "Unauthorized network access attempt".to_string(),
        ThreatType::DataBreach => "Potential data exfiltration detected".to_string(),
        ThreatType::Vulnerability => "Security vulnerability identified".to_string(),
        ThreatType::SuspiciousActivity => "Unusual system behavior detected".to_string(),
        ThreatType::BlockedConnection => "Suspicious outbound connection blocked".to_string(),
        ThreatType::UnauthorizedAccess => "Failed authentication attempt".to_string(),
        ThreatType::Other => "Security event detected".to_string(),
    }
}

// ============================================================================
// Tauri Commands
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryQuery {
    pub days: Option<u32>,
    pub severity: Option<String>,
    pub threat_type: Option<String>,
    pub resolved: Option<bool>,
    pub limit: Option<usize>,
}

/// Get threat history with optional filters
#[tauri::command]
pub async fn get_threat_history(query: Option<HistoryQuery>) -> Result<Vec<ThreatEvent>, String> {
    let history = THREAT_HISTORY.read();
    let mut results: Vec<ThreatEvent> = history.clone();
    
    if let Some(q) = query {
        let now = Utc::now();
        
        // Filter by days
        if let Some(days) = q.days {
            let cutoff = now - Duration::days(days as i64);
            results.retain(|e| e.timestamp >= cutoff);
        }
        
        // Filter by severity
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
        
        // Filter by resolved status
        if let Some(resolved) = q.resolved {
            results.retain(|e| e.resolved == resolved);
        }
        
        // Apply limit
        if let Some(limit) = q.limit {
            results.truncate(limit);
        }
    }
    
    Ok(results)
}

/// Get aggregated threat statistics
#[tauri::command]
pub async fn get_threat_stats() -> Result<ThreatStats, String> {
    let history = THREAT_HISTORY.read();
    let now = Utc::now();
    
    let today_start = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
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
    
    // Severity breakdown
    let by_severity = SeverityBreakdown {
        low: history.iter().filter(|e| e.severity == Severity::Low).count() as u64,
        medium: history.iter().filter(|e| e.severity == Severity::Medium).count() as u64,
        high: history.iter().filter(|e| e.severity == Severity::High).count() as u64,
        critical: history.iter().filter(|e| e.severity == Severity::Critical).count() as u64,
    };
    
    // Type breakdown
    let mut type_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for event in history.iter() {
        let type_str = format!("{:?}", event.threat_type);
        *type_counts.entry(type_str).or_insert(0) += 1;
    }
    
    let by_type: Vec<ThreatTypeCount> = type_counts.iter()
        .map(|(k, v)| ThreatTypeCount {
            threat_type: k.clone(),
            count: *v,
            percentage: (*v as f32 / total as f32) * 100.0,
        })
        .collect();
    
    // Daily counts for the past 14 days
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
            blocked: day_events.iter().filter(|e| 
                e.threat_type == ThreatType::BlockedConnection
            ).count() as u64,
            resolved: day_events.iter().filter(|e| e.resolved).count() as u64,
        });
    }
    daily_counts.reverse();
    
    // Hourly distribution
    let mut hourly: Vec<HourlyCount> = (0..24).map(|h| HourlyCount { hour: h, count: 0 }).collect();
    for event in history.iter() {
        let hour = event.timestamp.hour() as usize;
        hourly[hour].count += 1;
    }
    
    // Trend calculation
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

/// Add a new threat event (for real-time updates)
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

