// Cyber Security Prime - Database Queries
// Common query patterns and helpers

use super::models::*;
use super::{get_connection, parse_datetime};
use chrono::{DateTime, Utc};
use rusqlite::{params, Result as SqliteResult};

/// Get scan count by status
pub fn get_scan_count_by_status(status: &str) -> SqliteResult<i32> {
    let db_lock = get_connection();
    let lock = db_lock.lock();
    
    if let Some(conn) = lock.as_ref() {
        let count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM scans WHERE status = ?1",
            [status],
            |row| row.get(0),
        )?;
        return Ok(count);
    }
    
    Ok(0)
}

/// Get threats detected in a date range
pub fn get_threats_in_range(start: DateTime<Utc>, end: DateTime<Utc>) -> SqliteResult<Vec<ThreatRecord>> {
    let db_lock = get_connection();
    let lock = db_lock.lock();
    let mut threats = Vec::new();
    
    if let Some(conn) = lock.as_ref() {
        let mut stmt = conn.prepare(
            "SELECT id, scan_id, name, severity, file_path, detected_at, status, action_taken 
             FROM threats 
             WHERE detected_at BETWEEN ?1 AND ?2
             ORDER BY detected_at DESC"
        )?;
        
        let threat_iter = stmt.query_map(
            params![start.to_rfc3339(), end.to_rfc3339()],
            |row| {
                Ok(ThreatRecord {
                    id: row.get(0)?,
                    scan_id: row.get(1)?,
                    name: row.get(2)?,
                    severity: row.get(3)?,
                    file_path: row.get(4)?,
                    detected_at: parse_datetime(row.get::<_, String>(5)?),
                    status: row.get(6)?,
                    action_taken: row.get(7)?,
                })
            },
        )?;
        
        for threat in threat_iter {
            threats.push(threat?);
        }
    }
    
    Ok(threats)
}

/// Get daily threat counts for the last N days
pub fn get_daily_threat_counts(days: i32) -> SqliteResult<Vec<(String, i32)>> {
    let db_lock = get_connection();
    let lock = db_lock.lock();
    let mut counts = Vec::new();
    
    if let Some(conn) = lock.as_ref() {
        let mut stmt = conn.prepare(
            "SELECT date(detected_at) as day, COUNT(*) as count 
             FROM threats 
             WHERE detected_at >= datetime('now', ?1)
             GROUP BY day
             ORDER BY day ASC"
        )?;
        
        let days_param = format!("-{} days", days);
        let iter = stmt.query_map([days_param], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
        })?;
        
        for item in iter {
            counts.push(item?);
        }
    }
    
    Ok(counts)
}

/// Get activity log by module
pub fn get_activity_by_module(module: &str, limit: i32) -> SqliteResult<Vec<ActivityRecord>> {
    let db_lock = get_connection();
    let lock = db_lock.lock();
    let mut activities = Vec::new();
    
    if let Some(conn) = lock.as_ref() {
        let mut stmt = conn.prepare(
            "SELECT id, event_type, title, description, severity, module, timestamp 
             FROM activity_log 
             WHERE module = ?1
             ORDER BY timestamp DESC 
             LIMIT ?2"
        )?;
        
        let iter = stmt.query_map(params![module, limit], |row| {
            Ok(ActivityRecord {
                id: row.get(0)?,
                event_type: row.get(1)?,
                title: row.get(2)?,
                description: row.get(3)?,
                severity: row.get(4)?,
                module: row.get(5)?,
                timestamp: parse_datetime(row.get::<_, String>(6)?),
            })
        })?;
        
        for activity in iter {
            activities.push(activity?);
        }
    }
    
    Ok(activities)
}

/// Get security score components from recent data
pub fn calculate_security_score() -> SqliteResult<SecurityScoreComponents> {
    let db_lock = get_connection();
    let lock = db_lock.lock();
    
    if let Some(conn) = lock.as_ref() {
        // Get recent threat count (lower is better)
        let recent_threats: i32 = conn.query_row(
            "SELECT COUNT(*) FROM threats WHERE detected_at >= datetime('now', '-7 days')",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        
        // Get unresolved threats (lower is better)
        let unresolved: i32 = conn.query_row(
            "SELECT COUNT(*) FROM threats WHERE status NOT IN ('resolved', 'quarantined', 'deleted')",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        
        // Get critical threats (much lower is better)
        let critical_threats: i32 = conn.query_row(
            "SELECT COUNT(*) FROM threats WHERE severity = 'critical' AND status NOT IN ('resolved', 'quarantined', 'deleted')",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        
        // Get last scan time
        let last_scan: Option<String> = conn.query_row(
            "SELECT MAX(started_at) FROM scans WHERE status = 'completed'",
            [],
            |row| row.get(0),
        ).unwrap_or(None);
        
        // Calculate scores
        let threat_score = (100 - (recent_threats * 5).min(50)).max(0);
        let resolution_score = if unresolved > 0 { 100 - (unresolved * 10).min(40) } else { 100 };
        let critical_score = if critical_threats > 0 { 100 - (critical_threats * 25).min(75) } else { 100 };
        
        // Scan recency score
        let scan_score = if let Some(last) = last_scan {
            let last_dt = parse_datetime(last);
            let hours_since = (Utc::now() - last_dt).num_hours();
            if hours_since < 24 { 100 }
            else if hours_since < 72 { 80 }
            else if hours_since < 168 { 60 }
            else { 40 }
        } else {
            30 // Never scanned
        };
        
        return Ok(SecurityScoreComponents {
            threat_score,
            resolution_score,
            critical_score,
            scan_score,
        });
    }
    
    Ok(SecurityScoreComponents::default())
}

/// Security score components
#[derive(Debug, Clone, Default)]
pub struct SecurityScoreComponents {
    pub threat_score: i32,
    pub resolution_score: i32,
    pub critical_score: i32,
    pub scan_score: i32,
}

impl SecurityScoreComponents {
    pub fn overall_score(&self) -> i32 {
        // Weighted average
        let weighted = (self.threat_score * 30 + 
                       self.resolution_score * 25 + 
                       self.critical_score * 30 + 
                       self.scan_score * 15) / 100;
        weighted.max(0).min(100)
    }
    
    pub fn grade(&self) -> String {
        let score = self.overall_score();
        match score {
            90..=100 => "A".to_string(),
            80..=89 => "B".to_string(),
            70..=79 => "C".to_string(),
            60..=69 => "D".to_string(),
            _ => "F".to_string(),
        }
    }
}

/// Cleanup old records
pub fn cleanup_old_records(days: i32) -> SqliteResult<i32> {
    let db_lock = get_connection();
    let lock = db_lock.lock();
    let mut deleted = 0;
    
    if let Some(conn) = lock.as_ref() {
        let days_param = format!("-{} days", days);
        
        // Clean old activity logs
        deleted += conn.execute(
            "DELETE FROM activity_log WHERE timestamp < datetime('now', ?1)",
            [&days_param],
        )?;
        
        // Clean old resolved threats
        deleted += conn.execute(
            "DELETE FROM threats WHERE status IN ('resolved', 'deleted') AND detected_at < datetime('now', ?1)",
            [&days_param],
        )?;
        
        // Clean old completed scans
        deleted += conn.execute(
            "DELETE FROM scans WHERE status = 'completed' AND completed_at < datetime('now', ?1)",
            [&days_param],
        )?;
    }
    
    Ok(deleted as i32)
}
