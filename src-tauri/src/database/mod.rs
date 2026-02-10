// Cyber Security Prime - Database Module
// SQLite persistence for scan history, threats, settings, and licensing

use rusqlite::{Connection, Result as SqliteResult, params};
use std::path::PathBuf;
use std::sync::Arc;
use parking_lot::Mutex;
use once_cell::sync::Lazy;
use chrono::{DateTime, Utc};

pub mod models;
pub mod queries;

use models::*;

// Global database connection
static DB_CONNECTION: Lazy<Arc<Mutex<Option<Connection>>>> = Lazy::new(|| {
    Arc::new(Mutex::new(None))
});

/// Get the database file path
fn get_db_path() -> PathBuf {
    let app_data = std::env::var("APPDATA")
        .unwrap_or_else(|_| ".".to_string());
    let db_dir = PathBuf::from(app_data).join("SecurityPrime");
    std::fs::create_dir_all(&db_dir).ok();
    db_dir.join("security_prime.db")
}

/// Initialize the database connection and run migrations
pub fn initialize_database() -> SqliteResult<()> {
    let db_path = get_db_path();
    let conn = Connection::open(&db_path)?;
    
    // Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON", [])?;
    
    // Run migrations
    run_migrations(&conn)?;
    
    // Store connection globally
    let mut db_lock = DB_CONNECTION.lock();
    *db_lock = Some(conn);
    
    Ok(())
}

/// Get a reference to the database connection
pub fn get_connection() -> Arc<Mutex<Option<Connection>>> {
    Arc::clone(&DB_CONNECTION)
}

/// Run database migrations
fn run_migrations(conn: &Connection) -> SqliteResult<()> {
    // Create migrations table if not exists
    conn.execute(
        "CREATE TABLE IF NOT EXISTS migrations (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    // Define migrations
    let migrations = vec![
        ("001_initial_schema", include_str!("migrations/001_initial_schema.sql")),
        ("002_license_table", include_str!("migrations/002_license_table.sql")),
        ("003_activity_log", include_str!("migrations/003_activity_log.sql")),
    ];

    for (name, sql) in migrations {
        // Check if migration already applied
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM migrations WHERE name = ?)",
            [name],
            |row| row.get(0),
        )?;

        if !exists {
            // Execute migration
            conn.execute_batch(sql)?;
            
            // Record migration
            conn.execute(
                "INSERT INTO migrations (name) VALUES (?)",
                [name],
            )?;
            
            println!("Applied migration: {}", name);
        }
    }

    Ok(())
}

// ============================================================================
// Scan Operations
// ============================================================================

/// Insert a new scan record
pub fn insert_scan(scan: &ScanRecord) -> SqliteResult<()> {
    let db_lock = DB_CONNECTION.lock();
    if let Some(conn) = db_lock.as_ref() {
        conn.execute(
            "INSERT INTO scans (id, scan_type, status, started_at, completed_at, threats_found, files_scanned)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                scan.id,
                scan.scan_type,
                scan.status,
                scan.started_at.to_rfc3339(),
                scan.completed_at.map(|dt| dt.to_rfc3339()),
                scan.threats_found,
                scan.files_scanned,
            ],
        )?;
    }
    Ok(())
}

/// Update scan status
pub fn update_scan_status(scan_id: &str, status: &str, threats_found: i32, files_scanned: i64) -> SqliteResult<()> {
    let db_lock = DB_CONNECTION.lock();
    if let Some(conn) = db_lock.as_ref() {
        conn.execute(
            "UPDATE scans SET status = ?1, threats_found = ?2, files_scanned = ?3, 
             completed_at = CASE WHEN ?1 IN ('completed', 'failed', 'cancelled') THEN datetime('now') ELSE completed_at END
             WHERE id = ?4",
            params![status, threats_found, files_scanned, scan_id],
        )?;
    }
    Ok(())
}

/// Get recent scans
pub fn get_recent_scans(limit: i32) -> SqliteResult<Vec<ScanRecord>> {
    let db_lock = DB_CONNECTION.lock();
    let mut scans = Vec::new();
    
    if let Some(conn) = db_lock.as_ref() {
        let mut stmt = conn.prepare(
            "SELECT id, scan_type, status, started_at, completed_at, threats_found, files_scanned 
             FROM scans ORDER BY started_at DESC LIMIT ?1"
        )?;
        
        let scan_iter = stmt.query_map([limit], |row| {
            Ok(ScanRecord {
                id: row.get(0)?,
                scan_type: row.get(1)?,
                status: row.get(2)?,
                started_at: parse_datetime(row.get::<_, String>(3)?),
                completed_at: row.get::<_, Option<String>>(4)?.map(parse_datetime),
                threats_found: row.get(5)?,
                files_scanned: row.get(6)?,
            })
        })?;
        
        for scan in scan_iter {
            scans.push(scan?);
        }
    }
    
    Ok(scans)
}

// ============================================================================
// Threat Operations
// ============================================================================

/// Insert a threat record
pub fn insert_threat(threat: &ThreatRecord) -> SqliteResult<()> {
    let db_lock = DB_CONNECTION.lock();
    if let Some(conn) = db_lock.as_ref() {
        conn.execute(
            "INSERT INTO threats (id, scan_id, name, severity, file_path, detected_at, status, action_taken)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                threat.id,
                threat.scan_id,
                threat.name,
                threat.severity,
                threat.file_path,
                threat.detected_at.to_rfc3339(),
                threat.status,
                threat.action_taken,
            ],
        )?;
    }
    Ok(())
}

/// Update threat status
pub fn update_threat_status(threat_id: &str, status: &str, action_taken: Option<&str>) -> SqliteResult<()> {
    let db_lock = DB_CONNECTION.lock();
    if let Some(conn) = db_lock.as_ref() {
        conn.execute(
            "UPDATE threats SET status = ?1, action_taken = ?2 WHERE id = ?3",
            params![status, action_taken, threat_id],
        )?;
    }
    Ok(())
}

/// Get threats by scan ID
pub fn get_threats_by_scan(scan_id: &str) -> SqliteResult<Vec<ThreatRecord>> {
    let db_lock = DB_CONNECTION.lock();
    let mut threats = Vec::new();
    
    if let Some(conn) = db_lock.as_ref() {
        let mut stmt = conn.prepare(
            "SELECT id, scan_id, name, severity, file_path, detected_at, status, action_taken 
             FROM threats WHERE scan_id = ?1 ORDER BY detected_at DESC"
        )?;
        
        let threat_iter = stmt.query_map([scan_id], |row| {
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
        })?;
        
        for threat in threat_iter {
            threats.push(threat?);
        }
    }
    
    Ok(threats)
}

/// Get all unresolved threats
pub fn get_unresolved_threats() -> SqliteResult<Vec<ThreatRecord>> {
    let db_lock = DB_CONNECTION.lock();
    let mut threats = Vec::new();
    
    if let Some(conn) = db_lock.as_ref() {
        let mut stmt = conn.prepare(
            "SELECT id, scan_id, name, severity, file_path, detected_at, status, action_taken 
             FROM threats WHERE status NOT IN ('resolved', 'quarantined', 'deleted') 
             ORDER BY detected_at DESC"
        )?;
        
        let threat_iter = stmt.query_map([], |row| {
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
        })?;
        
        for threat in threat_iter {
            threats.push(threat?);
        }
    }
    
    Ok(threats)
}

// ============================================================================
// Settings Operations
// ============================================================================

/// Get a setting value
pub fn get_setting(key: &str) -> SqliteResult<Option<String>> {
    let db_lock = DB_CONNECTION.lock();
    
    if let Some(conn) = db_lock.as_ref() {
        let result = conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            [key],
            |row| row.get(0),
        );
        
        match result {
            Ok(value) => return Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    
    Ok(None)
}

/// Set a setting value
pub fn set_setting(key: &str, value: &str) -> SqliteResult<()> {
    let db_lock = DB_CONNECTION.lock();
    if let Some(conn) = db_lock.as_ref() {
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, datetime('now'))",
            params![key, value],
        )?;
    }
    Ok(())
}

/// Get all settings
pub fn get_all_settings() -> SqliteResult<std::collections::HashMap<String, String>> {
    let db_lock = DB_CONNECTION.lock();
    let mut settings = std::collections::HashMap::new();
    
    if let Some(conn) = db_lock.as_ref() {
        let mut stmt = conn.prepare("SELECT key, value FROM settings")?;
        let setting_iter = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        
        for setting in setting_iter {
            let (key, value) = setting?;
            settings.insert(key, value);
        }
    }
    
    Ok(settings)
}

// ============================================================================
// Activity Log Operations
// ============================================================================

/// Insert an activity log entry
pub fn insert_activity(activity: &ActivityRecord) -> SqliteResult<()> {
    let db_lock = DB_CONNECTION.lock();
    if let Some(conn) = db_lock.as_ref() {
        conn.execute(
            "INSERT INTO activity_log (id, event_type, title, description, severity, module, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                activity.id,
                activity.event_type,
                activity.title,
                activity.description,
                activity.severity,
                activity.module,
                activity.timestamp.to_rfc3339(),
            ],
        )?;
    }
    Ok(())
}

/// Get recent activity
pub fn get_recent_activity(limit: i32) -> SqliteResult<Vec<ActivityRecord>> {
    let db_lock = DB_CONNECTION.lock();
    let mut activities = Vec::new();
    
    if let Some(conn) = db_lock.as_ref() {
        let mut stmt = conn.prepare(
            "SELECT id, event_type, title, description, severity, module, timestamp 
             FROM activity_log ORDER BY timestamp DESC LIMIT ?1"
        )?;
        
        let activity_iter = stmt.query_map([limit], |row| {
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
        
        for activity in activity_iter {
            activities.push(activity?);
        }
    }
    
    Ok(activities)
}

// ============================================================================
// License Operations
// ============================================================================

/// Get stored license
pub fn get_license() -> SqliteResult<Option<LicenseRecord>> {
    let db_lock = DB_CONNECTION.lock();
    
    if let Some(conn) = db_lock.as_ref() {
        let result = conn.query_row(
            "SELECT id, license_key, organization_id, organization_name, activated_at, expires_at, endpoint_id, max_endpoints, features
             FROM license WHERE id = 1",
            [],
            |row| {
                Ok(LicenseRecord {
                    id: row.get(0)?,
                    license_key: row.get(1)?,
                    organization_id: row.get(2)?,
                    organization_name: row.get(3)?,
                    activated_at: row.get::<_, Option<String>>(4)?.map(parse_datetime),
                    expires_at: row.get::<_, Option<String>>(5)?.map(parse_datetime),
                    endpoint_id: row.get(6)?,
                    max_endpoints: row.get(7)?,
                    features: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
                })
            },
        );
        
        match result {
            Ok(license) => return Ok(Some(license)),
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    
    Ok(None)
}

/// Store or update license
pub fn store_license(license: &LicenseRecord) -> SqliteResult<()> {
    let db_lock = DB_CONNECTION.lock();
    if let Some(conn) = db_lock.as_ref() {
        conn.execute(
            "INSERT OR REPLACE INTO license (id, license_key, organization_id, organization_name, activated_at, expires_at, endpoint_id, max_endpoints, features)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                license.license_key,
                license.organization_id,
                license.organization_name,
                license.activated_at.map(|dt| dt.to_rfc3339()),
                license.expires_at.map(|dt| dt.to_rfc3339()),
                license.endpoint_id,
                license.max_endpoints,
                license.features,
            ],
        )?;
    }
    Ok(())
}

/// Clear license
pub fn clear_license() -> SqliteResult<()> {
    let db_lock = DB_CONNECTION.lock();
    if let Some(conn) = db_lock.as_ref() {
        conn.execute("DELETE FROM license", [])?;
    }
    Ok(())
}

// ============================================================================
// Statistics
// ============================================================================

/// Get threat statistics
pub fn get_threat_stats() -> SqliteResult<ThreatStats> {
    let db_lock = DB_CONNECTION.lock();
    
    if let Some(conn) = db_lock.as_ref() {
        let total: i32 = conn.query_row(
            "SELECT COUNT(*) FROM threats",
            [],
            |row| row.get(0),
        )?;
        
        let today: i32 = conn.query_row(
            "SELECT COUNT(*) FROM threats WHERE date(detected_at) = date('now')",
            [],
            |row| row.get(0),
        )?;
        
        let this_week: i32 = conn.query_row(
            "SELECT COUNT(*) FROM threats WHERE detected_at >= datetime('now', '-7 days')",
            [],
            |row| row.get(0),
        )?;
        
        let unresolved: i32 = conn.query_row(
            "SELECT COUNT(*) FROM threats WHERE status NOT IN ('resolved', 'quarantined', 'deleted')",
            [],
            |row| row.get(0),
        )?;
        
        let by_severity = get_threats_by_severity(conn)?;
        
        return Ok(ThreatStats {
            total_threats: total,
            threats_today: today,
            threats_this_week: this_week,
            unresolved_threats: unresolved,
            by_severity,
        });
    }
    
    Ok(ThreatStats::default())
}

fn get_threats_by_severity(conn: &Connection) -> SqliteResult<std::collections::HashMap<String, i32>> {
    let mut result = std::collections::HashMap::new();
    let mut stmt = conn.prepare(
        "SELECT severity, COUNT(*) FROM threats GROUP BY severity"
    )?;
    
    let iter = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
    })?;
    
    for item in iter {
        let (severity, count) = item?;
        result.insert(severity, count);
    }
    
    Ok(result)
}

// ============================================================================
// Helpers
// ============================================================================

pub fn parse_datetime(s: String) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}
