-- Initial database schema for SecurityPrime
-- Creates core tables for scans, threats, and settings

-- Scan history table
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at DATETIME,
    completed_at DATETIME,
    threats_found INTEGER DEFAULT 0,
    files_scanned INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Threats table
CREATE TABLE IF NOT EXISTS threats (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    file_path TEXT,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'detected',
    action_taken TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

-- Settings table
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);
CREATE INDEX IF NOT EXISTS idx_threats_scan_id ON threats(scan_id);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at);
CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);

-- Insert default settings
INSERT OR IGNORE INTO settings (key, value) VALUES ('theme', 'dark');
INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_start', 'false');
INSERT OR IGNORE INTO settings (key, value) VALUES ('real_time_protection', 'true');
INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_update', 'true');
INSERT OR IGNORE INTO settings (key, value) VALUES ('notifications_enabled', 'true');
INSERT OR IGNORE INTO settings (key, value) VALUES ('scan_on_startup', 'false');
