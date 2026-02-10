-- Activity log table for tracking all security events
-- Provides audit trail and recent activity display

CREATE TABLE IF NOT EXISTS activity_log (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT DEFAULT 'low',
    module TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT
);

-- Firewall rules tracking
CREATE TABLE IF NOT EXISTS firewall_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    direction TEXT NOT NULL,
    action TEXT NOT NULL,
    protocol TEXT DEFAULT 'any',
    local_port TEXT,
    remote_port TEXT,
    remote_address TEXT,
    application TEXT,
    description TEXT,
    is_custom BOOLEAN DEFAULT true,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Network connections log (for historical analysis)
CREATE TABLE IF NOT EXISTS network_connections_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    process_name TEXT,
    process_id INTEGER,
    local_address TEXT,
    local_port INTEGER,
    remote_address TEXT,
    remote_port INTEGER,
    protocol TEXT,
    state TEXT,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_suspicious BOOLEAN DEFAULT false,
    notes TEXT
);

-- Encrypted files registry
CREATE TABLE IF NOT EXISTS encrypted_files (
    id TEXT PRIMARY KEY,
    original_name TEXT NOT NULL,
    original_path TEXT NOT NULL,
    encrypted_path TEXT NOT NULL,
    original_size INTEGER,
    encrypted_size INTEGER,
    algorithm TEXT DEFAULT 'AES-256-GCM',
    encrypted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_accessed DATETIME
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_activity_log_timestamp ON activity_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_log_event_type ON activity_log(event_type);
CREATE INDEX IF NOT EXISTS idx_activity_log_module ON activity_log(module);
CREATE INDEX IF NOT EXISTS idx_activity_log_severity ON activity_log(severity);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_enabled ON firewall_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_network_log_process ON network_connections_log(process_name);
CREATE INDEX IF NOT EXISTS idx_network_log_suspicious ON network_connections_log(is_suspicious);
CREATE INDEX IF NOT EXISTS idx_encrypted_files_path ON encrypted_files(encrypted_path);
