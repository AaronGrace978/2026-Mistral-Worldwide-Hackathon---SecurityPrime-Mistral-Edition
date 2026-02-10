-- License table for activation and entitlement
-- Stores the license key and activation information

CREATE TABLE IF NOT EXISTS license (
    id INTEGER PRIMARY KEY,
    license_key TEXT NOT NULL,
    organization_id TEXT,
    organization_name TEXT,
    activated_at DATETIME,
    expires_at DATETIME,
    endpoint_id TEXT UNIQUE,
    max_endpoints INTEGER,
    features TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- MSP Server configuration
CREATE TABLE IF NOT EXISTS server_config (
    id INTEGER PRIMARY KEY,
    server_url TEXT,
    api_key TEXT,
    heartbeat_interval INTEGER DEFAULT 60,
    enabled BOOLEAN DEFAULT false,
    last_connected DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Endpoint registration info
CREATE TABLE IF NOT EXISTS endpoint_info (
    id INTEGER PRIMARY KEY,
    endpoint_id TEXT UNIQUE NOT NULL,
    hostname TEXT,
    os_name TEXT,
    os_version TEXT,
    cpu_cores INTEGER,
    total_memory_gb REAL,
    registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create index for endpoint lookup
CREATE INDEX IF NOT EXISTS idx_endpoint_info_endpoint_id ON endpoint_info(endpoint_id);
