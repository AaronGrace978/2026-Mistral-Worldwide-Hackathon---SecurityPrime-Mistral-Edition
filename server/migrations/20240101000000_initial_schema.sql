-- Security Prime MSP Server - Initial Database Schema

-- Create enum types
CREATE TYPE user_role AS ENUM ('super_admin', 'msp_admin', 'msp_user', 'client_admin', 'client_user');
CREATE TYPE org_type AS ENUM ('msp', 'client');
CREATE TYPE endpoint_status AS ENUM ('online', 'offline', 'warning', 'critical');
CREATE TYPE alert_severity AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE alert_status AS ENUM ('open', 'acknowledged', 'in_progress', 'resolved', 'dismissed');

-- Organizations table
CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    org_type org_type NOT NULL,
    parent_id UUID REFERENCES organizations(id),
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true,
    max_endpoints INTEGER DEFAULT 50,
    license_expires_at TIMESTAMPTZ
);

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    role user_role NOT NULL,
    organization_id UUID REFERENCES organizations(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT true
);

-- Endpoints table
CREATE TABLE endpoints (
    id UUID PRIMARY KEY,
    endpoint_id VARCHAR(255) NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    hostname VARCHAR(255) NOT NULL,
    os_name VARCHAR(100),
    os_version VARCHAR(100),
    agent_version VARCHAR(50),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status endpoint_status DEFAULT 'online',
    security_score INTEGER DEFAULT 100,
    threats_detected INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}',
    UNIQUE(endpoint_id, organization_id)
);

-- Alerts table
CREATE TABLE alerts (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    endpoint_id UUID REFERENCES endpoints(id),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity alert_severity NOT NULL,
    status alert_status DEFAULT 'open',
    source VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id),
    metadata JSONB DEFAULT '{}'
);

-- Licenses table
CREATE TABLE licenses (
    id UUID PRIMARY KEY,
    license_key VARCHAR(50) UNIQUE NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    max_endpoints INTEGER NOT NULL,
    features TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN DEFAULT true
);

-- Security events table (for detailed logging)
CREATE TABLE security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID REFERENCES endpoints(id),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source VARCHAR(255),
    description TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log table
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    organization_id UUID REFERENCES organizations(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    details JSONB DEFAULT '{}',
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_organization ON users(organization_id);
CREATE INDEX idx_organizations_parent ON organizations(parent_id);
CREATE INDEX idx_organizations_slug ON organizations(slug);
CREATE INDEX idx_endpoints_organization ON endpoints(organization_id);
CREATE INDEX idx_endpoints_status ON endpoints(status);
CREATE INDEX idx_endpoints_last_seen ON endpoints(last_seen);
CREATE INDEX idx_alerts_organization ON alerts(organization_id);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX idx_licenses_key ON licenses(license_key);
CREATE INDEX idx_licenses_organization ON licenses(organization_id);
CREATE INDEX idx_security_events_endpoint ON security_events(endpoint_id);
CREATE INDEX idx_security_events_organization ON security_events(organization_id);
CREATE INDEX idx_security_events_created ON security_events(created_at DESC);
CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at DESC);

-- Insert default super admin (password: admin123 - CHANGE IN PRODUCTION!)
INSERT INTO organizations (id, name, slug, org_type, created_at, updated_at)
VALUES ('00000000-0000-0000-0000-000000000001', 'Security Prime', 'security-prime', 'msp', NOW(), NOW());

INSERT INTO users (id, email, password_hash, name, role, organization_id, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'admin@securityprime.local',
    -- bcrypt hash of 'admin123' - CHANGE IN PRODUCTION!
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4v.jY3wC5j0gQyKe',
    'System Administrator',
    'super_admin',
    '00000000-0000-0000-0000-000000000001',
    NOW(),
    NOW()
);
