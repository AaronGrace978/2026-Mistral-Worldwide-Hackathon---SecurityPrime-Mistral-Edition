# Security Prime - MSP Deployment Guide

## Overview

Security Prime is an enterprise-grade cybersecurity solution designed for Managed Service Providers (MSPs). This guide covers deploying and managing Security Prime across multiple client organizations.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    MSP Management Server                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ REST API    │  │ PostgreSQL  │  │ MSP Web Dashboard       │  │
│  │ (Axum/Rust) │  │ Database    │  │ (SvelteKit)             │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              │      HTTPS / TLS          │
              │   (Heartbeat & Events)    │
              └─────────────┬─────────────┘
                            │
    ┌───────────────────────┼───────────────────────┐
    │                       │                       │
    ▼                       ▼                       ▼
┌─────────┐           ┌─────────┐           ┌─────────┐
│ Client  │           │ Client  │           │ Client  │
│ Org A   │           │ Org B   │           │ Org C   │
└────┬────┘           └────┬────┘           └────┬────┘
     │                     │                     │
┌────┴────┐           ┌────┴────┐           ┌────┴────┐
│Endpoint │           │Endpoint │           │Endpoint │
│ Agent   │           │ Agent   │           │ Agent   │
└─────────┘           └─────────┘           └─────────┘
```

## Components

### 1. Endpoint Agent (Tauri Desktop App)
- Installed on each client workstation
- Real-time security monitoring
- Reports to MSP server via heartbeat
- Can run as Windows Service for always-on protection

### 2. MSP Management Server (Rust/Axum)
- REST API for all management operations
- PostgreSQL database for multi-tenant data
- JWT-based authentication
- Role-based access control (RBAC)

### 3. MSP Web Dashboard (SvelteKit)
- Web-based management console
- Organization and endpoint management
- Alert monitoring and response
- Reporting and analytics

---

## Server Deployment

### Prerequisites
- Linux server (Ubuntu 22.04+ recommended)
- PostgreSQL 14+
- Domain with SSL certificate
- Docker (optional but recommended)

### Option 1: Docker Deployment

```bash
# Clone the repository
git clone https://github.com/securityprime/security-prime.git
cd security-prime

# Create environment file
cat > .env << EOF
DATABASE_URL=postgres://secprime:yourpassword@db:5432/security_prime
JWT_SECRET=$(openssl rand -base64 32)
PORT=3000
RUST_LOG=security_prime_server=info
EOF

# Start with Docker Compose
docker-compose up -d
```

### Option 2: Manual Deployment

```bash
# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Create database
sudo -u postgres psql
CREATE DATABASE security_prime;
CREATE USER secprime WITH PASSWORD 'yourpassword';
GRANT ALL PRIVILEGES ON DATABASE security_prime TO secprime;
\q

# Build and run server
cd server
cargo build --release
./target/release/security-prime-server
```

### Reverse Proxy (Nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Agent Deployment

### Mass Deployment Options

#### 1. Group Policy (GPO)
```powershell
# Create deployment share
$SharePath = "\\server\SecurityPrime"
Copy-Item "SecurityPrime-1.0.0.msi" -Destination $SharePath

# GPO: Computer Configuration > Software Settings > Software Installation
# Add new package pointing to the MSI
```

#### 2. Intune / Endpoint Manager
1. Upload MSI to Intune
2. Configure as Required or Available
3. Assign to device groups

#### 3. RMM Tools (ConnectWise, Datto, etc.)
```powershell
# Silent install script
msiexec /i "SecurityPrime-1.0.0.msi" /qn /norestart `
    SERVERURL="https://api.yourdomain.com" `
    APIKEY="your-license-key"
```

#### 4. SCCM/ConfigMgr
1. Create Application in Software Library
2. Add MSI as deployment type
3. Deploy to collection

### Post-Installation Configuration

After installation, configure the MSP server connection:

```powershell
# Option 1: Registry (pre-configure before deployment)
$RegPath = "HKLM:\SOFTWARE\SecurityPrime"
New-Item -Path $RegPath -Force
Set-ItemProperty -Path $RegPath -Name "ServerURL" -Value "https://api.yourdomain.com"
Set-ItemProperty -Path $RegPath -Name "ApiKey" -Value "your-license-key"

# Option 2: Configuration file
$ConfigPath = "$env:APPDATA\SecurityPrime\config.json"
@{
    server_url = "https://api.yourdomain.com"
    api_key = "your-license-key"
    heartbeat_interval_secs = 60
    enabled = $true
} | ConvertTo-Json | Set-Content $ConfigPath
```

---

## License Management

### Generating Licenses

Licenses are generated through the MSP Dashboard or API:

```bash
# API: Create license
curl -X POST https://api.yourdomain.com/api/licenses \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "org-uuid",
    "max_endpoints": 100,
    "features": ["scanner", "firewall", "encryption", "ai_agent"],
    "duration_days": 365
  }'
```

### License Format
```
XXXX-XXXX-XXXX-XXXX
```

Licenses encode:
- Organization ID
- Expiration date
- Feature flags
- Endpoint limit
- Checksum for validation

---

## Monitoring & Alerts

### Alert Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| Critical | Active breach, ransomware | Immediate |
| High | Malware detected, firewall breach | < 1 hour |
| Medium | Suspicious activity, vulnerabilities | < 24 hours |
| Low | Configuration issues, updates | < 1 week |

### Setting Up Notifications

Configure webhooks in the MSP Dashboard:

```json
{
  "webhook_url": "https://your-psa.com/webhook",
  "events": ["alert.critical", "alert.high", "endpoint.offline"],
  "format": "json"
}
```

---

## Security Best Practices

### Server Security
- [ ] Use strong, unique JWT secret
- [ ] Enable TLS 1.3
- [ ] Configure firewall rules
- [ ] Regular security updates
- [ ] Database backups

### Agent Security
- [ ] Code-sign installers
- [ ] Use per-client API keys
- [ ] Enable tamper protection
- [ ] Regular agent updates

### Access Control
- [ ] Use role-based access (RBAC)
- [ ] Enable MFA for admin accounts
- [ ] Audit all admin actions
- [ ] Rotate API keys periodically

---

## Troubleshooting

### Agent Not Connecting

1. Check network connectivity:
```powershell
Test-NetConnection -ComputerName api.yourdomain.com -Port 443
```

2. Verify API key:
```powershell
$config = Get-Content "$env:APPDATA\SecurityPrime\config.json" | ConvertFrom-Json
Write-Host "Server: $($config.server_url)"
Write-Host "Enabled: $($config.enabled)"
```

3. Check Windows Event Log:
```powershell
Get-EventLog -LogName Application -Source "SecurityPrime" -Newest 10
```

### Server Issues

1. Check server logs:
```bash
journalctl -u security-prime-server -f
```

2. Verify database connection:
```bash
psql -h localhost -U secprime -d security_prime -c "SELECT 1"
```

3. Test API health:
```bash
curl https://api.yourdomain.com/health
```

---

## Support

- Documentation: https://docs.securityprime.io
- Support Portal: https://support.securityprime.io
- Emergency: support@securityprime.io
