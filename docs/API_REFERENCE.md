# Security Prime - API Reference

## Base URL
```
Production: https://api.securityprime.io
Development: http://localhost:3000
```

## Authentication

All protected endpoints require a Bearer token in the Authorization header:

```
Authorization: Bearer <access_token>
```

### Get Access Token

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "your-password"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "uuid",
    "email": "admin@example.com",
    "name": "Admin User",
    "role": "msp_admin",
    "organization_id": "org-uuid"
  },
  "expires_at": "2024-01-21T12:00:00Z"
}
```

### Refresh Token

```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

---

## Organizations

### List Organizations

```http
GET /api/organizations
Authorization: Bearer <token>
```

**Response:**
```json
[
  {
    "id": "uuid",
    "name": "Acme Corp",
    "slug": "acme-corp",
    "org_type": "client",
    "parent_id": "msp-uuid",
    "is_active": true,
    "max_endpoints": 50,
    "created_at": "2024-01-01T00:00:00Z"
  }
]
```

### Create Organization

```http
POST /api/organizations
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "New Client Corp",
  "org_type": "client",
  "parent_id": "msp-uuid",
  "max_endpoints": 25
}
```

### Get Organization

```http
GET /api/organizations/:id
Authorization: Bearer <token>
```

### Get Organization Endpoints

```http
GET /api/organizations/:id/endpoints
Authorization: Bearer <token>
```

---

## Endpoints

### List All Endpoints

```http
GET /api/endpoints
Authorization: Bearer <token>
```

**Response:**
```json
[
  {
    "id": "uuid",
    "endpoint_id": "abc123def456",
    "organization_id": "org-uuid",
    "hostname": "WORKSTATION-01",
    "os_name": "Windows",
    "os_version": "11 Pro 23H2",
    "agent_version": "1.0.0",
    "last_seen": "2024-01-21T10:30:00Z",
    "status": "online",
    "security_score": 85,
    "threats_detected": 2
  }
]
```

### Get Endpoint Details

```http
GET /api/endpoints/:id
Authorization: Bearer <token>
```

### Heartbeat (Agent → Server)

```http
POST /api/endpoints/heartbeat
Content-Type: application/json

{
  "endpoint_id": "abc123def456",
  "api_key": "XXXX-XXXX-XXXX-XXXX",
  "hostname": "WORKSTATION-01",
  "os_name": "Windows",
  "os_version": "11 Pro 23H2",
  "agent_version": "1.0.0",
  "security_score": 85,
  "threats_detected": 2,
  "metadata": {
    "uptime_secs": 86400,
    "last_scan": "2024-01-21T08:00:00Z"
  }
}
```

**Response:**
```json
{
  "success": true,
  "server_time": "2024-01-21T10:30:00Z",
  "commands": [
    {
      "command_type": "start_scan",
      "payload": { "scan_type": "quick" }
    }
  ]
}
```

### Report Security Events

```http
POST /api/endpoints/events
Content-Type: application/json

{
  "endpoint_id": "abc123def456",
  "api_key": "XXXX-XXXX-XXXX-XXXX",
  "events": [
    {
      "event_type": "threat_detected",
      "severity": "high",
      "source": "scanner",
      "description": "Malware detected: Trojan.GenericKD",
      "timestamp": "2024-01-21T10:25:00Z",
      "metadata": {
        "file_path": "C:\\Users\\user\\Downloads\\malicious.exe",
        "hash": "abc123..."
      }
    }
  ]
}
```

---

## Alerts

### List Alerts

```http
GET /api/alerts
Authorization: Bearer <token>
```

**Query Parameters:**
- `status` - Filter by status (open, resolved, etc.)
- `severity` - Filter by severity (critical, high, medium, low)
- `organization_id` - Filter by organization

**Response:**
```json
[
  {
    "id": "uuid",
    "organization_id": "org-uuid",
    "endpoint_id": "endpoint-uuid",
    "title": "Malware Detected",
    "description": "Trojan detected on WORKSTATION-01",
    "severity": "high",
    "status": "open",
    "source": "abc123def456",
    "created_at": "2024-01-21T10:25:00Z",
    "resolved_at": null
  }
]
```

### Create Alert

```http
POST /api/alerts
Authorization: Bearer <token>
Content-Type: application/json

{
  "organization_id": "org-uuid",
  "endpoint_id": "endpoint-uuid",
  "title": "Custom Alert",
  "description": "Manual alert created by admin",
  "severity": "medium",
  "source": "manual"
}
```

### Resolve Alert

```http
POST /api/alerts/:id/resolve
Authorization: Bearer <token>
```

---

## Users

### List Users

```http
GET /api/users
Authorization: Bearer <token>
```

### Create User

```http
POST /api/users
Authorization: Bearer <token>
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure-password",
  "name": "John Doe",
  "role": "msp_user",
  "organization_id": "org-uuid"
}
```

**User Roles:**
- `super_admin` - Full system access
- `msp_admin` - MSP management access
- `msp_user` - MSP read/limited write
- `client_admin` - Client organization admin
- `client_user` - Client read-only

---

## Licenses

### Create License (Admin Only)

```http
POST /api/licenses
Authorization: Bearer <token>
Content-Type: application/json

{
  "organization_id": "org-uuid",
  "max_endpoints": 100,
  "features": ["scanner", "firewall", "encryption", "ai_agent"],
  "duration_days": 365
}
```

**Response:**
```json
{
  "id": "uuid",
  "license_key": "ABCD-EFGH-IJKL-MNOP",
  "organization_id": "org-uuid",
  "max_endpoints": 100,
  "features": ["scanner", "firewall", "encryption", "ai_agent"],
  "created_at": "2024-01-21T00:00:00Z",
  "expires_at": "2025-01-21T00:00:00Z",
  "is_active": true
}
```

### Validate License (Public)

```http
POST /api/licenses/validate
Content-Type: application/json

{
  "license_key": "ABCD-EFGH-IJKL-MNOP",
  "endpoint_id": "abc123def456"
}
```

**Response:**
```json
{
  "valid": true,
  "organization_name": "Acme Corp",
  "features": ["scanner", "firewall", "encryption", "ai_agent"],
  "expires_at": "2025-01-21T00:00:00Z",
  "error": null
}
```

---

## Reports

### Dashboard Summary

```http
GET /api/reports/summary
Authorization: Bearer <token>
```

**Response:**
```json
{
  "total_organizations": 25,
  "total_endpoints": 450,
  "online_endpoints": 420,
  "offline_endpoints": 30,
  "critical_alerts": 3,
  "total_threats_today": 15,
  "average_security_score": 82.5
}
```

### Threat Report

```http
GET /api/reports/threats
Authorization: Bearer <token>
```

**Query Parameters:**
- `start_date` - Report period start
- `end_date` - Report period end
- `organization_id` - Filter by organization

---

## Error Responses

All errors follow this format:

```json
{
  "error": "error_type",
  "message": "Human-readable error message",
  "details": "Optional additional details"
}
```

**HTTP Status Codes:**
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (missing/invalid token)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `409` - Conflict (duplicate resource)
- `500` - Internal Server Error

---

## Rate Limiting

API requests are rate-limited:
- Authentication endpoints: 10 requests/minute
- Other endpoints: 100 requests/minute

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705834800
```
