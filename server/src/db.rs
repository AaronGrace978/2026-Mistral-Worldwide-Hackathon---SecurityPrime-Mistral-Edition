// Security Prime MSP Server - Database Layer

use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::models::*;
use crate::error::{AppError, Result};

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await?;
        
        Ok(Self { pool })
    }
    
    pub async fn run_migrations(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await?;
        Ok(())
    }
    
    // ========================================================================
    // User Operations
    // ========================================================================
    
    pub async fn create_user(&self, req: CreateUserRequest, password_hash: String) -> Result<User> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (id, email, password_hash, name, role, organization_id, created_at, updated_at, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)
            RETURNING *
            "#
        )
        .bind(id)
        .bind(&req.email)
        .bind(&password_hash)
        .bind(&req.name)
        .bind(&req.role)
        .bind(req.organization_id)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        
        Ok(user)
    }
    
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        
        Ok(user)
    }
    
    pub async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        
        Ok(user)
    }
    
    pub async fn list_users(&self, organization_id: Option<Uuid>) -> Result<Vec<User>> {
        let users = if let Some(org_id) = organization_id {
            sqlx::query_as::<_, User>("SELECT * FROM users WHERE organization_id = $1 ORDER BY created_at DESC")
                .bind(org_id)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await?
        };
        
        Ok(users)
    }
    
    pub async fn update_user_last_login(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE users SET last_login = $1 WHERE id = $2")
            .bind(Utc::now())
            .bind(id)
            .execute(&self.pool)
            .await?;
        
        Ok(())
    }
    
    pub async fn update_user(&self, id: Uuid, req: UpdateUserRequest) -> Result<User> {
        let now = Utc::now();
        
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users SET
                email = COALESCE($1, email),
                name = COALESCE($2, name),
                role = COALESCE($3, role),
                is_active = COALESCE($4, is_active),
                updated_at = $5
            WHERE id = $6
            RETURNING *
            "#
        )
        .bind(&req.email)
        .bind(&req.name)
        .bind(&req.role)
        .bind(req.is_active)
        .bind(now)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        
        Ok(user)
    }
    
    pub async fn soft_delete_user(&self, id: Uuid) -> Result<()> {
        let now = Utc::now();
        
        sqlx::query("UPDATE users SET is_active = false, updated_at = $1 WHERE id = $2")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        
        Ok(())
    }
    
    // ========================================================================
    // Organization Operations
    // ========================================================================
    
    pub async fn create_organization(&self, req: CreateOrganizationRequest) -> Result<Organization> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let slug = slugify(&req.name);
        
        let org = sqlx::query_as::<_, Organization>(
            r#"
            INSERT INTO organizations (id, name, slug, org_type, parent_id, settings, created_at, updated_at, is_active, max_endpoints)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, $9)
            RETURNING *
            "#
        )
        .bind(id)
        .bind(&req.name)
        .bind(&slug)
        .bind(&req.org_type)
        .bind(req.parent_id)
        .bind(serde_json::json!({}))
        .bind(now)
        .bind(now)
        .bind(req.max_endpoints.unwrap_or(50))
        .fetch_one(&self.pool)
        .await?;
        
        Ok(org)
    }
    
    pub async fn get_organization(&self, id: Uuid) -> Result<Option<Organization>> {
        let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        
        Ok(org)
    }
    
    pub async fn list_organizations(&self, parent_id: Option<Uuid>) -> Result<Vec<Organization>> {
        let orgs = if let Some(pid) = parent_id {
            sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE parent_id = $1 ORDER BY name")
                .bind(pid)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query_as::<_, Organization>("SELECT * FROM organizations ORDER BY name")
                .fetch_all(&self.pool)
                .await?
        };
        
        Ok(orgs)
    }
    
    pub async fn update_organization(&self, id: Uuid, req: UpdateOrganizationRequest) -> Result<Organization> {
        let now = Utc::now();
        
        let org = sqlx::query_as::<_, Organization>(
            r#"
            UPDATE organizations SET
                name = COALESCE($1, name),
                settings = COALESCE($2, settings),
                is_active = COALESCE($3, is_active),
                max_endpoints = COALESCE($4, max_endpoints),
                updated_at = $5
            WHERE id = $6
            RETURNING *
            "#
        )
        .bind(&req.name)
        .bind(&req.settings)
        .bind(req.is_active)
        .bind(req.max_endpoints)
        .bind(now)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        
        Ok(org)
    }
    
    pub async fn soft_delete_organization(&self, id: Uuid) -> Result<()> {
        let now = Utc::now();
        
        sqlx::query("UPDATE organizations SET is_active = false, updated_at = $1 WHERE id = $2")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        
        Ok(())
    }
    
    // ========================================================================
    // Endpoint Operations
    // ========================================================================
    
    pub async fn upsert_endpoint(&self, req: &HeartbeatRequest, org_id: Uuid) -> Result<Endpoint> {
        let now = Utc::now();
        
        // Try to find existing endpoint
        let existing = sqlx::query_as::<_, Endpoint>(
            "SELECT * FROM endpoints WHERE endpoint_id = $1 AND organization_id = $2"
        )
        .bind(&req.endpoint_id)
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await?;
        
        let endpoint = if let Some(_) = existing {
            // Update existing endpoint
            sqlx::query_as::<_, Endpoint>(
                r#"
                UPDATE endpoints SET
                    hostname = $1,
                    os_name = $2,
                    os_version = $3,
                    agent_version = $4,
                    last_seen = $5,
                    status = 'online',
                    security_score = $6,
                    threats_detected = $7,
                    updated_at = $8,
                    metadata = COALESCE($9, metadata)
                WHERE endpoint_id = $10 AND organization_id = $11
                RETURNING *
                "#
            )
            .bind(&req.hostname)
            .bind(&req.os_name)
            .bind(&req.os_version)
            .bind(&req.agent_version)
            .bind(now)
            .bind(req.security_score)
            .bind(req.threats_detected)
            .bind(now)
            .bind(&req.metadata)
            .bind(&req.endpoint_id)
            .bind(org_id)
            .fetch_one(&self.pool)
            .await?
        } else {
            // Create new endpoint
            let id = Uuid::new_v4();
            sqlx::query_as::<_, Endpoint>(
                r#"
                INSERT INTO endpoints (id, endpoint_id, organization_id, hostname, os_name, os_version, agent_version, last_seen, status, security_score, threats_detected, created_at, updated_at, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'online', $9, $10, $11, $12, $13)
                RETURNING *
                "#
            )
            .bind(id)
            .bind(&req.endpoint_id)
            .bind(org_id)
            .bind(&req.hostname)
            .bind(&req.os_name)
            .bind(&req.os_version)
            .bind(&req.agent_version)
            .bind(now)
            .bind(req.security_score)
            .bind(req.threats_detected)
            .bind(now)
            .bind(now)
            .bind(&req.metadata.clone().unwrap_or(serde_json::json!({})))
            .fetch_one(&self.pool)
            .await?
        };
        
        Ok(endpoint)
    }
    
    pub async fn list_endpoints(&self, organization_id: Option<Uuid>) -> Result<Vec<Endpoint>> {
        let endpoints = if let Some(org_id) = organization_id {
            sqlx::query_as::<_, Endpoint>("SELECT * FROM endpoints WHERE organization_id = $1 ORDER BY hostname")
                .bind(org_id)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query_as::<_, Endpoint>("SELECT * FROM endpoints ORDER BY hostname")
                .fetch_all(&self.pool)
                .await?
        };
        
        Ok(endpoints)
    }
    
    pub async fn get_endpoint(&self, id: Uuid) -> Result<Option<Endpoint>> {
        let endpoint = sqlx::query_as::<_, Endpoint>("SELECT * FROM endpoints WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        
        Ok(endpoint)
    }
    
    pub async fn delete_endpoint(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM endpoints WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        
        Ok(())
    }
    
    pub async fn get_endpoint_uuid(&self, endpoint_id: &str, org_id: Uuid) -> Result<Option<Uuid>> {
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM endpoints WHERE endpoint_id = $1 AND organization_id = $2"
        )
        .bind(endpoint_id)
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(id)
    }
    
    pub async fn get_pending_commands(&self, endpoint_id: &str) -> Result<Vec<EndpointCommand>> {
        let rows = sqlx::query(
            "SELECT command_type, payload FROM pending_commands WHERE endpoint_id = $1 AND delivered = false"
        )
        .bind(endpoint_id)
        .fetch_all(&self.pool)
        .await?;
        
        sqlx::query("UPDATE pending_commands SET delivered = true WHERE endpoint_id = $1 AND delivered = false")
            .bind(endpoint_id)
            .execute(&self.pool)
            .await?;
        
        Ok(rows.into_iter().map(|row| EndpointCommand {
            command_type: row.get("command_type"),
            payload: row.get("payload"),
        }).collect())
    }
    
    // ========================================================================
    // Alert Operations
    // ========================================================================
    
    pub async fn create_alert(&self, req: CreateAlertRequest) -> Result<Alert> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        let alert = sqlx::query_as::<_, Alert>(
            r#"
            INSERT INTO alerts (id, organization_id, endpoint_id, title, description, severity, status, source, created_at, updated_at, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, 'open', $7, $8, $9, $10)
            RETURNING *
            "#
        )
        .bind(id)
        .bind(req.organization_id)
        .bind(req.endpoint_id)
        .bind(&req.title)
        .bind(&req.description)
        .bind(&req.severity)
        .bind(&req.source)
        .bind(now)
        .bind(now)
        .bind(&req.metadata.unwrap_or(serde_json::json!({})))
        .fetch_one(&self.pool)
        .await?;
        
        Ok(alert)
    }
    
    pub async fn list_alerts(&self, organization_id: Option<Uuid>, status: Option<AlertStatus>) -> Result<Vec<Alert>> {
        let mut query = "SELECT * FROM alerts WHERE 1=1".to_string();
        
        if organization_id.is_some() {
            query.push_str(" AND organization_id = $1");
        }
        if status.is_some() {
            query.push_str(if organization_id.is_some() { " AND status = $2" } else { " AND status = $1" });
        }
        query.push_str(" ORDER BY created_at DESC");
        
        // This is a simplified version - in production, use a query builder
        let alerts = sqlx::query_as::<_, Alert>(&query)
            .fetch_all(&self.pool)
            .await?;
        
        Ok(alerts)
    }
    
    pub async fn resolve_alert(&self, id: Uuid, resolved_by: Uuid) -> Result<Alert> {
        let now = Utc::now();
        
        let alert = sqlx::query_as::<_, Alert>(
            r#"
            UPDATE alerts SET
                status = 'resolved',
                resolved_at = $1,
                resolved_by = $2,
                updated_at = $3
            WHERE id = $4
            RETURNING *
            "#
        )
        .bind(now)
        .bind(resolved_by)
        .bind(now)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        
        Ok(alert)
    }
    
    pub async fn get_alert(&self, id: Uuid) -> Result<Option<Alert>> {
        let alert = sqlx::query_as::<_, Alert>("SELECT * FROM alerts WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        
        Ok(alert)
    }
    
    pub async fn update_alert(&self, id: Uuid, req: UpdateAlertRequest) -> Result<Alert> {
        let now = Utc::now();
        
        let alert = sqlx::query_as::<_, Alert>(
            r#"
            UPDATE alerts SET
                status = COALESCE($1, status),
                title = COALESCE($2, title),
                description = COALESCE($3, description),
                updated_at = $4
            WHERE id = $5
            RETURNING *
            "#
        )
        .bind(&req.status)
        .bind(&req.title)
        .bind(&req.description)
        .bind(now)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        
        Ok(alert)
    }
    
    // ========================================================================
    // License Operations
    // ========================================================================
    
    pub async fn create_license(&self, req: CreateLicenseRequest) -> Result<License> {
        let id = Uuid::new_v4();
        let license_key = generate_license_key();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::days(req.duration_days as i64);
        
        let license = sqlx::query_as::<_, License>(
            r#"
            INSERT INTO licenses (id, license_key, organization_id, max_endpoints, features, created_at, expires_at, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, true)
            RETURNING *
            "#
        )
        .bind(id)
        .bind(&license_key)
        .bind(req.organization_id)
        .bind(req.max_endpoints)
        .bind(&req.features)
        .bind(now)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        
        Ok(license)
    }
    
    pub async fn get_license_by_key(&self, key: &str) -> Result<Option<License>> {
        let license = sqlx::query_as::<_, License>(
            "SELECT * FROM licenses WHERE license_key = $1 AND is_active = true"
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(license)
    }
    
    pub async fn get_organization_by_license(&self, license_key: &str) -> Result<Option<Organization>> {
        let org = sqlx::query_as::<_, Organization>(
            r#"
            SELECT o.* FROM organizations o
            JOIN licenses l ON l.organization_id = o.id
            WHERE l.license_key = $1 AND l.is_active = true
            "#
        )
        .bind(license_key)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(org)
    }
    
    pub async fn list_licenses(&self, organization_id: Option<Uuid>) -> Result<Vec<License>> {
        let licenses = if let Some(org_id) = organization_id {
            sqlx::query_as::<_, License>(
                "SELECT * FROM licenses WHERE organization_id = $1 ORDER BY created_at DESC"
            )
            .bind(org_id)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, License>("SELECT * FROM licenses ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await?
        };
        
        Ok(licenses)
    }
    
    pub async fn revoke_license(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE licenses SET is_active = false WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        
        Ok(())
    }
    
    // ========================================================================
    // Dashboard / Reports
    // ========================================================================
    
    pub async fn get_dashboard_summary(&self, organization_id: Option<Uuid>) -> Result<DashboardSummary> {
        // This is simplified - in production would use proper aggregation queries
        let total_organizations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organizations")
            .fetch_one(&self.pool)
            .await?;
        
        let total_endpoints: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM endpoints")
            .fetch_one(&self.pool)
            .await?;
        
        let online_endpoints: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM endpoints WHERE status = 'online'"
        )
        .fetch_one(&self.pool)
        .await?;
        
        let critical_alerts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'critical' AND status = 'open'"
        )
        .fetch_one(&self.pool)
        .await?;
        
        let avg_score: f64 = sqlx::query_scalar(
            "SELECT COALESCE(AVG(security_score), 0) FROM endpoints"
        )
        .fetch_one(&self.pool)
        .await?;
        
        Ok(DashboardSummary {
            total_organizations,
            total_endpoints,
            online_endpoints,
            offline_endpoints: total_endpoints - online_endpoints,
            critical_alerts,
            total_threats_today: 0, // Would aggregate from events
            average_security_score: avg_score,
        })
    }
    
    pub async fn get_threat_report(&self, organization_id: Option<Uuid>) -> Result<ThreatReport> {
        let now = Utc::now();
        let period_start = now - chrono::Duration::days(30);
        
        let total_threats: i64 = if let Some(org_id) = organization_id {
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM alerts WHERE organization_id = $1 AND created_at >= $2"
            )
            .bind(org_id)
            .bind(period_start)
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM alerts WHERE created_at >= $1")
                .bind(period_start)
                .fetch_one(&self.pool)
                .await?
        };
        
        let severity_rows = if let Some(org_id) = organization_id {
            sqlx::query(
                "SELECT severity::text as sev, COUNT(*) as cnt FROM alerts WHERE organization_id = $1 AND created_at >= $2 GROUP BY severity"
            )
            .bind(org_id)
            .bind(period_start)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT severity::text as sev, COUNT(*) as cnt FROM alerts WHERE created_at >= $1 GROUP BY severity"
            )
            .bind(period_start)
            .fetch_all(&self.pool)
            .await?
        };
        
        let by_severity: Vec<SeverityCount> = severity_rows.into_iter().map(|row| SeverityCount {
            severity: row.get("sev"),
            count: row.get("cnt"),
        }).collect();
        
        let type_rows = if let Some(org_id) = organization_id {
            sqlx::query(
                "SELECT source as ttype, COUNT(*) as cnt FROM alerts WHERE organization_id = $1 AND created_at >= $2 GROUP BY source"
            )
            .bind(org_id)
            .bind(period_start)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT source as ttype, COUNT(*) as cnt FROM alerts WHERE created_at >= $1 GROUP BY source"
            )
            .bind(period_start)
            .fetch_all(&self.pool)
            .await?
        };
        
        let by_type: Vec<TypeCount> = type_rows.into_iter().map(|row| TypeCount {
            threat_type: row.get("ttype"),
            count: row.get("cnt"),
        }).collect();
        
        let endpoint_rows = if let Some(org_id) = organization_id {
            sqlx::query(
                r#"
                SELECT e.id as eid, e.hostname, COUNT(a.id) as cnt
                FROM alerts a
                JOIN endpoints e ON e.id = a.endpoint_id
                WHERE a.organization_id = $1 AND a.created_at >= $2
                GROUP BY e.id, e.hostname
                ORDER BY cnt DESC
                LIMIT 10
                "#
            )
            .bind(org_id)
            .bind(period_start)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT e.id as eid, e.hostname, COUNT(a.id) as cnt
                FROM alerts a
                JOIN endpoints e ON e.id = a.endpoint_id
                WHERE a.created_at >= $1
                GROUP BY e.id, e.hostname
                ORDER BY cnt DESC
                LIMIT 10
                "#
            )
            .bind(period_start)
            .fetch_all(&self.pool)
            .await?
        };
        
        let top_affected_endpoints: Vec<EndpointThreatCount> = endpoint_rows.into_iter().map(|row| EndpointThreatCount {
            endpoint_id: row.get("eid"),
            hostname: row.get("hostname"),
            threat_count: row.get("cnt"),
        }).collect();
        
        Ok(ThreatReport {
            period_start,
            period_end: now,
            total_threats,
            by_severity,
            by_type,
            top_affected_endpoints,
        })
    }
    
    pub async fn get_compliance_report(&self, organization_id: Option<Uuid>) -> Result<serde_json::Value> {
        let avg_score: f64 = if let Some(org_id) = organization_id {
            sqlx::query_scalar("SELECT COALESCE(AVG(security_score), 0) FROM endpoints WHERE organization_id = $1")
                .bind(org_id)
                .fetch_one(&self.pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COALESCE(AVG(security_score), 0) FROM endpoints")
                .fetch_one(&self.pool)
                .await?
        };
        
        let total_endpoints: i64 = if let Some(org_id) = organization_id {
            sqlx::query_scalar("SELECT COUNT(*) FROM endpoints WHERE organization_id = $1")
                .bind(org_id)
                .fetch_one(&self.pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM endpoints")
                .fetch_one(&self.pool)
                .await?
        };
        
        let online_endpoints: i64 = if let Some(org_id) = organization_id {
            sqlx::query_scalar("SELECT COUNT(*) FROM endpoints WHERE organization_id = $1 AND status = 'online'")
                .bind(org_id)
                .fetch_one(&self.pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM endpoints WHERE status = 'online'")
                .fetch_one(&self.pool)
                .await?
        };
        
        let open_critical: i64 = if let Some(org_id) = organization_id {
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM alerts WHERE organization_id = $1 AND status = 'open' AND severity IN ('critical', 'high')"
            )
            .bind(org_id)
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM alerts WHERE status = 'open' AND severity IN ('critical', 'high')"
            )
            .fetch_one(&self.pool)
            .await?
        };
        
        let uptime_ratio = if total_endpoints > 0 {
            (online_endpoints as f64 / total_endpoints as f64 * 100.0).round()
        } else {
            100.0
        };
        let alert_penalty = (open_critical as f64 * 5.0).min(30.0);
        let score = ((avg_score * 0.5) + (uptime_ratio * 0.5) - alert_penalty).max(0.0).min(100.0) as i64;
        let status = if score >= 80 { "compliant" } else if score >= 50 { "needs_attention" } else { "non_compliant" };
        
        Ok(serde_json::json!({
            "status": status,
            "checks": [
                {
                    "name": "endpoint_security_score",
                    "status": if avg_score >= 70.0 { "pass" } else { "fail" },
                    "value": avg_score
                },
                {
                    "name": "endpoint_online_ratio",
                    "status": if uptime_ratio >= 90.0 { "pass" } else { "fail" },
                    "value": uptime_ratio
                },
                {
                    "name": "critical_alerts_resolved",
                    "status": if open_critical == 0 { "pass" } else { "fail" },
                    "value": open_critical
                }
            ],
            "score": score
        }))
    }
}

// Helper functions

fn slugify(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn generate_license_key() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    
    let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
    
    (0..4)
        .map(|_| {
            (0..4)
                .map(|_| chars[rng.gen_range(0..chars.len())])
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}
