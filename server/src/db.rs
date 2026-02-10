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
