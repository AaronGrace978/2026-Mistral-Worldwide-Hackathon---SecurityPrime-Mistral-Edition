// Security Prime MSP Server - Endpoints API Handlers

use axum::{
    extract::Path,
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, Result};
use crate::models::*;
use crate::AppState;

/// List all endpoints
pub async fn list(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<Endpoint>>> {
    let endpoints = match user.role {
        UserRole::SuperAdmin => {
            state.db.list_endpoints(None).await?
        }
        _ => {
            state.db.list_endpoints(user.organization_id).await?
        }
    };
    
    Ok(Json(endpoints))
}

/// Get a single endpoint
pub async fn get(
    Extension(state): Extension<Arc<AppState>>,
    _user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Endpoint>> {
    let endpoint = state.db.get_endpoint(id).await?
        .ok_or(AppError::NotFound("Endpoint not found".to_string()))?;
    
    Ok(Json(endpoint))
}

/// Delete an endpoint
pub async fn delete(
    Extension(_state): Extension<Arc<AppState>>,
    _user: AuthUser,
    Path(_id): Path<Uuid>,
) -> Result<Json<()>> {
    // TODO: Implement endpoint deletion
    Ok(Json(()))
}

/// Heartbeat from an endpoint agent
pub async fn heartbeat(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>> {
    // Validate API key and get organization
    let org = state.db.get_organization_by_license(&req.api_key).await?
        .ok_or(AppError::Unauthorized)?;
    
    // Update or create endpoint
    let _endpoint = state.db.upsert_endpoint(&req, org.id).await?;
    
    // Return response with any pending commands
    Ok(Json(HeartbeatResponse {
        success: true,
        server_time: chrono::Utc::now(),
        commands: vec![], // TODO: Fetch pending commands
    }))
}

/// Report security events from an endpoint
pub async fn report_events(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<ReportEventsRequest>,
) -> Result<Json<()>> {
    // Validate API key and get organization
    let org = state.db.get_organization_by_license(&req.api_key).await?
        .ok_or(AppError::Unauthorized)?;
    
    // Process events - create alerts for high severity events
    for event in &req.events {
        if event.severity == "high" || event.severity == "critical" {
            let alert_req = CreateAlertRequest {
                organization_id: org.id,
                endpoint_id: None, // TODO: Get endpoint ID from endpoint_id string
                title: format!("{}: {}", event.event_type, event.source),
                description: event.description.clone(),
                severity: match event.severity.as_str() {
                    "critical" => AlertSeverity::Critical,
                    "high" => AlertSeverity::High,
                    "medium" => AlertSeverity::Medium,
                    _ => AlertSeverity::Low,
                },
                source: req.endpoint_id.clone(),
                metadata: event.metadata.clone(),
            };
            
            state.db.create_alert(alert_req).await?;
        }
    }
    
    Ok(Json(()))
}
