// Security Prime MSP Server - Alerts API Handlers

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

/// List alerts
pub async fn list(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<Alert>>> {
    let alerts = match user.role {
        UserRole::SuperAdmin => {
            state.db.list_alerts(None, None).await?
        }
        _ => {
            state.db.list_alerts(user.organization_id, None).await?
        }
    };
    
    Ok(Json(alerts))
}

/// Get a single alert
pub async fn get(
    Extension(state): Extension<Arc<AppState>>,
    _user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Alert>> {
    let alert = state.db.get_alert(id).await?
        .ok_or(AppError::NotFound("Alert not found".to_string()))?;
    
    Ok(Json(alert))
}

/// Create a new alert
pub async fn create(
    Extension(state): Extension<Arc<AppState>>,
    _user: AuthUser,
    Json(req): Json<CreateAlertRequest>,
) -> Result<Json<Alert>> {
    let alert = state.db.create_alert(req).await?;
    
    Ok(Json(alert))
}

/// Update an alert
pub async fn update(
    Extension(state): Extension<Arc<AppState>>,
    _user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateAlertRequest>,
) -> Result<Json<Alert>> {
    let _ = state.db.get_alert(id).await?
        .ok_or(AppError::NotFound("Alert not found".to_string()))?;
    
    let alert = state.db.update_alert(id, req).await?;
    
    Ok(Json(alert))
}

/// Resolve an alert
pub async fn resolve(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Alert>> {
    let alert = state.db.resolve_alert(id, user.id).await?;
    
    Ok(Json(alert))
}
