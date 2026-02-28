// Security Prime MSP Server - Licenses API Handlers

use axum::{
    extract::Path,
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{require_role, AuthUser};
use crate::error::{AppError, Result};
use crate::models::*;
use crate::AppState;

/// List licenses
pub async fn list(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<License>>> {
    require_role(&user, UserRole::MspAdmin)?;
    
    let licenses = match user.role {
        UserRole::SuperAdmin => state.db.list_licenses(None).await?,
        _ => state.db.list_licenses(user.organization_id).await?,
    };
    
    Ok(Json(licenses))
}

/// Get a single license
pub async fn get(
    Extension(_state): Extension<Arc<AppState>>,
    user: AuthUser,
    Path(_id): Path<Uuid>,
) -> Result<Json<License>> {
    require_role(&user, UserRole::MspAdmin)?;
    
    Err(AppError::NotFound("License not found".to_string()))
}

/// Create a new license
pub async fn create(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateLicenseRequest>,
) -> Result<Json<License>> {
    require_role(&user, UserRole::SuperAdmin)?;
    
    let license = state.db.create_license(req).await?;
    
    Ok(Json(license))
}

/// Revoke a license
pub async fn revoke(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<()>> {
    require_role(&user, UserRole::SuperAdmin)?;
    
    state.db.revoke_license(id).await?;
    
    Ok(Json(()))
}

/// Validate a license (called by agents)
pub async fn validate(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<ValidateLicenseRequest>,
) -> Result<Json<ValidateLicenseResponse>> {
    // Get license by key
    let license = match state.db.get_license_by_key(&req.license_key).await? {
        Some(l) => l,
        None => {
            return Ok(Json(ValidateLicenseResponse {
                valid: false,
                organization_name: None,
                features: vec![],
                expires_at: None,
                error: Some("Invalid license key".to_string()),
            }));
        }
    };
    
    // Check if expired
    if license.expires_at < chrono::Utc::now() {
        return Ok(Json(ValidateLicenseResponse {
            valid: false,
            organization_name: None,
            features: vec![],
            expires_at: Some(license.expires_at),
            error: Some("License has expired".to_string()),
        }));
    }
    
    // Get organization name
    let org = state.db.get_organization(license.organization_id).await?;
    
    Ok(Json(ValidateLicenseResponse {
        valid: true,
        organization_name: org.map(|o| o.name),
        features: license.features,
        expires_at: Some(license.expires_at),
        error: None,
    }))
}
