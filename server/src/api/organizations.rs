// Security Prime MSP Server - Organizations API Handlers

use axum::{
    extract::Path,
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{AuthUser, can_access_organization, require_role};
use crate::error::{AppError, Result};
use crate::models::*;
use crate::AppState;

/// List organizations
pub async fn list(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<Organization>>> {
    let orgs = match user.role {
        UserRole::SuperAdmin => {
            state.db.list_organizations(None).await?
        }
        UserRole::MspAdmin | UserRole::MspUser => {
            // Get MSP's client organizations
            state.db.list_organizations(user.organization_id).await?
        }
        UserRole::ClientAdmin | UserRole::ClientUser => {
            // Get only their organization
            if let Some(org_id) = user.organization_id {
                if let Some(org) = state.db.get_organization(org_id).await? {
                    vec![org]
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        }
    };
    
    Ok(Json(orgs))
}

/// Get a single organization
pub async fn get(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Organization>> {
    can_access_organization(&user, id)?;
    
    let org = state.db.get_organization(id).await?
        .ok_or(AppError::NotFound("Organization not found".to_string()))?;
    
    Ok(Json(org))
}

/// Create a new organization
pub async fn create(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateOrganizationRequest>,
) -> Result<Json<Organization>> {
    // Only super admin and MSP admin can create organizations
    require_role(&user, UserRole::MspAdmin)?;
    
    let org = state.db.create_organization(req).await?;
    
    Ok(Json(org))
}

/// Update an organization
pub async fn update(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(_req): Json<UpdateOrganizationRequest>,
) -> Result<Json<Organization>> {
    can_access_organization(&user, id)?;
    require_role(&user, UserRole::MspAdmin)?;
    
    // TODO: Implement update
    let org = state.db.get_organization(id).await?
        .ok_or(AppError::NotFound("Organization not found".to_string()))?;
    
    Ok(Json(org))
}

/// Delete an organization
pub async fn delete(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<()>> {
    require_role(&user, UserRole::SuperAdmin)?;
    
    // TODO: Implement soft delete
    let _ = state.db.get_organization(id).await?
        .ok_or(AppError::NotFound("Organization not found".to_string()))?;
    
    Ok(Json(()))
}

/// Get endpoints for an organization
pub async fn get_endpoints(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Endpoint>>> {
    can_access_organization(&user, id)?;
    
    let endpoints = state.db.list_endpoints(Some(id)).await?;
    
    Ok(Json(endpoints))
}
