// Security Prime MSP Server - Users API Handlers

use axum::{
    extract::Path,
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{hash_password, require_role, AuthUser};
use crate::error::{AppError, Result};
use crate::models::*;
use crate::AppState;

/// List users
pub async fn list(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<UserPublic>>> {
    require_role(&user, UserRole::MspAdmin)?;
    
    let users = match user.role {
        UserRole::SuperAdmin => {
            state.db.list_users(None).await?
        }
        _ => {
            state.db.list_users(user.organization_id).await?
        }
    };
    
    let public_users: Vec<UserPublic> = users.into_iter().map(|u| u.into()).collect();
    
    Ok(Json(public_users))
}

/// Get a single user
pub async fn get(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<UserPublic>> {
    // Users can view themselves, admins can view others
    if user.id != id {
        require_role(&user, UserRole::MspAdmin)?;
    }
    
    let target_user = state.db.get_user_by_id(id).await?
        .ok_or(AppError::NotFound("User not found".to_string()))?;
    
    Ok(Json(target_user.into()))
}

/// Create a new user
pub async fn create(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserPublic>> {
    require_role(&user, UserRole::MspAdmin)?;
    
    // Check if email already exists
    if state.db.get_user_by_email(&req.email).await?.is_some() {
        return Err(AppError::Conflict("Email already registered".to_string()));
    }
    
    // Hash password
    let password_hash = hash_password(&req.password)?;
    
    // Create user
    let new_user = state.db.create_user(req, password_hash).await?;
    
    Ok(Json(new_user.into()))
}

/// Update a user
pub async fn update(
    Extension(_state): Extension<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(_req): Json<UpdateUserRequest>,
) -> Result<Json<UserPublic>> {
    // Users can update themselves, admins can update others
    if user.id != id {
        require_role(&user, UserRole::MspAdmin)?;
    }
    
    // TODO: Implement update
    Err(AppError::NotFound("User not found".to_string()))
}

/// Delete a user
pub async fn delete(
    Extension(_state): Extension<Arc<AppState>>,
    user: AuthUser,
    Path(_id): Path<Uuid>,
) -> Result<Json<()>> {
    require_role(&user, UserRole::SuperAdmin)?;
    
    // TODO: Implement soft delete
    Ok(Json(()))
}
