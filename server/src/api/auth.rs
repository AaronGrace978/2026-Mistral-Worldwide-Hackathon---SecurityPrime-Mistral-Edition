// Security Prime MSP Server - Auth API Handlers

use axum::{Extension, Json};
use chrono::Duration;
use std::sync::Arc;

use crate::auth::{create_token, hash_password, verify_password, Claims};
use crate::error::{AppError, Result};
use crate::models::*;
use crate::AppState;

/// Login endpoint
pub async fn login(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // Find user by email
    let user = state.db.get_user_by_email(&req.email).await?
        .ok_or(AppError::Unauthorized)?;
    
    // Verify password
    if !verify_password(&req.password, &user.password_hash)? {
        return Err(AppError::Unauthorized);
    }
    
    // Check if user is active
    if !user.is_active {
        return Err(AppError::Forbidden);
    }
    
    // Update last login
    state.db.update_user_last_login(user.id).await?;
    
    // Create tokens
    let access_claims = Claims::new(
        user.id,
        user.email.clone(),
        user.role.clone(),
        user.organization_id,
        Duration::hours(24),
    );
    
    let refresh_claims = Claims::new(
        user.id,
        user.email.clone(),
        user.role.clone(),
        user.organization_id,
        Duration::days(7),
    );
    
    let token = create_token(&access_claims, &state.jwt_secret)?;
    let refresh_token = create_token(&refresh_claims, &state.jwt_secret)?;
    
    Ok(Json(LoginResponse {
        token,
        refresh_token,
        user: user.into(),
        expires_at: chrono::Utc::now() + Duration::hours(24),
    }))
}

/// Refresh token endpoint
pub async fn refresh_token(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<Json<LoginResponse>> {
    // Verify refresh token
    let claims = crate::auth::verify_token(&req.refresh_token, &state.jwt_secret)?;
    
    // Get user
    let user = state.db.get_user_by_id(claims.sub).await?
        .ok_or(AppError::Unauthorized)?;
    
    // Check if user is still active
    if !user.is_active {
        return Err(AppError::Forbidden);
    }
    
    // Create new tokens
    let access_claims = Claims::new(
        user.id,
        user.email.clone(),
        user.role.clone(),
        user.organization_id,
        Duration::hours(24),
    );
    
    let refresh_claims = Claims::new(
        user.id,
        user.email.clone(),
        user.role.clone(),
        user.organization_id,
        Duration::days(7),
    );
    
    let token = create_token(&access_claims, &state.jwt_secret)?;
    let new_refresh_token = create_token(&refresh_claims, &state.jwt_secret)?;
    
    Ok(Json(LoginResponse {
        token,
        refresh_token: new_refresh_token,
        user: user.into(),
        expires_at: chrono::Utc::now() + Duration::hours(24),
    }))
}

/// Register endpoint (for initial setup / super admin)
pub async fn register(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserPublic>> {
    // Check if email already exists
    if state.db.get_user_by_email(&req.email).await?.is_some() {
        return Err(AppError::Conflict("Email already registered".to_string()));
    }
    
    // Hash password
    let password_hash = hash_password(&req.password)?;
    
    // Create user
    let user = state.db.create_user(req, password_hash).await?;
    
    Ok(Json(user.into()))
}
