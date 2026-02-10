// Security Prime MSP Server - Authentication

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode, header},
    RequestPartsExt,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::UserRole;
use crate::error::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,           // User ID
    pub email: String,
    pub role: UserRole,
    pub org_id: Option<Uuid>,
    pub exp: i64,            // Expiration timestamp
    pub iat: i64,            // Issued at
}

impl Claims {
    pub fn new(user_id: Uuid, email: String, role: UserRole, org_id: Option<Uuid>, expires_in: Duration) -> Self {
        let now = Utc::now();
        Self {
            sub: user_id,
            email,
            role,
            org_id,
            exp: (now + expires_in).timestamp(),
            iat: now.timestamp(),
        }
    }
}

/// Generate a JWT token
pub fn create_token(claims: &Claims, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// Verify and decode a JWT token
pub fn verify_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

/// Hash a password using bcrypt
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    bcrypt::verify(password, hash)
}

/// Authenticated user extracted from request
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub role: UserRole,
    pub organization_id: Option<Uuid>,
}

/// Extractor for authenticated user from JWT
#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract Authorization header
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;
        
        // Check for Bearer token
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized)?;
        
        // Get JWT secret from app state
        // In a real app, this would come from the app state
        let jwt_secret = std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "change-this-secret-in-production".to_string());
        
        // Verify token
        let claims = verify_token(token, &jwt_secret)
            .map_err(|_| AppError::Unauthorized)?;
        
        // Check if token is expired
        if claims.exp < Utc::now().timestamp() {
            return Err(AppError::Unauthorized);
        }
        
        Ok(AuthUser {
            id: claims.sub,
            email: claims.email,
            role: claims.role,
            organization_id: claims.org_id,
        })
    }
}

/// Require specific role
pub fn require_role(user: &AuthUser, required_role: UserRole) -> Result<(), AppError> {
    match (&user.role, &required_role) {
        // Super admin can do everything
        (UserRole::SuperAdmin, _) => Ok(()),
        
        // MSP admin can manage their MSP
        (UserRole::MspAdmin, UserRole::MspAdmin) => Ok(()),
        (UserRole::MspAdmin, UserRole::MspUser) => Ok(()),
        (UserRole::MspAdmin, UserRole::ClientAdmin) => Ok(()),
        (UserRole::MspAdmin, UserRole::ClientUser) => Ok(()),
        
        // MSP user has limited access
        (UserRole::MspUser, UserRole::MspUser) => Ok(()),
        (UserRole::MspUser, UserRole::ClientUser) => Ok(()),
        
        // Client admin can manage their client
        (UserRole::ClientAdmin, UserRole::ClientAdmin) => Ok(()),
        (UserRole::ClientAdmin, UserRole::ClientUser) => Ok(()),
        
        // Client user has minimal access
        (UserRole::ClientUser, UserRole::ClientUser) => Ok(()),
        
        _ => Err(AppError::Forbidden),
    }
}

/// Check if user can access an organization
pub fn can_access_organization(user: &AuthUser, org_id: Uuid) -> Result<(), AppError> {
    match user.role {
        UserRole::SuperAdmin => Ok(()),
        UserRole::MspAdmin | UserRole::MspUser | UserRole::ClientAdmin | UserRole::ClientUser => {
            if user.organization_id == Some(org_id) {
                Ok(())
            } else {
                // In production, would also check if org is a child of user's org
                Err(AppError::Forbidden)
            }
        }
    }
}
