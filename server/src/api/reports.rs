// Security Prime MSP Server - Reports API Handlers

use axum::{Extension, Json};
use std::sync::Arc;

use crate::auth::AuthUser;
use crate::error::Result;
use crate::models::*;
use crate::AppState;

/// Get dashboard summary
pub async fn summary(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<DashboardSummary>> {
    let summary = state.db.get_dashboard_summary(user.organization_id).await?;
    
    Ok(Json(summary))
}

/// Get threat report
pub async fn threat_report(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<ThreatReport>> {
    let report = state.db.get_threat_report(user.organization_id).await?;
    
    Ok(Json(report))
}

/// Get compliance report
pub async fn compliance_report(
    Extension(state): Extension<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<serde_json::Value>> {
    let report = state.db.get_compliance_report(user.organization_id).await?;
    
    Ok(Json(report))
}
