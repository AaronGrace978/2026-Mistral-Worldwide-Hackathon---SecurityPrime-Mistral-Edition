// Security Prime MSP Server
// REST API for managing multiple SecurityPrime endpoints

mod api;
mod auth;
mod db;
mod models;
mod error;

use axum::{
    routing::{get, post, put, delete},
    Router,
    Extension,
};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub db: db::Database,
    pub jwt_secret: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables
    dotenv::dotenv().ok();
    
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "security_prime_server=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    tracing::info!("Starting Security Prime MSP Server...");
    
    // Get configuration from environment
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/security_prime".to_string());
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "change-this-secret-in-production".to_string());
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .unwrap_or(3000);
    
    // Initialize database
    let db = db::Database::connect(&database_url).await?;
    db.run_migrations().await?;
    
    tracing::info!("Database connected and migrations applied");
    
    // Create app state
    let state = Arc::new(AppState {
        db,
        jwt_secret,
    });
    
    // Build router
    let app = Router::new()
        // Health check
        .route("/health", get(|| async { "OK" }))
        
        // Auth routes
        .route("/api/auth/login", post(api::auth::login))
        .route("/api/auth/refresh", post(api::auth::refresh_token))
        .route("/api/auth/register", post(api::auth::register))
        
        // Organization routes (protected)
        .route("/api/organizations", get(api::organizations::list).post(api::organizations::create))
        .route("/api/organizations/:id", get(api::organizations::get).put(api::organizations::update).delete(api::organizations::delete))
        .route("/api/organizations/:id/endpoints", get(api::organizations::get_endpoints))
        
        // Endpoint routes (protected)
        .route("/api/endpoints", get(api::endpoints::list))
        .route("/api/endpoints/:id", get(api::endpoints::get).delete(api::endpoints::delete))
        .route("/api/endpoints/heartbeat", post(api::endpoints::heartbeat))
        .route("/api/endpoints/events", post(api::endpoints::report_events))
        
        // Alert routes (protected)
        .route("/api/alerts", get(api::alerts::list).post(api::alerts::create))
        .route("/api/alerts/:id", get(api::alerts::get).put(api::alerts::update))
        .route("/api/alerts/:id/resolve", post(api::alerts::resolve))
        
        // User management routes (protected, admin only)
        .route("/api/users", get(api::users::list).post(api::users::create))
        .route("/api/users/:id", get(api::users::get).put(api::users::update).delete(api::users::delete))
        
        // Reports routes (protected)
        .route("/api/reports/summary", get(api::reports::summary))
        .route("/api/reports/threats", get(api::reports::threat_report))
        .route("/api/reports/compliance", get(api::reports::compliance_report))
        
        // License management routes (admin only)
        .route("/api/licenses", get(api::licenses::list).post(api::licenses::create))
        .route("/api/licenses/:id", get(api::licenses::get).delete(api::licenses::revoke))
        .route("/api/licenses/validate", post(api::licenses::validate))
        
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any))
        .layer(Extension(state));
    
    // Start server
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("Server listening on http://0.0.0.0:{}", port);
    
    axum::serve(listener, app).await?;
    
    Ok(())
}
