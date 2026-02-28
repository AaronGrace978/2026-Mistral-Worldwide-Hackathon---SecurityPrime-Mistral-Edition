// Cyber Security Prime - Module Registry
// Each security feature is implemented as a separate module for clean separation of concerns

pub mod agent;
pub mod app_control;
pub mod compliance;
pub mod encryption;
pub mod firewall;
pub mod flagship;
pub mod history;
pub mod isolation;
pub mod management;
pub mod network;
pub mod plugins;
pub mod report_generator;
pub mod reporting;
pub mod scanner;
pub mod secure_storage;
pub mod security_hardening;
pub mod tamper_detection;
pub mod vulnerability;
pub mod vpn;

use serde::{Deserialize, Serialize};

/// Trait that all security modules must implement
pub trait SecurityModule {
    /// Get the module name
    fn name(&self) -> &'static str;
    
    /// Get a description of the module
    fn description(&self) -> &'static str;
    
    /// Check if the module is currently active
    fn is_active(&self) -> bool;
    
    /// Initialize the module
    fn initialize(&mut self) -> Result<(), String>;
    
    /// Shutdown the module
    fn shutdown(&mut self) -> Result<(), String>;
    
    /// Perform a health check
    fn health_check(&self) -> ModuleHealth;
}

/// Health status of a module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleHealth {
    pub healthy: bool,
    pub message: String,
    pub last_check: String,
}

impl Default for ModuleHealth {
    fn default() -> Self {
        Self {
            healthy: true,
            message: "Module is operating normally".to_string(),
            last_check: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Module metadata for the registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub enabled: bool,
    pub health: ModuleHealth,
}

