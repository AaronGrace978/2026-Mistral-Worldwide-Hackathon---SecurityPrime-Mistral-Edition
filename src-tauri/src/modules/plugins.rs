// Cyber Security Prime - Plugin System Module
// Extensible plugin architecture for third-party security tools

use crate::utils::generate_id;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plugin {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub homepage: Option<String>,
    pub category: PluginCategory,
    pub enabled: bool,
    pub installed_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    pub permissions: Vec<PluginPermission>,
    pub config: HashMap<String, serde_json::Value>,
    pub status: PluginStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PluginCategory {
    Scanner,
    Firewall,
    Encryption,
    NetworkMonitor,
    VulnerabilityScanner,
    ThreatIntelligence,
    DataProtection,
    Authentication,
    Reporting,
    Integration,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PluginPermission {
    FileSystemRead,
    FileSystemWrite,
    NetworkAccess,
    SystemInfo,
    ProcessList,
    RegistryAccess,
    AdminPrivileges,
    NotificationSend,
    SettingsModify,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PluginStatus {
    Active,
    Inactive,
    Error,
    Updating,
    Installing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub homepage: Option<String>,
    pub category: PluginCategory,
    pub permissions: Vec<PluginPermission>,
    pub min_app_version: String,
    pub entry_point: String,
    pub config_schema: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub plugin: Plugin,
    pub manifest: PluginManifest,
    pub health: PluginHealth,
    pub stats: PluginStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginHealth {
    pub healthy: bool,
    pub message: String,
    pub last_check: DateTime<Utc>,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginStats {
    pub invocations: u64,
    pub errors: u64,
    pub avg_response_ms: f32,
    pub last_invoked: Option<DateTime<Utc>>,
}

// ============================================================================
// Plugin Registry
// ============================================================================

lazy_static::lazy_static! {
    static ref PLUGIN_REGISTRY: Arc<RwLock<HashMap<String, Plugin>>> = Arc::new(RwLock::new(create_sample_plugins()));
}

fn create_sample_plugins() -> HashMap<String, Plugin> {
    let mut plugins = HashMap::new();
    
    // VirusTotal Integration
    let vt_id = generate_id();
    plugins.insert(vt_id.clone(), Plugin {
        id: vt_id,
        name: "VirusTotal Scanner".to_string(),
        version: "1.2.0".to_string(),
        description: "Scan files and URLs against 70+ antivirus engines using VirusTotal API".to_string(),
        author: "Security Prime Labs".to_string(),
        homepage: Some("https://virustotal.com".to_string()),
        category: PluginCategory::Scanner,
        enabled: true,
        installed_at: Utc::now(),
        updated_at: None,
        permissions: vec![
            PluginPermission::FileSystemRead,
            PluginPermission::NetworkAccess,
        ],
        config: {
            let mut c = HashMap::new();
            c.insert("api_key".to_string(), serde_json::json!(""));
            c.insert("auto_scan".to_string(), serde_json::json!(true));
            c
        },
        status: PluginStatus::Active,
    });
    
    // Shodan Integration
    let shodan_id = generate_id();
    plugins.insert(shodan_id.clone(), Plugin {
        id: shodan_id,
        name: "Shodan Network Intel".to_string(),
        version: "2.0.1".to_string(),
        description: "Lookup IP addresses and domains against Shodan's database of internet-connected devices".to_string(),
        author: "Security Prime Labs".to_string(),
        homepage: Some("https://shodan.io".to_string()),
        category: PluginCategory::ThreatIntelligence,
        enabled: false,
        installed_at: Utc::now(),
        updated_at: None,
        permissions: vec![
            PluginPermission::NetworkAccess,
        ],
        config: {
            let mut c = HashMap::new();
            c.insert("api_key".to_string(), serde_json::json!(""));
            c
        },
        status: PluginStatus::Inactive,
    });
    
    // Have I Been Pwned
    let hibp_id = generate_id();
    plugins.insert(hibp_id.clone(), Plugin {
        id: hibp_id,
        name: "Breach Monitor".to_string(),
        version: "1.0.0".to_string(),
        description: "Check if your email addresses have been compromised in data breaches using HIBP".to_string(),
        author: "Security Prime Labs".to_string(),
        homepage: Some("https://haveibeenpwned.com".to_string()),
        category: PluginCategory::DataProtection,
        enabled: true,
        installed_at: Utc::now(),
        updated_at: None,
        permissions: vec![
            PluginPermission::NetworkAccess,
            PluginPermission::NotificationSend,
        ],
        config: HashMap::new(),
        status: PluginStatus::Active,
    });
    
    // YubiKey Authentication
    let yubi_id = generate_id();
    plugins.insert(yubi_id.clone(), Plugin {
        id: yubi_id,
        name: "YubiKey Auth".to_string(),
        version: "1.1.0".to_string(),
        description: "Hardware security key authentication for sensitive operations".to_string(),
        author: "Security Prime Labs".to_string(),
        homepage: Some("https://yubico.com".to_string()),
        category: PluginCategory::Authentication,
        enabled: false,
        installed_at: Utc::now(),
        updated_at: None,
        permissions: vec![
            PluginPermission::SystemInfo,
        ],
        config: HashMap::new(),
        status: PluginStatus::Inactive,
    });
    
    // Custom Firewall Rules Importer
    let fw_id = generate_id();
    plugins.insert(fw_id.clone(), Plugin {
        id: fw_id,
        name: "pfSense Sync".to_string(),
        version: "0.9.0".to_string(),
        description: "Synchronize firewall rules with pfSense and OPNsense routers".to_string(),
        author: "Community".to_string(),
        homepage: None,
        category: PluginCategory::Firewall,
        enabled: false,
        installed_at: Utc::now(),
        updated_at: None,
        permissions: vec![
            PluginPermission::NetworkAccess,
            PluginPermission::SettingsModify,
        ],
        config: {
            let mut c = HashMap::new();
            c.insert("router_ip".to_string(), serde_json::json!(""));
            c.insert("api_token".to_string(), serde_json::json!(""));
            c
        },
        status: PluginStatus::Inactive,
    });
    
    plugins
}

// ============================================================================
// Tauri Commands
// ============================================================================

/// Get all installed plugins
#[tauri::command]
pub async fn get_plugins() -> Result<Vec<Plugin>, String> {
    let registry = PLUGIN_REGISTRY.read();
    Ok(registry.values().cloned().collect())
}

/// Install a plugin from manifest
#[tauri::command]
pub async fn install_plugin(manifest: PluginManifest) -> Result<Plugin, String> {
    let id = generate_id();
    
    let plugin = Plugin {
        id: id.clone(),
        name: manifest.name,
        version: manifest.version,
        description: manifest.description,
        author: manifest.author,
        homepage: manifest.homepage,
        category: manifest.category,
        enabled: false,
        installed_at: Utc::now(),
        updated_at: None,
        permissions: manifest.permissions,
        config: HashMap::new(),
        status: PluginStatus::Inactive,
    };
    
    let mut registry = PLUGIN_REGISTRY.write();
    registry.insert(id, plugin.clone());
    
    Ok(plugin)
}

/// Uninstall a plugin
#[tauri::command]
pub async fn uninstall_plugin(plugin_id: String) -> Result<bool, String> {
    let mut registry = PLUGIN_REGISTRY.write();
    
    if registry.remove(&plugin_id).is_some() {
        Ok(true)
    } else {
        Err("Plugin not found".to_string())
    }
}

/// Enable or disable a plugin
#[tauri::command]
pub async fn toggle_plugin(plugin_id: String, enabled: bool) -> Result<Plugin, String> {
    let mut registry = PLUGIN_REGISTRY.write();
    
    if let Some(plugin) = registry.get_mut(&plugin_id) {
        plugin.enabled = enabled;
        plugin.status = if enabled { PluginStatus::Active } else { PluginStatus::Inactive };
        plugin.updated_at = Some(Utc::now());
        Ok(plugin.clone())
    } else {
        Err("Plugin not found".to_string())
    }
}

/// Get detailed plugin info
#[tauri::command]
pub async fn get_plugin_info(plugin_id: String) -> Result<PluginInfo, String> {
    let registry = PLUGIN_REGISTRY.read();
    
    if let Some(plugin) = registry.get(&plugin_id) {
        let manifest = PluginManifest {
            name: plugin.name.clone(),
            version: plugin.version.clone(),
            description: plugin.description.clone(),
            author: plugin.author.clone(),
            homepage: plugin.homepage.clone(),
            category: plugin.category.clone(),
            permissions: plugin.permissions.clone(),
            min_app_version: "0.1.0".to_string(),
            entry_point: format!("plugins/{}/main.wasm", plugin.id),
            config_schema: None,
        };
        
        let health = PluginHealth {
            healthy: plugin.status == PluginStatus::Active,
            message: if plugin.status == PluginStatus::Active {
                "Plugin is running normally".to_string()
            } else {
                "Plugin is not active".to_string()
            },
            last_check: Utc::now(),
            uptime_seconds: if plugin.enabled { 3600 } else { 0 },
        };
        
        let stats = PluginStats {
            invocations: if plugin.enabled { 1247 } else { 0 },
            errors: if plugin.enabled { 3 } else { 0 },
            avg_response_ms: if plugin.enabled { 45.2 } else { 0.0 },
            last_invoked: if plugin.enabled { Some(Utc::now()) } else { None },
        };
        
        Ok(PluginInfo {
            plugin: plugin.clone(),
            manifest,
            health,
            stats,
        })
    } else {
        Err("Plugin not found".to_string())
    }
}

/// Update plugin configuration
#[tauri::command]
pub async fn update_plugin_config(
    plugin_id: String,
    config: HashMap<String, serde_json::Value>,
) -> Result<Plugin, String> {
    let mut registry = PLUGIN_REGISTRY.write();
    
    if let Some(plugin) = registry.get_mut(&plugin_id) {
        plugin.config = config;
        plugin.updated_at = Some(Utc::now());
        Ok(plugin.clone())
    } else {
        Err("Plugin not found".to_string())
    }
}

