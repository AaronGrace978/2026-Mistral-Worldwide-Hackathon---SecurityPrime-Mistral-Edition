// Cyber Security Prime - AI Security Agent Module
// Powered by Mistral AI (direct API + Ollama Cloud/Local)
// Supports streaming responses via Tauri events

use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::sync::Arc;
use parking_lot::RwLock;
use tauri::{AppHandle, Manager};
use crate::modules::secure_storage;
use std::path::Path;
use std::fs;
use std::collections::HashMap;
use base64::Engine as _;

const MISTRAL_DEFAULT_MODEL: &str = "mistral-large-3:675b";
const MISTRAL_FAST_MODEL: &str = "ministral:8b";
const MISTRAL_DEEP_MODEL: &str = "mistral-large-3:675b";

const MISTRAL_API_BASE: &str = "https://api.mistral.ai/v1";

/// Map Ollama-style model names to Mistral API model identifiers
fn ollama_to_mistral_model(ollama_name: &str) -> &'static str {
    let normalized = ollama_name.to_lowercase();
    if normalized.contains("mistral-large") {
        "mistral-large-latest"
    } else if normalized.contains("ministral") && normalized.contains("8b") {
        "ministral-8b-latest"
    } else if normalized.contains("devstral") {
        "devstral-small-latest"
    } else if normalized.contains("pixtral") {
        "pixtral-12b-2409"
    } else if normalized.contains("codestral") {
        "codestral-latest"
    } else if normalized.contains("mixtral") {
        "open-mixtral-8x7b"
    } else {
        "mistral-large-latest"
    }
}

/// Check if a direct Mistral API key is available
fn has_mistral_direct_key() -> bool {
    secure_storage::mistral_api_key_exists()
}

/// Get the direct Mistral API key
fn get_mistral_direct_key() -> Option<String> {
    secure_storage::get_mistral_api_key().ok()
}

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub default_model: String,
    pub fast_model: String,
    pub deep_model: String,
    pub timeout_secs: u64,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        // Try to load from cloud config file first
        if let Some(cloud_config) = load_cloud_config() {
            return cloud_config;
        }
        
        log::info!("Config file not found — using default Ollama Cloud settings");
        Self {
            base_url: "https://ollama.com".to_string(),
            api_key: None,
            default_model: MISTRAL_DEFAULT_MODEL.to_string(),
            fast_model: MISTRAL_FAST_MODEL.to_string(),
            deep_model: MISTRAL_DEEP_MODEL.to_string(),
            timeout_secs: 300,
        }
    }
}

fn is_mistral_model(model_name: &str) -> bool {
    let normalized = model_name.to_lowercase();
    let mistral_markers = ["mistral", "mixtral", "ministral", "codestral", "devstral", "pixtral"];
    mistral_markers.iter().any(|marker| normalized.contains(marker))
}

fn normalize_mistral_model(model_name: Option<String>, fallback: &str) -> String {
    if let Some(candidate) = model_name {
        if is_mistral_model(&candidate) {
            return candidate;
        }
    }

    if is_mistral_model(fallback) {
        fallback.to_string()
    } else {
        MISTRAL_DEFAULT_MODEL.to_string()
    }
}

fn enforce_mistral_config(config: &mut OllamaConfig) {
    config.default_model = normalize_mistral_model(Some(config.default_model.clone()), MISTRAL_DEFAULT_MODEL);
    config.fast_model = normalize_mistral_model(Some(config.fast_model.clone()), &config.default_model);
    config.deep_model = normalize_mistral_model(Some(config.deep_model.clone()), &config.default_model);
}

/// Load Ollama Cloud configuration from config file
fn load_cloud_config() -> Option<OllamaConfig> {
    let mut config_paths = vec![
        std::path::PathBuf::from("config/ollama_cloud_config.json"),
        std::path::PathBuf::from("../config/ollama_cloud_config.json"),
        std::path::PathBuf::from("../../config/ollama_cloud_config.json"),
    ];
    
    // Add path relative to executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            config_paths.push(exe_dir.join("config/ollama_cloud_config.json"));
            config_paths.push(exe_dir.join("../config/ollama_cloud_config.json"));
            config_paths.push(exe_dir.join("../../config/ollama_cloud_config.json"));
            config_paths.push(exe_dir.join("../../../config/ollama_cloud_config.json"));
        }
    }

    // Resolve from SECURITYPRIME_CONFIG_DIR env var if set (portable)
    if let Ok(config_dir) = std::env::var("SECURITYPRIME_CONFIG_DIR") {
        config_paths.push(std::path::PathBuf::from(&config_dir).join("ollama_cloud_config.json"));
    }

    // Resolve from CARGO_MANIFEST_DIR for development builds
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        config_paths.push(std::path::PathBuf::from(&manifest_dir).join("../config/ollama_cloud_config.json"));
    }
    
    for config_path in &config_paths {
        log::debug!("Trying config path: {:?}", config_path);
        if let Ok(content) = fs::read_to_string(config_path) {
            log::info!("Found cloud config at: {:?}", config_path);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                let ollama_cloud = json.get("ollama_cloud")?;
                let enabled = ollama_cloud.get("enabled")?.as_bool()?;
                
                if !enabled {
                    continue;
                }
                
                let api_key = ollama_cloud.get("api_key")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                
                let base_url = ollama_cloud.get("base_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("https://ollama.com")
                    .to_string();
                
                let timeout = ollama_cloud.get("timeout")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(300);
                
                // Get cloud models for defaults
                let cloud_models = json.get("cloud_models");
                
                // Find best models for each use case (Mistral-only)
                let default_model = find_model_for_task(cloud_models, "general_purpose")
                    .unwrap_or_else(|| MISTRAL_DEFAULT_MODEL.to_string());
                let fast_model = find_model_for_task(cloud_models, "efficient")
                    .unwrap_or_else(|| MISTRAL_FAST_MODEL.to_string());
                let deep_model = find_model_for_task(cloud_models, "threat_analysis")
                    .unwrap_or_else(|| MISTRAL_DEEP_MODEL.to_string());
                
                log::info!("Loaded Ollama Cloud config - base_url: {}, default_model: {}", base_url, default_model);
                let mut config = OllamaConfig {
                    base_url,
                    api_key,
                    default_model,
                    fast_model,
                    deep_model,
                    timeout_secs: timeout,
                };
                enforce_mistral_config(&mut config);
                return Some(config);
            }
        }
    }
    
    log::warn!("Could not find ollama_cloud_config.json, tried paths: {:?}", config_paths);
    None
}

/// Find the best model for a given task from cloud models config
fn find_model_for_task(cloud_models: Option<&serde_json::Value>, task: &str) -> Option<String> {
    let models = cloud_models?.as_object()?;
    
    for (model_id, model_info) in models {
        if !model_info.get("enabled")?.as_bool()? {
            continue;
        }
        if !is_mistral_model(model_id) {
            continue;
        }
        
        let best_for = model_info.get("best_for")?.as_array()?;
        for feature in best_for {
            if feature.as_str()? == task {
                // Get the default size or first size
                let size = model_info.get("default_size")
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        model_info.get("sizes")
                            .and_then(|s| s.as_array())
                            .and_then(|arr| arr.last())
                            .and_then(|v| v.as_str())
                    });
                
                if let Some(size) = size {
                    return Some(format!("{}:{}", model_id, size));
                }
                return Some(model_id.clone());
            }
        }
    }
    
    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub name: String,
    pub size: Option<u64>,
    pub modified_at: Option<String>,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<ChatOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_predict: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub model: String,
    pub message: ChatMessage,
    pub done: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_eval_count: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eval_count: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    pub id: String,
    pub created_at: String,
    pub messages: Vec<ChatMessage>,
    pub model: String,
    pub context: AgentContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentContext {
    pub security_score: Option<u8>,
    pub active_threats: Vec<String>,
    pub recent_scans: Vec<String>,
    pub system_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub connected: bool,
    pub available_models: Vec<ModelInfo>,
    pub current_model: String,
    pub session_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalysis {
    pub summary: String,
    pub risk_level: String,
    pub recommendations: Vec<String>,
    pub threats_detected: Vec<ThreatInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub name: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryScanResult {
    pub path: String,
    pub total_files: usize,
    pub total_dirs: usize,
    pub total_size_bytes: u64,
    pub file_types: HashMap<String, usize>,
    pub largest_files: Vec<FileInfo>,
    pub suspicious_files: Vec<SuspiciousFile>,
    pub health_issues: Vec<HealthIssue>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size_bytes: u64,
    pub file_type: String,
    pub modified: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousFile {
    pub path: String,
    pub reason: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthIssue {
    pub category: String,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

// ============================================================================
// Ollama Client
// ============================================================================

pub struct OllamaClient {
    client: Client,
    config: Arc<RwLock<OllamaConfig>>,
}

impl OllamaClient {
    pub fn new(config: OllamaConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            client,
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Check if this client is configured for Ollama Cloud
    fn is_cloud(&self) -> bool {
        let config = self.config.read();
        config.base_url.contains("ollama.com")
    }

    /// Get the API base URL, properly formatted for cloud or local
    fn get_api_base(&self) -> String {
        let config = self.config.read();
        let base = config.base_url.trim_end_matches('/').to_string();
        
        // For Ollama Cloud, ensure we use /api endpoint
        if base.contains("ollama.com") {
            if base.ends_with("/api") {
                base
            } else {
                format!("{}/api", base)
            }
        } else {
            // Local Ollama uses /api
            format!("{}/api", base)
        }
    }

    fn get_headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        
        // Try to get API key from secure storage first, then fallback to config
        let api_key = secure_storage::get_ollama_api_key()
            .ok()
            .or_else(|| {
                let config = self.config.read();
                config.api_key.clone()
            });
        
        if let Some(api_key) = api_key {
            if !api_key.is_empty() {
                headers.insert(
                    "Authorization",
                    format!("Bearer {}", api_key).parse().unwrap(),
                );
            }
        }
        
        headers
    }

    pub async fn test_connection(&self) -> Result<AgentStatus, String> {
        // If Mistral direct API key is available, use that as primary
        if has_mistral_direct_key() {
            let config = self.config.read();
            let current_model = normalize_mistral_model(Some(config.default_model.clone()), MISTRAL_DEFAULT_MODEL);
            
            let mistral_models = vec![
                ModelInfo {
                    name: "mistral-large-latest".to_string(),
                    size: None,
                    modified_at: None,
                    digest: Some("mistral-api".to_string()),
                },
                ModelInfo {
                    name: "ministral-8b-latest".to_string(),
                    size: None,
                    modified_at: None,
                    digest: Some("mistral-api".to_string()),
                },
                ModelInfo {
                    name: "devstral-small-latest".to_string(),
                    size: None,
                    modified_at: None,
                    digest: Some("mistral-api".to_string()),
                },
                ModelInfo {
                    name: "pixtral-12b-2409".to_string(),
                    size: None,
                    modified_at: None,
                    digest: Some("mistral-api".to_string()),
                },
                ModelInfo {
                    name: "codestral-latest".to_string(),
                    size: None,
                    modified_at: None,
                    digest: Some("mistral-api".to_string()),
                },
            ];
            
            return Ok(AgentStatus {
                connected: true,
                available_models: mistral_models,
                current_model: ollama_to_mistral_model(&current_model).to_string(),
                session_active: false,
            });
        }

        let (current_model, headers, is_cloud) = {
            let config = self.config.read();
            (
                normalize_mistral_model(Some(config.default_model.clone()), MISTRAL_DEFAULT_MODEL),
                self.get_headers(),
                config.base_url.contains("ollama.com"),
            )
        };

        // For Ollama Cloud, we can't list models the same way - just return configured models
        if is_cloud {
            // Cloud is considered connected if we have an API key
            let has_api_key = headers.get("Authorization").is_some();
            
            if has_api_key {
                // Return the configured cloud models as available
                let config = self.config.read();
                let cloud_models = vec![
                    ModelInfo {
                        name: normalize_mistral_model(Some(config.default_model.clone()), MISTRAL_DEFAULT_MODEL),
                        size: None,
                        modified_at: None,
                        digest: Some("cloud".to_string()),
                    },
                    ModelInfo {
                        name: normalize_mistral_model(Some(config.fast_model.clone()), MISTRAL_DEFAULT_MODEL),
                        size: None,
                        modified_at: None,
                        digest: Some("cloud".to_string()),
                    },
                    ModelInfo {
                        name: normalize_mistral_model(Some(config.deep_model.clone()), MISTRAL_DEFAULT_MODEL),
                        size: None,
                        modified_at: None,
                        digest: Some("cloud".to_string()),
                    },
                ];
                let mut unique_models: std::collections::HashMap<String, ModelInfo> = std::collections::HashMap::new();
                for model in cloud_models.into_iter().filter(|m| is_mistral_model(&m.name)) {
                    unique_models.insert(model.name.clone(), model);
                }
                
                return Ok(AgentStatus {
                    connected: true,
                    available_models: unique_models.into_values().collect(),
                    current_model: normalize_mistral_model(Some(current_model), MISTRAL_DEFAULT_MODEL),
                    session_active: false,
                });
            } else {
                return Err("Ollama Cloud requires an API key. Add one in the settings.".to_string());
            }
        }

        // Local Ollama - test connection with /api/tags
        let url = format!("{}/tags", self.get_api_base());

        match self.client.get(&url).headers(headers).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let data: serde_json::Value = response.json().await
                        .map_err(|e| e.to_string())?;
                    
                    let models: Vec<ModelInfo> = data["models"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().filter_map(|m| {
                                let name = m["name"].as_str()?.to_string();
                                if !is_mistral_model(&name) {
                                    return None;
                                }
                                Some(ModelInfo {
                                    name,
                                    size: m["size"].as_u64(),
                                    modified_at: m["modified_at"].as_str().map(String::from),
                                    digest: m["digest"].as_str().map(String::from),
                                })
                            }).collect()
                        })
                        .unwrap_or_default();

                    Ok(AgentStatus {
                        connected: true,
                        available_models: models,
                        current_model: normalize_mistral_model(Some(current_model), MISTRAL_DEFAULT_MODEL),
                        session_active: false,
                    })
                } else {
                    Err(format!("Ollama returned status: {}", response.status()))
                }
            }
            Err(e) => {
                if e.is_connect() {
                    Err("Ollama not running. Start with: ollama serve".to_string())
                } else {
                    Err(e.to_string())
                }
            }
        }
    }

    pub async fn get_models(&self) -> Result<Vec<ModelInfo>, String> {
        let status = self.test_connection().await?;
        Ok(status.available_models)
    }

    pub async fn chat(&self, messages: Vec<ChatMessage>, model: Option<String>, temperature: Option<f32>) -> Result<ChatResponse, String> {
        let (model_name, headers) = {
            let config = self.config.read();
            (
                normalize_mistral_model(model, &config.default_model),
                self.get_headers(),
            )
        };

        // Build URL using the proper API base
        let url = format!("{}/chat", self.get_api_base());

        let request = ChatRequest {
            model: model_name.clone(),
            messages,
            stream: false,
            options: Some(ChatOptions {
                temperature,
                num_predict: Some(4096),
            }),
        };

        log::info!("Sending chat request to {} with model {}", url, model_name);

        let response = self.client
            .post(&url)
            .headers(headers)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                log::error!("Chat request failed: {}", e);
                e.to_string()
            })?;

        if response.status().is_success() {
            response.json().await.map_err(|e| e.to_string())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            log::error!("Chat failed ({}): {}", status, body);
            Err(format!("Chat failed ({}): {}", status, body))
        }
    }

    /// Chat using the direct Mistral API (api.mistral.ai)
    async fn chat_mistral_direct(
        &self,
        messages: Vec<ChatMessage>,
        model: Option<String>,
        temperature: Option<f32>,
    ) -> Result<ChatResponse, String> {
        let api_key = get_mistral_direct_key()
            .ok_or("Mistral API key not found in secure storage")?;

        let ollama_model = {
            let config = self.config.read();
            normalize_mistral_model(model, &config.default_model)
        };
        let mistral_model = ollama_to_mistral_model(&ollama_model);

        let url = format!("{}/chat/completions", MISTRAL_API_BASE);

        let body = serde_json::json!({
            "model": mistral_model,
            "messages": messages,
            "temperature": temperature.unwrap_or(0.7),
            "max_tokens": 4096,
            "stream": false,
        });

        log::info!("Sending chat to Mistral API — model: {} (mapped from {})", mistral_model, ollama_model);

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Mistral API request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            log::error!("Mistral API error ({}): {}", status, body);
            return Err(format!("Mistral API error ({}): {}", status, body));
        }

        let data: serde_json::Value = response.json().await
            .map_err(|e| format!("Failed to parse Mistral API response: {}", e))?;

        let content = data["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(ChatResponse {
            model: mistral_model.to_string(),
            message: ChatMessage {
                role: "assistant".to_string(),
                content,
            },
            done: true,
            prompt_eval_count: data["usage"]["prompt_tokens"].as_i64().map(|v| v as i32),
            eval_count: data["usage"]["completion_tokens"].as_i64().map(|v| v as i32),
        })
    }

    /// Smart chat: tries direct Mistral API first, falls back to Ollama
    pub async fn smart_chat(
        &self,
        messages: Vec<ChatMessage>,
        model: Option<String>,
        temperature: Option<f32>,
    ) -> Result<ChatResponse, String> {
        if has_mistral_direct_key() {
            log::info!("Using direct Mistral API (api.mistral.ai)");
            match self.chat_mistral_direct(messages.clone(), model.clone(), temperature).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    log::warn!("Mistral direct API failed, falling back to Ollama: {}", e);
                }
            }
        }
        self.chat(messages, model, temperature).await
    }

    pub fn update_config(&self, new_config: OllamaConfig) {
        let mut config = self.config.write();
        *config = new_config;
    }
}

// ============================================================================
// Security Agent
// ============================================================================

lazy_static::lazy_static! {
    static ref OLLAMA_CLIENT: Arc<RwLock<Option<OllamaClient>>> = Arc::new(RwLock::new(None));
    static ref AGENT_SESSION: Arc<RwLock<Option<AgentSession>>> = Arc::new(RwLock::new(None));
}

/// Reset the Ollama client to reload config
pub fn reset_client() {
    let mut client_lock = OLLAMA_CLIENT.write();
    *client_lock = None;
    log::info!("Ollama client reset - will reload config on next use");
}

fn get_or_create_client() -> OllamaClient {
    let client_lock = OLLAMA_CLIENT.read();
    if client_lock.is_some() {
        drop(client_lock);
        return OLLAMA_CLIENT.read().as_ref().unwrap().clone();
    }
    drop(client_lock);

    // Load config (Default::default() will try cloud config first)
    let mut config = OllamaConfig::default();
    
    // Override API key from secure storage if available (takes precedence)
    if let Ok(api_key) = secure_storage::get_ollama_api_key() {
        if !api_key.is_empty() {
            config.api_key = Some(api_key);
        }
    }
    enforce_mistral_config(&mut config);
    
    log::info!("Initializing Ollama client — base_url: {}, model: {}, cloud: {}", 
               config.base_url, config.default_model, config.base_url.contains("ollama.com"));

    let new_client = OllamaClient::new(config);
    let mut client_lock = OLLAMA_CLIENT.write();
    *client_lock = Some(new_client.clone());
    new_client
}

impl Clone for OllamaClient {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            config: Arc::clone(&self.config),
        }
    }
}

// ============================================================================
// Tauri Commands
// ============================================================================

/// Reset the Ollama client to reload configuration AND clear the session
#[tauri::command]
pub async fn reset_agent_client() -> Result<String, String> {
    // Clear the cached session (this is what stores the old model name!)
    {
        let mut session_lock = AGENT_SESSION.write();
        *session_lock = None;
    }
    
    // Reset the client to reload config
    reset_client();
    
    // Recreate client with fresh config
    let client = get_or_create_client();
    let config = client.config.read();
    
    log::info!("Agent reset - base_url: {}, default_model: {}", config.base_url, config.default_model);
    
    Ok(format!("Client and session reset. Now using base_url: {}, model: {}", config.base_url, config.default_model))
}

/// Initialize or get agent status
#[tauri::command]
pub async fn get_agent_status() -> Result<AgentStatus, String> {
    let client = get_or_create_client();
    client.test_connection().await
}

/// Update Ollama configuration
#[tauri::command]
pub async fn configure_agent(mut config: OllamaConfig) -> Result<AgentStatus, String> {
    // Store API key securely if provided
    if let Some(api_key) = &config.api_key {
        if let Err(e) = secure_storage::store_ollama_api_key(api_key) {
            return Err(format!("Failed to store API key securely: {}", e));
        }
    }
    
    // Clear API key from config struct (it's now in secure storage)
    config.api_key = None;
    enforce_mistral_config(&mut config);
    
    let client = get_or_create_client();
    client.update_config(config);
    client.test_connection().await
}

/// Get available models
#[tauri::command]
pub async fn get_agent_models() -> Result<Vec<ModelInfo>, String> {
    let client = get_or_create_client();
    client.get_models().await
}

/// Start a new agent session
#[tauri::command]
pub async fn start_agent_session(model: Option<String>) -> Result<AgentSession, String> {
    let client = get_or_create_client();
    let model_name = {
        let config = client.config.read();
        normalize_mistral_model(model, &config.default_model)
    };

    let session = AgentSession {
        id: uuid::Uuid::new_v4().to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: get_security_system_prompt(),
            }
        ],
        model: model_name,
        context: AgentContext::default(),
    };

    let mut session_lock = AGENT_SESSION.write();
    *session_lock = Some(session.clone());

    Ok(session)
}

/// Send a message to the agent
#[tauri::command]
pub async fn chat_with_agent(message: String, model: Option<String>) -> Result<String, String> {
    let client = get_or_create_client();

    // Get or create session
    let needs_session = {
        let session_lock = AGENT_SESSION.read();
        session_lock.is_none()
    };

    if needs_session {
        start_agent_session(model.clone()).await?;
    }

    // Check if user wants to scan a directory
    let message_lower = message.to_lowercase();
    let scan_keywords = vec!["scan", "look at", "analyze", "check", "examine", "inspect"];
    let path_keywords = vec!["folder", "directory", "path", "folder", "system32", "c:\\", "d:\\"];
    
    let wants_scan = scan_keywords.iter().any(|kw| message_lower.contains(kw)) &&
                     (path_keywords.iter().any(|kw| message_lower.contains(kw)) || 
                      message_lower.contains("system") || 
                      message_lower.contains("pc") ||
                      message_lower.contains("computer"));
    
    // Try to extract path from message
    let mut scan_path: Option<String> = None;
    if wants_scan {
        // Try to extract Windows paths (C:\..., D:\...)
        for part in message.split_whitespace() {
            let part_clean = part.trim_matches(|c: char| c == '"' || c == '\'' || c == ',');
            if part_clean.starts_with("C:\\") || part_clean.starts_with("D:\\") || 
               part_clean.starts_with("E:\\") || part_clean.starts_with("F:\\") {
                scan_path = Some(part_clean.to_string());
                break;
            } else if part_clean.eq_ignore_ascii_case("system32") {
                scan_path = Some("C:\\Windows\\System32".to_string());
                break;
            }
        }
        
        // If no explicit path, check for common folder names
        if scan_path.is_none() {
            if message_lower.contains("system32") {
                scan_path = Some("C:\\Windows\\System32".to_string());
            } else if message_lower.contains("documents") {
                if let Ok(home) = std::env::var("USERPROFILE") {
                    scan_path = Some(format!("{}\\Documents", home));
                }
            } else if message_lower.contains("downloads") {
                if let Ok(home) = std::env::var("USERPROFILE") {
                    scan_path = Some(format!("{}\\Downloads", home));
                }
            } else if message_lower.contains("desktop") {
                if let Ok(home) = std::env::var("USERPROFILE") {
                    scan_path = Some(format!("{}\\Desktop", home));
                }
            }
        }
    }

    // Perform scan if requested
    let mut enhanced_message = message.clone();
    if let Some(path) = scan_path {
        match scan_directory_for_analysis(path.clone()).await {
            Ok(scan_result) => {
                let scan_data = serde_json::to_string(&scan_result)
                    .unwrap_or_else(|_| "Failed to serialize scan results".to_string());
                enhanced_message = format!(
                    "{}\n\n[Directory Scan Results for {}]\n{}\n\nPlease analyze these scan results and provide insights about PC health, security, and any recommendations.",
                    message,
                    path,
                    scan_data
                );
            }
            Err(e) => {
                enhanced_message = format!(
                    "{}\n\n[Note: Attempted to scan directory but encountered error: {}]",
                    message,
                    e
                );
            }
        }
    }

    // Add user message to session and get data for chat
    let (messages, model_to_use) = {
        let mut session_lock = AGENT_SESSION.write();
        if let Some(session) = session_lock.as_mut() {
            session.messages.push(ChatMessage {
                role: "user".to_string(),
                content: enhanced_message.clone(),
            });
            (
                session.messages.clone(),
                Some(normalize_mistral_model(model.or_else(|| Some(session.model.clone())), &session.model)),
            )
        } else {
            return Err("Failed to get or create session".to_string());
        }
    };

    let response = client.smart_chat(messages, model_to_use, Some(0.7)).await?;

    // Save assistant response
    {
        let mut session_lock = AGENT_SESSION.write();
        if let Some(session) = session_lock.as_mut() {
            session.messages.push(response.message.clone());
        }
    }

    Ok(response.message.content)
}

/// Analyze security with AI
#[tauri::command]
pub async fn analyze_security(context: String) -> Result<SecurityAnalysis, String> {
    let client = get_or_create_client();

    let prompt = format!(
        r#"You are a cybersecurity expert AI assistant. Analyze the following security context and provide a detailed security analysis.

Context:
{}

Provide your analysis in the following JSON format:
{{
    "summary": "Brief summary of the security situation",
    "risk_level": "low|medium|high|critical",
    "recommendations": ["recommendation 1", "recommendation 2", ...],
    "threats_detected": [
        {{
            "name": "Threat name",
            "severity": "low|medium|high|critical",
            "description": "Description of the threat",
            "remediation": "How to fix/mitigate"
        }}
    ]
}}

Respond ONLY with the JSON, no other text."#,
        context
    );

    let messages = vec![
        ChatMessage {
            role: "system".to_string(),
            content: "You are a cybersecurity expert. Always respond with valid JSON.".to_string(),
        },
        ChatMessage {
            role: "user".to_string(),
            content: prompt,
        },
    ];

    let deep_model = {
        let config = client.config.read();
        config.deep_model.clone()
    };

    let response = client.smart_chat(messages, Some(deep_model), Some(0.3)).await?;

    // Parse the JSON response
    let content = response.message.content.trim();
    let json_content = if content.starts_with("```json") {
        content.trim_start_matches("```json").trim_end_matches("```").trim()
    } else if content.starts_with("```") {
        content.trim_start_matches("```").trim_end_matches("```").trim()
    } else {
        content
    };

    serde_json::from_str(json_content).map_err(|_e| {
        format!("Failed to parse AI response. Raw response: {}", content)
    })
}

/// Get security recommendations
#[tauri::command]
pub async fn get_security_recommendations() -> Result<Vec<String>, String> {
    let client = get_or_create_client();

    let messages = vec![
        ChatMessage {
            role: "system".to_string(),
            content: "You are a cybersecurity expert. Provide actionable security recommendations.".to_string(),
        },
        ChatMessage {
            role: "user".to_string(),
            content: "Provide 5 practical security recommendations for a typical Windows user. Be specific and actionable. Format as a JSON array of strings.".to_string(),
        },
    ];

    let response = client.smart_chat(messages, None, Some(0.5)).await?;
    
    let content = response.message.content.trim();
    let json_content = if content.starts_with("[") {
        content
    } else if content.contains("[") {
        let start = content.find('[').unwrap();
        let end = content.rfind(']').unwrap_or(content.len() - 1) + 1;
        &content[start..end]
    } else {
        // Fallback: split by newlines
        return Ok(content.lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.trim_start_matches(|c: char| c.is_numeric() || c == '.' || c == '-' || c == ' ').to_string())
            .collect());
    };

    serde_json::from_str(json_content).map_err(|_e| {
        // Fallback to line-based parsing
        Ok::<Vec<String>, String>(content.lines()
            .filter(|l| !l.is_empty())
            .map(|s| s.to_string())
            .collect())
    }).unwrap_or_else(|v| v)
}

/// Clear agent session (also resets client to pick up new config)
#[tauri::command]
pub async fn clear_agent_session() -> Result<(), String> {
    let mut session_lock = AGENT_SESSION.write();
    *session_lock = None;
    drop(session_lock);
    
    // Also reset the client to pick up any new config
    reset_client();
    
    log::info!("Agent session cleared and client reset");
    Ok(())
}

// ============================================================================
// Streaming Chat
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    pub content: String,
    pub done: bool,
    pub model: String,
}

/// Send a message with streaming response via Tauri events
#[tauri::command]
pub async fn chat_with_agent_stream(
    app: AppHandle,
    message: String,
    model: Option<String>,
) -> Result<String, String> {
    let client = get_or_create_client();

    // Get or create session
    let needs_session = {
        let session_lock = AGENT_SESSION.read();
        session_lock.is_none()
    };

    if needs_session {
        start_agent_session(model.clone()).await?;
    }

    // Check if user wants to scan a directory (same logic as non-streaming)
    let message_lower = message.to_lowercase();
    let scan_keywords = vec!["scan", "look at", "analyze", "check", "examine", "inspect"];
    let path_keywords = vec!["folder", "directory", "path", "folder", "system32", "c:\\", "d:\\"];
    
    let wants_scan = scan_keywords.iter().any(|kw| message_lower.contains(kw)) &&
                     (path_keywords.iter().any(|kw| message_lower.contains(kw)) || 
                      message_lower.contains("system") || 
                      message_lower.contains("pc") ||
                      message_lower.contains("computer"));
    
    let mut scan_path: Option<String> = None;
    if wants_scan {
        for part in message.split_whitespace() {
            let part_clean = part.trim_matches(|c: char| c == '"' || c == '\'' || c == ',');
            if part_clean.starts_with("C:\\") || part_clean.starts_with("D:\\") || 
               part_clean.starts_with("E:\\") || part_clean.starts_with("F:\\") {
                scan_path = Some(part_clean.to_string());
                break;
            } else if part_clean.eq_ignore_ascii_case("system32") {
                scan_path = Some("C:\\Windows\\System32".to_string());
                break;
            }
        }
        
        if scan_path.is_none() {
            if message_lower.contains("system32") {
                scan_path = Some("C:\\Windows\\System32".to_string());
            } else if message_lower.contains("documents") {
                if let Ok(home) = std::env::var("USERPROFILE") {
                    scan_path = Some(format!("{}\\Documents", home));
                }
            } else if message_lower.contains("downloads") {
                if let Ok(home) = std::env::var("USERPROFILE") {
                    scan_path = Some(format!("{}\\Downloads", home));
                }
            } else if message_lower.contains("desktop") {
                if let Ok(home) = std::env::var("USERPROFILE") {
                    scan_path = Some(format!("{}\\Desktop", home));
                }
            }
        }
    }

    // Perform scan if requested
    let mut enhanced_message = message.clone();
    if let Some(path) = scan_path {
        match scan_directory_for_analysis(path.clone()).await {
            Ok(scan_result) => {
                let scan_data = serde_json::to_string(&scan_result)
                    .unwrap_or_else(|_| "Failed to serialize scan results".to_string());
                enhanced_message = format!(
                    "{}\n\n[Directory Scan Results for {}]\n{}\n\nPlease analyze these scan results and provide insights about PC health, security, and any recommendations.",
                    message,
                    path,
                    scan_data
                );
            }
            Err(e) => {
                enhanced_message = format!(
                    "{}\n\n[Note: Attempted to scan directory but encountered error: {}]",
                    message,
                    e
                );
            }
        }
    }

    // Add user message and get data for chat
    let (messages, model_to_use) = {
        let mut session_lock = AGENT_SESSION.write();
        if let Some(session) = session_lock.as_mut() {
            session.messages.push(ChatMessage {
                role: "user".to_string(),
                content: enhanced_message.clone(),
            });
            (
                session.messages.clone(),
                Some(normalize_mistral_model(model.or_else(|| Some(session.model.clone())), &session.model)),
            )
        } else {
            return Err("Failed to get or create session".to_string());
        }
    };

    // Determine if we should use Mistral direct API or Ollama
    let use_mistral_direct = has_mistral_direct_key();

    let (model_name, headers) = {
        let config = client.config.read();
        (
            normalize_mistral_model(model_to_use, &config.default_model),
            client.get_headers(),
        )
    };

    let (url, request_body, display_model) = if use_mistral_direct {
        let api_key = get_mistral_direct_key().unwrap_or_default();
        let mistral_model = ollama_to_mistral_model(&model_name).to_string();
        let url = format!("{}/chat/completions", MISTRAL_API_BASE);
        let body = serde_json::json!({
            "model": mistral_model,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 4096,
            "stream": true,
        });
        log::info!("Streaming via Mistral API — model: {}", mistral_model);
        (url, (body, Some(api_key)), mistral_model)
    } else {
        let url = format!("{}/chat", client.get_api_base());
        let request = ChatRequest {
            model: model_name.clone(),
            messages,
            stream: true,
            options: Some(ChatOptions {
                temperature: Some(0.7),
                num_predict: Some(4096),
            }),
        };
        let body = serde_json::to_value(&request).unwrap_or_default();
        log::info!("Streaming via Ollama — model: {}", model_name);
        (url, (body, None), model_name.clone())
    };

    // Send streaming request
    let mut req_builder = client.client.post(&url);
    if let Some(ref api_key) = request_body.1 {
        req_builder = req_builder
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json");
    } else {
        req_builder = req_builder.headers(headers);
    }
    let response = req_builder
        .json(&request_body.0)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Chat failed ({}): {}", status, body));
    }

    // Process streaming response
    let mut full_response = String::new();
    let mut stream = response.bytes_stream();
    
    use futures_util::StreamExt;
    
    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                let chunk_str = String::from_utf8_lossy(&chunk);
                
                for line in chunk_str.lines() {
                    if line.is_empty() {
                        continue;
                    }

                    if use_mistral_direct {
                        // Mistral API uses SSE: "data: {json}" or "data: [DONE]"
                        let data_line = line.strip_prefix("data: ").unwrap_or(line);
                        if data_line == "[DONE]" {
                            break;
                        }
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(data_line) {
                            if let Some(content) = parsed["choices"][0]["delta"]["content"].as_str() {
                                if !content.is_empty() {
                                    full_response.push_str(content);
                                    let _ = app.emit_all("agent-stream", StreamChunk {
                                        content: content.to_string(),
                                        done: false,
                                        model: display_model.clone(),
                                    });
                                }
                            }
                            if parsed["choices"][0]["finish_reason"].as_str() == Some("stop") {
                                break;
                            }
                        }
                    } else {
                        // Ollama sends newline-delimited JSON
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line) {
                            if let Some(msg) = parsed.get("message") {
                                if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                                    full_response.push_str(content);
                                    let _ = app.emit_all("agent-stream", StreamChunk {
                                        content: content.to_string(),
                                        done: parsed.get("done").and_then(|d| d.as_bool()).unwrap_or(false),
                                        model: display_model.clone(),
                                    });
                                }
                            }
                            if parsed.get("done").and_then(|d| d.as_bool()).unwrap_or(false) {
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                return Err(format!("Stream error: {}", e));
            }
        }
    }

    // Save assistant response to session
    {
        let mut session_lock = AGENT_SESSION.write();
        if let Some(session) = session_lock.as_mut() {
            session.messages.push(ChatMessage {
                role: "assistant".to_string(),
                content: full_response.clone(),
            });
        }
    }

    // Emit final done event
    let _ = app.emit_all("agent-stream-done", StreamChunk {
        content: String::new(),
        done: true,
        model: display_model,
    });

    Ok(full_response)
}

/// Get current session
#[tauri::command]
pub async fn get_agent_session() -> Result<Option<AgentSession>, String> {
    let session_lock = AGENT_SESSION.read();
    Ok(session_lock.clone())
}

// ============================================================================
// Secure API Key Management
// ============================================================================

/// Store Ollama API key securely in OS keychain
#[tauri::command]
pub async fn store_ollama_api_key(api_key: String) -> Result<(), String> {
    secure_storage::store_ollama_api_key(&api_key)
        .map_err(|e| format!("Failed to store API key: {}", e))
}

/// Check if Ollama API key exists in secure storage
#[tauri::command]
pub async fn has_ollama_api_key() -> Result<bool, String> {
    Ok(secure_storage::ollama_api_key_exists())
}

/// Delete Ollama API key from secure storage
#[tauri::command]
pub async fn delete_ollama_api_key() -> Result<(), String> {
    secure_storage::delete_ollama_api_key()
        .map_err(|e| format!("Failed to delete API key: {}", e))
}

/// Store Mistral API key securely in OS keychain (for direct api.mistral.ai access)
#[tauri::command]
pub async fn store_mistral_api_key(api_key: String) -> Result<(), String> {
    secure_storage::store_mistral_api_key(&api_key)
        .map_err(|e| format!("Failed to store Mistral API key: {}", e))
}

/// Check if Mistral API key exists in secure storage
#[tauri::command]
pub async fn has_mistral_api_key() -> Result<bool, String> {
    Ok(secure_storage::mistral_api_key_exists())
}

/// Delete Mistral API key from secure storage
#[tauri::command]
pub async fn delete_mistral_api_key() -> Result<(), String> {
    secure_storage::delete_mistral_api_key()
        .map_err(|e| format!("Failed to delete Mistral API key: {}", e))
}

/// Get which AI provider is currently active
#[tauri::command]
pub async fn get_ai_provider() -> Result<String, String> {
    if has_mistral_direct_key() {
        Ok("mistral".to_string())
    } else if secure_storage::ollama_api_key_exists() {
        Ok("ollama-cloud".to_string())
    } else {
        Ok("ollama-local".to_string())
    }
}

// ============================================================================
// ElevenLabs TTS Integration
// ============================================================================

#[tauri::command]
pub async fn store_elevenlabs_api_key(api_key: String) -> Result<(), String> {
    secure_storage::store_elevenlabs_api_key(&api_key)
        .map_err(|e| format!("Failed to store ElevenLabs API key: {}", e))
}

#[tauri::command]
pub async fn has_elevenlabs_api_key() -> Result<bool, String> {
    Ok(secure_storage::elevenlabs_api_key_exists())
}

#[tauri::command]
pub async fn delete_elevenlabs_api_key() -> Result<(), String> {
    secure_storage::delete_elevenlabs_api_key()
        .map_err(|e| format!("Failed to delete ElevenLabs API key: {}", e))
}

/// Convert text to speech using ElevenLabs API, returns base64-encoded MP3 audio
#[tauri::command]
pub async fn text_to_speech(text: String, voice_id: Option<String>) -> Result<String, String> {
    let api_key = secure_storage::get_elevenlabs_api_key()
        .map_err(|_| "ElevenLabs API key not found. Add it in Settings.".to_string())?;

    let voice = voice_id.unwrap_or_else(|| "5cVNuMBWdU6DJjJJdH0A".to_string());

    let client = Client::new();
    let url = format!("https://api.elevenlabs.io/v1/text-to-speech/{}", voice);

    let body = serde_json::json!({
        "text": text,
        "model_id": "eleven_multilingual_v2",
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.75,
            "style": 0.3,
            "use_speaker_boost": true
        }
    });

    let response = client
        .post(&url)
        .header("xi-api-key", &api_key)
        .header("Content-Type", "application/json")
        .header("Accept", "audio/mpeg")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("ElevenLabs API request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("ElevenLabs API error ({}): {}", status, body));
    }

    let audio_bytes = response.bytes().await
        .map_err(|e| format!("Failed to read audio response: {}", e))?;

    Ok(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &audio_bytes))
}

/// Get available ElevenLabs voices
#[tauri::command]
pub async fn get_elevenlabs_voices() -> Result<serde_json::Value, String> {
    let api_key = secure_storage::get_elevenlabs_api_key()
        .map_err(|_| "ElevenLabs API key not found".to_string())?;

    let client = Client::new();
    let response = client
        .get("https://api.elevenlabs.io/v1/voices")
        .header("xi-api-key", &api_key)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch voices: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Failed to fetch voices: {}", response.status()));
    }

    response.json().await.map_err(|e| format!("Failed to parse voices: {}", e))
}

// ============================================================================
// Pixtral Vision Analysis
// ============================================================================

/// Analyze an image using Pixtral vision model via Mistral API
#[tauri::command]
pub async fn analyze_image_with_pixtral(
    image_base64: String,
    prompt: Option<String>,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    let api_key = get_mistral_direct_key()
        .ok_or("Mistral API key required for Pixtral vision analysis")?;

    let analysis_prompt = prompt.unwrap_or_else(|| {
        "You are a cybersecurity forensic analyst. Analyze this image for security-relevant information. \
         Look for: suspicious processes, network connections, error messages, malware indicators, \
         configuration issues, exposed credentials, suspicious URLs, or any security anomalies. \
         Provide a detailed security assessment.".to_string()
    });

    let messages = serde_json::json!([
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": analysis_prompt
                },
                {
                    "type": "image_url",
                    "image_url": {
                        "url": format!("data:image/png;base64,{}", image_base64)
                    }
                }
            ]
        }
    ]);

    let body = serde_json::json!({
        "model": "pixtral-large-latest",
        "messages": messages,
        "max_tokens": 4096,
        "temperature": 0.3,
        "stream": true,
    });

    let client = Client::new();
    let response = client
        .post(format!("{}/chat/completions", MISTRAL_API_BASE))
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Pixtral API request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let err_body = response.text().await.unwrap_or_default();
        return Err(format!("Pixtral API error ({}): {}", status, err_body));
    }

    // Stream the response
    let mut full_response = String::new();
    let mut stream = response.bytes_stream();

    use futures_util::StreamExt;

    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                let chunk_str = String::from_utf8_lossy(&chunk);
                for line in chunk_str.lines() {
                    let data_line = line.strip_prefix("data: ").unwrap_or(line);
                    if data_line == "[DONE]" || data_line.is_empty() { continue; }
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(data_line) {
                        if let Some(content) = parsed["choices"][0]["delta"]["content"].as_str() {
                            full_response.push_str(content);
                            let _ = app_handle.emit_all("pixtral-stream", serde_json::json!({
                                "content": content,
                                "done": false,
                            }));
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("Pixtral stream error: {}", e);
                break;
            }
        }
    }

    let _ = app_handle.emit_all("pixtral-stream", serde_json::json!({
        "content": "",
        "done": true,
    }));

    Ok(full_response)
}

// ============================================================================
// PRIME Briefing — ambient intelligence status narration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimeBriefing {
    pub briefing_id: String,
    pub timestamp: String,
    pub narrative: String,
    pub headline: String,
    pub mood: String,       // "calm", "alert", "critical"
    pub facts_count: usize,
}

/// Gather live system telemetry and have the AI write a detective-style briefing.
/// Uses smart_chat (Mistral direct → Ollama fallback) so it works with either key.
#[tauri::command]
pub async fn generate_prime_briefing() -> Result<PrimeBriefing, String> {
    let now = chrono::Local::now();
    let time_str = now.format("%I:%M %p").to_string();
    let date_str = now.format("%A, %B %e, %Y").to_string();

    // Gather live telemetry
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    let cpus = sys.cpus();
    let cpu_usage = if cpus.is_empty() { 0.0 } else {
        cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
    };
    let total_mem = sys.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0);
    let used_mem = sys.used_memory() as f64 / (1024.0 * 1024.0 * 1024.0);
    let mem_pct = (used_mem / total_mem) * 100.0;
    let process_count = sys.processes().len();

    let netstat = std::process::Command::new("netstat")
        .args(["-an"])
        .output();
    let (established, listening) = if let Ok(out) = netstat {
        let text = String::from_utf8_lossy(&out.stdout);
        let est = text.lines().filter(|l| l.contains("ESTABLISHED")).count();
        let lis = text.lines().filter(|l| l.contains("LISTENING")).count();
        (est, lis)
    } else {
        (0, 0)
    };

    let mut top_procs: Vec<String> = sys.processes().values()
        .map(|p| p.name().to_string())
        .collect();
    top_procs.sort();
    top_procs.dedup();
    top_procs.truncate(15);

    let telemetry = format!(
        "Current time: {time} on {date}\n\
         CPU usage: {cpu:.1}%\n\
         Memory: {mem_used:.1} GB / {mem_total:.1} GB ({mem_pct:.0}% used)\n\
         Active processes: {procs}\n\
         Network: {est} established connections, {lis} listening ports\n\
         Notable processes running: {top}\n",
        time = time_str, date = date_str, cpu = cpu_usage,
        mem_used = used_mem, mem_total = total_mem, mem_pct = mem_pct,
        procs = process_count, est = established, lis = listening,
        top = top_procs.join(", ")
    );

    let prompt = format!(
        "You are PRIME, an elite AI cybersecurity analyst embedded in a desktop security suite.\n\
         You speak in first person like a detective giving a status briefing — confident, observant,\n\
         occasionally dramatic but always grounded in data.\n\n\
         Here is the live telemetry from the system you're protecting:\n\n\
         {telemetry}\n\n\
         Write a short briefing (3-5 paragraphs, under 200 words total). Things to include:\n\
         - Open with the time and a one-line mood read (\"Quiet night\" or \"Busy afternoon\")\n\
         - Call out anything interesting: high CPU, many connections, suspicious process names\n\
         - Mention specific numbers — processes, connections, memory\n\
         - Sprinkle in one cybersecurity fact or tip naturally\n\
         - Close with your assessment: is the system looking clean, or should the operator worry?\n\
         - Tone: film-noir detective meets SOC analyst. Dry wit welcome.\n\n\
         Also provide:\n\
         1. A one-line HEADLINE (max 8 words, punchy)\n\
         2. A MOOD: one of \"calm\", \"alert\", or \"critical\"\n\n\
         Format your response as JSON:\n\
         {{\"headline\": \"...\", \"mood\": \"...\", \"narrative\": \"...\"}}\n\
         Return ONLY valid JSON, no markdown fences.",
        telemetry = telemetry
    );

    // Use the existing smart_chat infrastructure (Mistral direct → Ollama fallback)
    let client = get_or_create_client();
    let messages = vec![
        ChatMessage {
            role: "user".to_string(),
            content: prompt,
        }
    ];
    let response = client.smart_chat(messages, None, Some(0.8)).await?;
    let raw_content = response.message.content.clone();

    let raw = raw_content
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap_or_else(|_| {
        serde_json::json!({
            "headline": "System Status Report",
            "mood": "calm",
            "narrative": raw
        })
    });

    Ok(PrimeBriefing {
        briefing_id: format!("PB-{}", now.format("%H%M%S")),
        timestamp: now.format("%Y-%m-%d %H:%M:%S").to_string(),
        narrative: parsed["narrative"].as_str().unwrap_or(raw).to_string(),
        headline: parsed["headline"].as_str().unwrap_or("Status Report").to_string(),
        mood: parsed["mood"].as_str().unwrap_or("calm").to_string(),
        facts_count: process_count,
    })
}

// ============================================================================
// Investigation Dossier — Pixtral forensics + Mistral narration + ElevenLabs TTS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DossierFinding {
    pub id: String,
    pub timestamp: String,
    pub category: String,
    pub title: String,
    pub detail: String,
    pub severity: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationDossier {
    pub case_id: String,
    pub created_at: String,
    pub classification: String,
    pub subject: String,
    pub findings: Vec<DossierFinding>,
    pub risk_assessment: String,
    pub narrative: String,
    pub analyst_notes: String,
}

/// Generate a full investigation dossier from an uploaded image.
/// Pixtral analyzes the image → Mistral Large writes a detective-style briefing.
#[tauri::command]
pub async fn generate_investigation_dossier(
    image_base64: String,
    context: Option<String>,
    app_handle: tauri::AppHandle,
) -> Result<InvestigationDossier, String> {
    let api_key = get_mistral_direct_key()
        .ok_or("Mistral API key required for investigation dossier")?;

    let ctx = context.unwrap_or_else(|| "General security investigation".to_string());
    let case_id = format!("CSP-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let created_at = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    // ── Stage 1: Pixtral forensic image analysis ────────────────────────
    let _ = app_handle.emit_all("dossier-progress", serde_json::json!({
        "stage": "analyzing", "message": "Pixtral is examining the evidence..."
    }));

    let pixtral_prompt = format!(
        "You are an elite cybersecurity forensic analyst codenamed PRIME.\n\
         Context: {}\n\n\
         Analyze this screenshot/image with extreme attention to detail.\n\
         Return your findings as a JSON array. Each finding must have:\n\
         - \"category\": one of [\"network\", \"process\", \"credential\", \"malware\", \"config\", \"anomaly\", \"info\"]\n\
         - \"title\": short headline (max 10 words)\n\
         - \"detail\": 1-3 sentence explanation of what you see\n\
         - \"severity\": one of [\"critical\", \"high\", \"medium\", \"low\", \"info\"]\n\
         - \"confidence\": 0.0 to 1.0\n\n\
         Look for: running processes, open ports, network connections, error messages,\n\
         exposed credentials, suspicious URLs, misconfigurations, browser tabs,\n\
         terminal commands, open applications, taskbar items, system tray icons,\n\
         IP addresses, file paths, registry entries, or anything security-relevant.\n\n\
         Be thorough. Even mundane details matter in forensics.\n\
         Return ONLY valid JSON — no markdown, no code fences.\n\
         Example: [{{\"category\":\"process\",\"title\":\"Suspicious PowerShell\",\"detail\":\"...\",\"severity\":\"high\",\"confidence\":0.9}}]",
        ctx
    );

    let pixtral_messages = serde_json::json!([{
        "role": "user",
        "content": [
            { "type": "text", "text": pixtral_prompt },
            { "type": "image_url", "image_url": { "url": format!("data:image/png;base64,{}", image_base64) } }
        ]
    }]);

    let pixtral_body = serde_json::json!({
        "model": "pixtral-large-latest",
        "messages": pixtral_messages,
        "max_tokens": 4096,
        "temperature": 0.2,
    });

    let client = Client::new();
    let pixtral_resp = client
        .post(format!("{}/chat/completions", MISTRAL_API_BASE))
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&pixtral_body)
        .send()
        .await
        .map_err(|e| format!("Pixtral request failed: {}", e))?;

    if !pixtral_resp.status().is_success() {
        let s = pixtral_resp.status();
        let b = pixtral_resp.text().await.unwrap_or_default();
        return Err(format!("Pixtral error ({}): {}", s, b));
    }

    let pixtral_json: serde_json::Value = pixtral_resp.json().await
        .map_err(|e| format!("Failed to parse Pixtral response: {}", e))?;

    let raw_findings = pixtral_json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("[]")
        .to_string();

    // Parse findings - strip markdown fences if Pixtral wraps them
    let clean_findings = raw_findings
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let parsed_findings: Vec<serde_json::Value> = serde_json::from_str(clean_findings)
        .unwrap_or_else(|_| {
            vec![serde_json::json!({
                "category": "info",
                "title": "Image analyzed",
                "detail": raw_findings,
                "severity": "info",
                "confidence": 0.5
            })]
        });

    let ts_now = chrono::Utc::now();
    let findings: Vec<DossierFinding> = parsed_findings.iter().enumerate().map(|(i, f)| {
        DossierFinding {
            id: format!("F-{:03}", i + 1),
            timestamp: (ts_now - chrono::Duration::minutes(i as i64))
                .format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            category: f["category"].as_str().unwrap_or("info").to_string(),
            title: f["title"].as_str().unwrap_or("Finding").to_string(),
            detail: f["detail"].as_str().unwrap_or("").to_string(),
            severity: f["severity"].as_str().unwrap_or("info").to_string(),
            confidence: f["confidence"].as_f64().unwrap_or(0.5),
        }
    }).collect();

    // Risk assessment
    let crit = findings.iter().filter(|f| f.severity == "critical").count();
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let risk_assessment = if crit > 0 {
        "CRITICAL — Immediate action required".to_string()
    } else if high > 0 {
        "HIGH — Significant security concerns identified".to_string()
    } else if findings.iter().any(|f| f.severity == "medium") {
        "MODERATE — Items warrant further investigation".to_string()
    } else {
        "LOW — No immediate threats detected".to_string()
    };

    let classification = if crit > 0 { "TOP SECRET" }
        else if high > 0 { "CLASSIFIED" }
        else { "CONFIDENTIAL" }.to_string();

    // ── Stage 2: Mistral Large writes detective-style narration ──────────
    let _ = app_handle.emit_all("dossier-progress", serde_json::json!({
        "stage": "narrating", "message": "Composing intelligence briefing..."
    }));

    let findings_summary: Vec<String> = findings.iter().map(|f| {
        format!("[{}] {} ({}): {}", f.severity.to_uppercase(), f.title, f.category, f.detail)
    }).collect();

    let narration_prompt = format!(
        "You are PRIME, an elite AI cybersecurity analyst delivering a threat intelligence briefing.\n\
         You speak like a seasoned detective — precise, dramatic where warranted, matter-of-fact.\n\
         Use timestamps, reference specific findings by their IDs, and connect dots between evidence.\n\n\
         Case ID: {}\n\
         Classification: {}\n\
         Risk Assessment: {}\n\n\
         Findings:\n{}\n\n\
         Write a 3-5 paragraph intelligence briefing narration. First person.\n\
         Start with something like \"Case {} — here's what I found.\"\n\
         Reference specific timestamps and finding IDs.\n\
         End with your recommendation: what the operator should do next.\n\
         Tone: think film-noir detective meets cyber threat analyst.\n\
         Keep it under 300 words — this will be read aloud.",
        case_id, classification, risk_assessment,
        findings_summary.join("\n"), case_id
    );

    let narr_body = serde_json::json!({
        "model": "mistral-large-latest",
        "messages": [{ "role": "user", "content": narration_prompt }],
        "max_tokens": 1500,
        "temperature": 0.7,
    });

    let narr_resp = client
        .post(format!("{}/chat/completions", MISTRAL_API_BASE))
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&narr_body)
        .send()
        .await
        .map_err(|e| format!("Narration request failed: {}", e))?;

    let narrative = if narr_resp.status().is_success() {
        let narr_json: serde_json::Value = narr_resp.json().await.unwrap_or_default();
        narr_json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("Briefing generation failed — please review findings manually.")
            .to_string()
    } else {
        "Unable to generate narration. Review the findings above.".to_string()
    };

    let _ = app_handle.emit_all("dossier-progress", serde_json::json!({
        "stage": "complete", "message": "Dossier ready."
    }));

    Ok(InvestigationDossier {
        case_id,
        created_at,
        classification,
        subject: ctx,
        findings,
        risk_assessment,
        narrative,
        analyst_notes: format!("{} findings extracted. {} critical, {} high severity.",
            parsed_findings.len(), crit, high),
    })
}

/// Narrate text through ElevenLabs TTS — returns base64 audio
#[tauri::command]
pub async fn narrate_dossier(
    text: String,
    voice_id: Option<String>,
) -> Result<String, String> {
    let api_key = secure_storage::get_elevenlabs_api_key()
        .map_err(|_| "ElevenLabs API key not found. Add it in Settings to enable voice briefings.".to_string())?;

    let voice = voice_id.unwrap_or_else(|| "5cVNuMBWdU6DJjJJdH0A".to_string());

    let client = Client::new();
    let url = format!("https://api.elevenlabs.io/v1/text-to-speech/{}", voice);

    let body = serde_json::json!({
        "text": text,
        "model_id": "eleven_multilingual_v2",
        "voice_settings": {
            "stability": 0.65,
            "similarity_boost": 0.8,
            "style": 0.45,
            "use_speaker_boost": true
        }
    });

    let response = client
        .post(&url)
        .header("xi-api-key", &api_key)
        .header("Content-Type", "application/json")
        .header("Accept", "audio/mpeg")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("ElevenLabs API request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let err = response.text().await.unwrap_or_default();
        return Err(format!("ElevenLabs error ({}): {}", status, err));
    }

    let audio_bytes = response.bytes().await
        .map_err(|e| format!("Failed to read audio: {}", e))?;

    let encoded = base64::engine::general_purpose::STANDARD.encode(&audio_bytes);
    Ok(encoded)
}

// ============================================================================
// Directory Scanning Functions
// ============================================================================

/// Scan a directory and collect metadata for AI analysis
#[tauri::command]
pub async fn scan_directory_for_analysis(path: String) -> Result<DirectoryScanResult, String> {
    let dir_path = Path::new(&path);
    
    if !dir_path.exists() {
        return Err(format!("Directory does not exist: {}", path));
    }
    
    if !dir_path.is_dir() {
        return Err(format!("Path is not a directory: {}", path));
    }
    
    // Safety check: Warn about critical system directories but allow scanning (read-only)
    let path_lower = path.to_lowercase();
    let critical_dirs = vec![
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\windows\\winsxs",
    ];
    
    let is_critical = critical_dirs.iter().any(|d| path_lower.contains(d));
    let max_depth = if is_critical { 3 } else { 10 }; // Limit depth for critical dirs
    
    let mut result = DirectoryScanResult {
        path: path.clone(),
        total_files: 0,
        total_dirs: 0,
        total_size_bytes: 0,
        file_types: HashMap::new(),
        largest_files: Vec::new(),
        suspicious_files: Vec::new(),
        health_issues: Vec::new(),
        summary: String::new(),
    };
    
    // Add warning for critical directories
    if is_critical {
        result.health_issues.push(HealthIssue {
            category: "Security".to_string(),
            severity: "high".to_string(),
            description: "Scanning critical system directory. This is a read-only analysis - no files will be modified.".to_string(),
            recommendation: "Be extremely cautious. Never delete files from system directories without expert guidance.".to_string(),
        });
    }
    
    // Scan directory recursively (with depth limit for safety)
    scan_directory_recursive(dir_path, &mut result, 0, max_depth)?;
    
    // Analyze findings
    analyze_scan_results(&mut result);
    
    Ok(result)
}

fn scan_directory_recursive(
    dir: &Path,
    result: &mut DirectoryScanResult,
    depth: usize,
    max_depth: usize,
) -> Result<(), String> {
    if depth > max_depth {
        return Ok(()); // Prevent infinite recursion
    }
    
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("Failed to read directory {}: {}", dir.display(), e))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path();
        let metadata = entry.metadata()
            .map_err(|e| format!("Failed to get metadata for {}: {}", path.display(), e))?;
        
        if metadata.is_dir() {
            result.total_dirs += 1;
            
            // Skip certain system directories to avoid issues
            let dir_name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            
            // Skip hidden/system directories and common system folders
            if !dir_name.starts_with('.') && 
               dir_name != "System Volume Information" &&
               dir_name != "$Recycle.Bin" &&
               dir_name != "Recovery" {
                let _ = scan_directory_recursive(&path, result, depth + 1, max_depth);
            }
        } else if metadata.is_file() {
            result.total_files += 1;
            
            let file_size = metadata.len();
            result.total_size_bytes += file_size;
            
            // Get file extension
            let extension = path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("unknown")
                .to_lowercase();
            
            *result.file_types.entry(extension.clone()).or_insert(0) += 1;
            
            // Track largest files
            let file_info = FileInfo {
                path: path.display().to_string(),
                size_bytes: file_size,
                file_type: extension,
                modified: metadata.modified()
                    .ok()
                    .and_then(|t| {
                        chrono::DateTime::<chrono::Utc>::from_timestamp(
                            t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64,
                            0
                        )
                        .map(|dt| dt.to_rfc3339())
                    }),
            };
            
            result.largest_files.push(file_info);
            
            // Check for suspicious files
            check_suspicious_file(&path, &metadata, result);
        }
    }
    
    // Sort largest files
    result.largest_files.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
    result.largest_files.truncate(20); // Keep top 20
    
    Ok(())
}

fn check_suspicious_file(path: &Path, _metadata: &fs::Metadata, result: &mut DirectoryScanResult) {
    let path_str = path.display().to_string().to_lowercase();
    let file_name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    
    // Check for suspicious patterns
    let suspicious_patterns = vec![
        ("autorun.inf", "medium", "Auto-run files can be used by malware"),
        (".exe", "low", "Executable files should be scanned"),
        (".bat", "medium", "Batch files can execute malicious commands"),
        (".cmd", "medium", "Command files can execute malicious commands"),
        (".vbs", "medium", "VBScript files can be used by malware"),
        (".js", "low", "JavaScript files can be used by malware"),
        (".scr", "high", "Screen saver files can be malware"),
        ("desktop.ini", "low", "System configuration file"),
        ("thumbs.db", "low", "Windows thumbnail cache"),
    ];
    
    for (pattern, severity, reason) in suspicious_patterns {
        if file_name.contains(pattern) || path_str.contains(pattern) {
            result.suspicious_files.push(SuspiciousFile {
                path: path.display().to_string(),
                reason: reason.to_string(),
                severity: severity.to_string(),
            });
            break;
        }
    }
}

fn analyze_scan_results(result: &mut DirectoryScanResult) {
    // Generate health issues based on findings
    let mut issues = Vec::new();
    
    // Check for too many executables
    let exe_count = result.file_types.get("exe").copied().unwrap_or(0);
    if exe_count > 100 {
        issues.push(HealthIssue {
            category: "Security".to_string(),
            severity: "medium".to_string(),
            description: format!("Found {} executable files. This is unusually high and may indicate potential security risk.", exe_count),
            recommendation: "Review executables and ensure they are from trusted sources. Consider scanning with antivirus.".to_string(),
        });
    }
    
    // Check for large files taking up space
    let total_gb = result.total_size_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    if total_gb > 50.0 {
        issues.push(HealthIssue {
            category: "Storage".to_string(),
            severity: "low".to_string(),
            description: format!("Directory uses {:.2} GB of storage space.", total_gb),
            recommendation: "Consider cleaning up old or unnecessary files to free up space.".to_string(),
        });
    }
    
    // Check for suspicious files
    let high_severity_suspicious = result.suspicious_files.iter()
        .filter(|f| f.severity == "high")
        .count();
    
    if high_severity_suspicious > 0 {
        issues.push(HealthIssue {
            category: "Security".to_string(),
            severity: "high".to_string(),
            description: format!("Found {} high-severity suspicious files.", high_severity_suspicious),
            recommendation: "Immediately scan these files with antivirus software. Do not execute them.".to_string(),
        });
    }
    
    // Check for many files (potential performance issue)
    if result.total_files > 10000 {
        issues.push(HealthIssue {
            category: "Performance".to_string(),
            severity: "low".to_string(),
            description: format!("Directory contains {} files, which may impact system performance.", result.total_files),
            recommendation: "Consider organizing files into subdirectories or archiving old files.".to_string(),
        });
    }
    
    result.health_issues = issues;
    
    // Generate summary
    result.summary = format!(
        "Scanned directory: {}\n- Files: {}\n- Directories: {}\n- Total size: {:.2} GB\n- File types: {}\n- Suspicious files: {}\n- Health issues: {}",
        result.path,
        result.total_files,
        result.total_dirs,
        result.total_size_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
        result.file_types.len(),
        result.suspicious_files.len(),
        result.health_issues.len()
    );
}

// ============================================================================
// Advanced AI Security Analysis
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPrediction {
    pub threat_level: String, // "low", "medium", "high", "critical"
    pub confidence: f32, // 0.0 to 1.0
    pub predicted_threats: Vec<String>,
    pub risk_factors: Vec<String>,
    pub recommendations: Vec<String>,
    pub time_window: String, // "immediate", "hours", "days", "weeks"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralPattern {
    pub pattern_type: String, // "normal", "suspicious", "anomalous"
    pub description: String,
    pub frequency: String,
    pub risk_level: String,
    pub observed_behaviors: Vec<String>,
    pub analysis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIntelligence {
    pub threat_indicators: Vec<String>,
    pub emerging_threats: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub intelligence_sources: Vec<String>,
    pub last_updated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAnalysisResult {
    pub threat_prediction: ThreatPrediction,
    pub behavioral_analysis: Vec<BehavioralPattern>,
    pub security_intelligence: SecurityIntelligence,
    pub overall_risk_assessment: String,
    pub priority_actions: Vec<String>,
}

#[tauri::command]
pub async fn analyze_threat_prediction(
    system_info: String,
    recent_events: Vec<String>,
    network_activity: String
) -> Result<ThreatPrediction, String> {
    // This would integrate with the AI agent to analyze patterns
    // For now, return a structured prediction based on heuristics

    let mut risk_factors = Vec::new();
    let mut recommendations = Vec::new();
    let mut predicted_threats = Vec::new();

    // Analyze system info for risk factors
    if system_info.contains("Windows 10") {
        risk_factors.push("Outdated Windows version - security updates may be limited".to_string());
        recommendations.push("Consider upgrading to Windows 11 for latest security features".to_string());
    }

    // Analyze recent events
    let suspicious_count = recent_events.iter()
        .filter(|event| event.to_lowercase().contains("suspicious") || event.to_lowercase().contains("blocked"))
        .count();

    if suspicious_count > 5 {
        risk_factors.push(format!("High number of suspicious activities detected ({})", suspicious_count));
        predicted_threats.push("Potential targeted attack or malware infection".to_string());
        recommendations.push("Run full system scan immediately".to_string());
        recommendations.push("Review firewall rules and network connections".to_string());
    }

    // Analyze network activity
    if network_activity.contains("unknown") || network_activity.contains("suspicious") {
        risk_factors.push("Suspicious network connections detected".to_string());
        predicted_threats.push("Possible data exfiltration or command & control communication".to_string());
        recommendations.push("Monitor network traffic closely".to_string());
        recommendations.push("Consider implementing network segmentation".to_string());
    }

    // Determine threat level and confidence
    let (threat_level, confidence) = if risk_factors.len() >= 3 {
        ("high", 0.85)
    } else if risk_factors.len() >= 2 {
        ("medium", 0.65)
    } else if risk_factors.len() >= 1 {
        ("low", 0.45)
    } else {
        ("low", 0.25)
    };

    let time_window = if threat_level == "high" { "immediate" } else { "days" };

    Ok(ThreatPrediction {
        threat_level: threat_level.to_string(),
        confidence,
        predicted_threats,
        risk_factors,
        recommendations,
        time_window: time_window.to_string(),
    })
}

#[tauri::command]
pub async fn analyze_behavioral_patterns_ai(
    process_list: Vec<String>,
    network_connections: Vec<String>,
    file_access_patterns: Vec<String>
) -> Result<Vec<BehavioralPattern>, String> {
    let mut patterns: Vec<BehavioralPattern> = Vec::new();

    // ── 1. Parse process entries into a lookup structure ──────────────
    // Expected formats: "name,pid,ppid,user" or "name pid ppid" or just "name"
    struct ProcInfo {
        name: String,
        pid: String,
        ppid: String,
        raw: String,
    }

    let procs: Vec<ProcInfo> = process_list.iter().map(|raw| {
        let parts: Vec<&str> = if raw.contains(',') {
            raw.split(',').map(|s| s.trim().trim_matches('"')).collect()
        } else {
            raw.split_whitespace().collect()
        };
        ProcInfo {
            name: parts.first().unwrap_or(&"").to_lowercase(),
            pid:  parts.get(1).unwrap_or(&"").to_string(),
            ppid: parts.get(2).unwrap_or(&"").to_string(),
            raw:  raw.clone(),
        }
    }).collect();

    let proc_names: std::collections::HashSet<String> =
        procs.iter().map(|p| p.name.clone()).collect();

    let pid_to_name: HashMap<String, String> =
        procs.iter().map(|p| (p.pid.clone(), p.name.clone())).collect();

    // ── 2. Suspicious process-chain detection ────────────────────────
    let shell_names = ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                       "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe"];
    let office_names = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                        "msaccess.exe", "onenote.exe"];

    let mut chain_evidence: Vec<String> = Vec::new();
    for p in &procs {
        if shell_names.contains(&p.name.as_str()) {
            if let Some(parent_name) = pid_to_name.get(&p.ppid) {
                if office_names.contains(&parent_name.as_str()) {
                    chain_evidence.push(format!(
                        "{} (PID {}) spawned by {} (PPID {}) — possible macro/exploit execution",
                        p.name, p.pid, parent_name, p.ppid
                    ));
                }
            }
        }
    }

    let lolbin_names = ["certutil.exe", "bitsadmin.exe", "msiexec.exe",
                        "regasm.exe", "installutil.exe", "msbuild.exe"];
    for p in &procs {
        if lolbin_names.contains(&p.name.as_str()) {
            chain_evidence.push(format!(
                "Living-off-the-land binary detected: {} (PID {})",
                p.name, p.pid
            ));
        }
    }

    if !chain_evidence.is_empty() {
        patterns.push(BehavioralPattern {
            pattern_type: "suspicious".to_string(),
            description: format!(
                "Suspicious process chain: {} indicator(s) of shell/LOLBin spawning from unexpected parents",
                chain_evidence.len()
            ),
            frequency: "active".to_string(),
            risk_level: if chain_evidence.len() >= 3 { "critical" } else { "high" }.to_string(),
            observed_behaviors: chain_evidence,
            analysis: "Shells or living-off-the-land binaries spawned from Office apps or \
                       unusual parents are a strong indicator of exploit/macro-based attacks. \
                       Investigate the parent process and review recent document opens."
                .to_string(),
        });
    }

    // ── 3. Persistence indicators ────────────────────────────────────
    let persistence_keywords = [
        ("currentversion\\run", "Registry Run key"),
        ("currentversion\\runonce", "Registry RunOnce key"),
        ("startup", "Startup folder"),
        ("schtasks", "Scheduled task creation"),
        ("at.exe", "AT scheduled task"),
        ("sc.exe create", "Service creation"),
        ("wmic process call create", "WMI process creation"),
        ("reg add", "Registry modification"),
        ("new-scheduledtask", "PowerShell scheduled task"),
        ("register-scheduledjob", "PowerShell scheduled job"),
    ];

    let all_text: Vec<String> = process_list.iter()
        .chain(file_access_patterns.iter())
        .cloned()
        .collect();

    let mut persist_evidence: Vec<String> = Vec::new();
    for entry in &all_text {
        let lower = entry.to_lowercase();
        for (keyword, label) in &persistence_keywords {
            if lower.contains(keyword) {
                persist_evidence.push(format!("{}: {}", label, entry));
            }
        }
    }

    if !persist_evidence.is_empty() {
        patterns.push(BehavioralPattern {
            pattern_type: "anomalous".to_string(),
            description: format!(
                "Persistence mechanism: {} indicator(s) of auto-start or scheduled persistence",
                persist_evidence.len()
            ),
            frequency: "recent".to_string(),
            risk_level: if persist_evidence.len() >= 2 { "high" } else { "medium" }.to_string(),
            observed_behaviors: persist_evidence,
            analysis: "References to Run keys, scheduled tasks, or startup folders suggest \
                       an attempt to maintain persistence across reboots. Verify whether these \
                       are legitimate administrative actions or indicators of compromise."
                .to_string(),
        });
    }

    // ── 4. Lateral-movement detection via network connections ─────────
    // Expected connection format: "proto local_addr:port remote_addr:port state pid"
    // or CSV variants. We extract remote ports.
    let lateral_ports: HashMap<u16, &str> = [
        (445u16, "SMB"), (3389, "RDP"), (135, "WMI/DCOM"),
        (5985, "WinRM-HTTP"), (5986, "WinRM-HTTPS"), (22, "SSH"),
    ].iter().cloned().collect();

    let mut lateral_evidence: Vec<String> = Vec::new();

    for conn in &network_connections {
        for (port, label) in &lateral_ports {
            let port_str = format!(":{}", port);
            if conn.contains(&port_str) {
                lateral_evidence.push(format!("{} connection (port {}) — {}", label, port, conn));
            }
        }
    }

    if !lateral_evidence.is_empty() {
        let uniq_protocols: std::collections::HashSet<&str> = lateral_evidence.iter()
            .filter_map(|e| e.split(' ').next())
            .collect();
        patterns.push(BehavioralPattern {
            pattern_type: "anomalous".to_string(),
            description: format!(
                "Lateral movement: {} connection(s) over {} protocol(s) ({})",
                lateral_evidence.len(),
                uniq_protocols.len(),
                uniq_protocols.into_iter().collect::<Vec<_>>().join(", ")
            ),
            frequency: "active".to_string(),
            risk_level: if lateral_evidence.len() >= 5 { "critical" } else { "high" }.to_string(),
            observed_behaviors: lateral_evidence.iter().take(10).cloned().collect(),
            analysis: "Active connections on SMB, RDP, WMI, or WinRM ports may indicate \
                       lateral movement within the network. Cross-reference with expected \
                       admin activity and check destination hosts for compromise."
                .to_string(),
        });
    }

    // ── 5. Data-exfiltration patterns ────────────────────────────────
    let suspicious_exfil_ports: Vec<u16> = vec![
        4444, 5555, 8443, 8080, 1337, 31337, 6667, 6697, // common C2/IRC
    ];
    let dns_exfil_indicators = ["txt", "nslookup", "dns"];

    let mut exfil_evidence: Vec<String> = Vec::new();

    for conn in &network_connections {
        let lower = conn.to_lowercase();
        for port in &suspicious_exfil_ports {
            if lower.contains(&format!(":{}", port)) {
                exfil_evidence.push(format!(
                    "Connection to unusual port {} — possible C2 channel: {}", port, conn
                ));
            }
        }
        // Large outbound heuristic: look for "bytes" or size tokens > 10 MB
        let parts: Vec<&str> = conn.split_whitespace().collect();
        for part in &parts {
            if let Ok(bytes) = part.parse::<u64>() {
                if bytes > 10_000_000 {
                    exfil_evidence.push(format!(
                        "Large outbound transfer (~{:.1} MB): {}",
                        bytes as f64 / 1_000_000.0, conn
                    ));
                }
            }
        }
        for indicator in &dns_exfil_indicators {
            if lower.contains(indicator) && lower.contains("outbound") {
                exfil_evidence.push(format!("Possible DNS exfiltration: {}", conn));
            }
        }
    }

    if !exfil_evidence.is_empty() {
        patterns.push(BehavioralPattern {
            pattern_type: "suspicious".to_string(),
            description: format!(
                "Data exfiltration: {} indicator(s) of large transfers or unusual outbound ports",
                exfil_evidence.len()
            ),
            frequency: "recent".to_string(),
            risk_level: if exfil_evidence.len() >= 3 { "critical" } else { "high" }.to_string(),
            observed_behaviors: exfil_evidence.iter().take(10).cloned().collect(),
            analysis: "Connections to uncommon ports or large outbound data transfers can \
                       indicate data exfiltration or command-and-control communication. \
                       Inspect the destination IPs and correlate with threat intelligence feeds."
                .to_string(),
        });
    }

    // ── 6. Cross-input correlation ───────────────────────────────────
    // If a process name appears in BOTH the process list AND network connections,
    // it is actively communicating — flag the overlap.
    let mut correlated_evidence: Vec<String> = Vec::new();

    for conn in &network_connections {
        let conn_lower = conn.to_lowercase();
        for pname in &proc_names {
            if pname.is_empty() { continue; }
            if conn_lower.contains(pname.as_str()) {
                correlated_evidence.push(format!(
                    "Process '{}' appears in both process list and network connections: {}",
                    pname, conn
                ));
            }
        }
    }

    // Also check file-access ↔ process overlap (e.g. process writing to suspicious paths)
    let sensitive_paths = ["\\appdata\\roaming", "\\temp\\", "\\programdata\\",
                           "\\downloads\\", "shadow", "sam", "ntds.dit"];
    for access in &file_access_patterns {
        let lower = access.to_lowercase();
        for pname in &proc_names {
            if pname.is_empty() { continue; }
            if lower.contains(pname.as_str()) {
                for spath in &sensitive_paths {
                    if lower.contains(spath) {
                        correlated_evidence.push(format!(
                            "Process '{}' accessing sensitive path: {}",
                            pname, access
                        ));
                    }
                }
            }
        }
    }

    if !correlated_evidence.is_empty() {
        patterns.push(BehavioralPattern {
            pattern_type: "anomalous".to_string(),
            description: format!(
                "Cross-signal correlation: {} linked indicator(s) across process, network, and file data",
                correlated_evidence.len()
            ),
            frequency: "active".to_string(),
            risk_level: if correlated_evidence.len() >= 4 { "critical" }
                        else if correlated_evidence.len() >= 2 { "high" }
                        else { "medium" }.to_string(),
            observed_behaviors: correlated_evidence.iter().take(10).cloned().collect(),
            analysis: "When the same process name surfaces across multiple telemetry sources \
                       (process list, network connections, file access) it strengthens the \
                       confidence that the activity is coordinated. Prioritize investigation \
                       of the overlapping processes."
                .to_string(),
        });
    }

    // ── 7. Credential-access / sensitive-file indicators ─────────────
    let cred_keywords = ["mimikatz", "lsass", "procdump", "sekurlsa",
                         "hashdump", "ntds.dit", "sam", "security",
                         "credential", "password", "kerberos", "ticket"];
    let mut cred_evidence: Vec<String> = Vec::new();

    for entry in process_list.iter().chain(file_access_patterns.iter()) {
        let lower = entry.to_lowercase();
        for kw in &cred_keywords {
            if lower.contains(kw) {
                cred_evidence.push(format!("Credential-access indicator '{}': {}", kw, entry));
                break;
            }
        }
    }

    if !cred_evidence.is_empty() {
        patterns.push(BehavioralPattern {
            pattern_type: "suspicious".to_string(),
            description: format!(
                "Credential access: {} indicator(s) of credential harvesting or dumping tools",
                cred_evidence.len()
            ),
            frequency: "recent".to_string(),
            risk_level: "critical".to_string(),
            observed_behaviors: cred_evidence.iter().take(10).cloned().collect(),
            analysis: "References to credential-dumping tools (Mimikatz, LSASS access, \
                       SAM/NTDS access) are high-confidence indicators of active credential \
                       theft. Immediately isolate the affected endpoint and reset compromised \
                       accounts."
                .to_string(),
        });
    }

    // ── 8. Default safe pattern when nothing flagged ──────────────────
    if patterns.is_empty() {
        patterns.push(BehavioralPattern {
            pattern_type: "normal".to_string(),
            description: "System behavior appears normal across all telemetry inputs".to_string(),
            frequency: "consistent".to_string(),
            risk_level: "low".to_string(),
            observed_behaviors: vec![
                format!("{} processes analyzed", procs.len()),
                format!("{} network connections analyzed", network_connections.len()),
                format!("{} file-access entries analyzed", file_access_patterns.len()),
            ],
            analysis: "No anomalous behavior detected. Process chains, network connections, \
                       file-access patterns, and cross-source correlations are within normal \
                       parameters."
                .to_string(),
        });
    }

    Ok(patterns)
}

#[tauri::command]
pub async fn get_security_intelligence() -> Result<SecurityIntelligence, String> {
    // This would fetch from real threat intelligence feeds
    // For now, return simulated intelligence

    let threat_indicators = vec![
        "Ransomware campaigns targeting Windows systems".to_string(),
        "New phishing campaigns using AI-generated content".to_string(),
        "Supply chain attacks on popular software libraries".to_string(),
        "Zero-day exploits in web browsers".to_string(),
    ];

    let emerging_threats = vec![
        "AI-powered malware that adapts to defenses".to_string(),
        "Quantum computing threats to encryption".to_string(),
        "IoT device-based botnets".to_string(),
    ];

    let recommended_actions = vec![
        "Update all software to latest versions".to_string(),
        "Enable multi-factor authentication everywhere".to_string(),
        "Regular security training for users".to_string(),
        "Implement network segmentation".to_string(),
        "Regular backup and testing of backups".to_string(),
    ];

    Ok(SecurityIntelligence {
        threat_indicators,
        emerging_threats,
        recommended_actions,
        intelligence_sources: vec![
            "Microsoft Security Intelligence".to_string(),
            "CrowdStrike Threat Intelligence".to_string(),
            "Mandiant Threat Reports".to_string(),
        ],
        last_updated: format!("{}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")),
    })
}

#[tauri::command]
pub async fn perform_comprehensive_ai_analysis(
    system_info: String,
    recent_events: Vec<String>,
    network_activity: String,
    process_list: Vec<String>,
    network_connections: Vec<String>,
    file_access_patterns: Vec<String>
) -> Result<AIAnalysisResult, String> {

    // Gather all analyses
    let threat_prediction = analyze_threat_prediction(
        system_info.clone(),
        recent_events.clone(),
        network_activity.clone()
    ).await?;

    let behavioral_analysis = analyze_behavioral_patterns_ai(
        process_list.clone(),
        network_connections.clone(),
        file_access_patterns.clone()
    ).await?;

    let security_intelligence = get_security_intelligence().await?;

    // Determine overall risk assessment
    let overall_risk = if threat_prediction.threat_level == "high" || behavioral_analysis.iter().any(|p| p.risk_level == "high") {
        "HIGH RISK - Immediate action required".to_string()
    } else if threat_prediction.threat_level == "medium" || behavioral_analysis.iter().any(|p| p.risk_level == "medium") {
        "MEDIUM RISK - Monitor closely and address issues".to_string()
    } else {
        "LOW RISK - System appears secure".to_string()
    };

    // Generate priority actions
    let mut priority_actions = threat_prediction.recommendations.clone();
    priority_actions.extend(security_intelligence.recommended_actions.iter().take(3).cloned());

    // Remove duplicates and limit to top 5
    let mut seen = std::collections::HashSet::new();
    priority_actions.retain(|action| seen.insert(action.clone()));
    priority_actions.truncate(5);

    Ok(AIAnalysisResult {
        threat_prediction,
        behavioral_analysis,
        security_intelligence,
        overall_risk_assessment: overall_risk,
        priority_actions,
    })
}

// ============================================================================
// Helper Functions
// ============================================================================

fn get_security_system_prompt() -> String {
    r#"You are an AI Security Assistant for Cyber Security Prime, a desktop cybersecurity application. Your role is to:

1. **Analyze Security**: Help users understand security threats, vulnerabilities, and risks
2. **Provide Recommendations**: Give actionable advice to improve system security
3. **Explain Threats**: Break down complex security concepts in understandable terms
4. **Assist with Scans**: Help interpret scan results and suggest remediation steps
5. **Answer Questions**: Respond to security-related questions accurately
6. **System Health Analysis**: When users ask you to scan or analyze directories/folders, you can use the scan_directory_for_analysis function to examine file systems and provide insights about PC health, security issues, and optimization opportunities

Guidelines:
- Be concise but thorough
- Prioritize actionable advice
- Warn about dangerous actions (NEVER suggest deleting critical system folders like System32, Windows, etc.)
- Never encourage illegal activities
- Explain technical terms when used
- Consider the user's technical level
- When analyzing directories, provide friendly, conversational insights about what you find
- Focus on security, privacy, and system health concerns
- If you detect suspicious files or potential threats, explain them clearly

You have access to the following context about the user's system:
- Operating System: Windows
- Security modules: Malware Scanner, Firewall, Encryption, Vulnerability Scanner, Network Monitor
- Directory scanning capabilities: You can analyze folders and provide health/security insights

When a user asks you to scan, look at, or analyze a directory/folder/path, automatically use the scan_directory_for_analysis function and then provide a friendly, conversational analysis of the results.

Always maintain a helpful, professional tone focused on cybersecurity."#.to_string()
}
