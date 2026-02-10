// Cyber Security Prime - AI Security Agent Module
// Powered by Ollama - Local and Cloud AI Models
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
        
        // Default to Ollama Cloud with hardcoded API key (for development)
        // This ensures cloud models work even if config file isn't found
        log::info!("Using hardcoded Ollama Cloud config (config file not found)");
        Self {
            base_url: "https://ollama.com".to_string(),
            api_key: Some("16a43cfd76114a4bb4fdcc6b19243382.Vwk6ornm9vX4rsn0U6hb94za".to_string()),
            default_model: "gemma3:27b".to_string(),         // General purpose cloud model
            fast_model: "gemma3:27b".to_string(),            // Fast cloud model
            deep_model: "deepseek-v3.1:671b".to_string(),    // Deep analysis cloud model
            timeout_secs: 300,
        }
    }
}

/// Load Ollama Cloud configuration from config file
fn load_cloud_config() -> Option<OllamaConfig> {
    // Try multiple config paths - including absolute paths for development
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
    
    // Add absolute path for Windows development
    config_paths.push(std::path::PathBuf::from(r"G:\SecurityPrime\config\ollama_cloud_config.json"));
    
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
                
                // Find best models for each use case
                let default_model = find_model_for_task(cloud_models, "general_purpose")
                    .unwrap_or_else(|| "gemma3:27b".to_string());
                let fast_model = find_model_for_task(cloud_models, "efficient")
                    .unwrap_or_else(|| "gemma3:27b".to_string());
                let deep_model = find_model_for_task(cloud_models, "threat_analysis")
                    .unwrap_or_else(|| "deepseek-v3.1:671b".to_string());
                
                log::info!("Loaded Ollama Cloud config - base_url: {}, default_model: {}", base_url, default_model);
                return Some(OllamaConfig {
                    base_url,
                    api_key,
                    default_model,
                    fast_model,
                    deep_model,
                    timeout_secs: timeout,
                });
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
        let (current_model, headers, is_cloud) = {
            let config = self.config.read();
            (
                config.default_model.clone(),
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
                        name: config.default_model.clone(),
                        size: None,
                        modified_at: None,
                        digest: Some("cloud".to_string()),
                    },
                    ModelInfo {
                        name: config.fast_model.clone(),
                        size: None,
                        modified_at: None,
                        digest: Some("cloud".to_string()),
                    },
                    ModelInfo {
                        name: config.deep_model.clone(),
                        size: None,
                        modified_at: None,
                        digest: Some("cloud".to_string()),
                    },
                ];
                
                return Ok(AgentStatus {
                    connected: true,
                    available_models: cloud_models,
                    current_model,
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
                                Some(ModelInfo {
                                    name: m["name"].as_str()?.to_string(),
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
                        current_model,
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
                model.unwrap_or_else(|| config.default_model.clone()),
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
    
    log::info!("Initializing Ollama client with base_url: {}, model: {}", 
               config.base_url, config.default_model);

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
        model.unwrap_or_else(|| config.default_model.clone())
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
            (session.messages.clone(), model.or_else(|| Some(session.model.clone())))
        } else {
            return Err("Failed to get or create session".to_string());
        }
    };

    // Get response from Ollama
    let response = client.chat(messages, model_to_use, Some(0.7)).await?;

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

    let response = client.chat(messages, Some(deep_model), Some(0.3)).await?;

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

    let response = client.chat(messages, None, Some(0.5)).await?;
    
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
            (session.messages.clone(), model.or_else(|| Some(session.model.clone())))
        } else {
            return Err("Failed to get or create session".to_string());
        }
    };

    // Build streaming request
    let (model_name, headers) = {
        let config = client.config.read();
        (
            model_to_use.unwrap_or_else(|| config.default_model.clone()),
            client.get_headers(),
        )
    };
    let url = format!("{}/chat", client.get_api_base());

    let request = ChatRequest {
        model: model_name.clone(),
        messages,
        stream: true, // Enable streaming!
        options: Some(ChatOptions {
            temperature: Some(0.7),
            num_predict: Some(4096),
        }),
    };

    // Send streaming request
    let response = client.client
        .post(&url)
        .headers(headers)
        .json(&request)
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
                
                // Ollama sends newline-delimited JSON
                for line in chunk_str.lines() {
                    if line.is_empty() {
                        continue;
                    }
                    
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line) {
                        if let Some(msg) = parsed.get("message") {
                            if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                                full_response.push_str(content);
                                
                                // Emit streaming chunk to frontend
                                let _ = app.emit_all("agent-stream", StreamChunk {
                                    content: content.to_string(),
                                    done: parsed.get("done").and_then(|d| d.as_bool()).unwrap_or(false),
                                    model: model_name.clone(),
                                });
                            }
                        }
                        
                        // Check if done
                        if parsed.get("done").and_then(|d| d.as_bool()).unwrap_or(false) {
                            break;
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
        model: model_name,
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
    let mut patterns = Vec::new();

    // Analyze process patterns
    let suspicious_processes = process_list.iter()
        .filter(|proc| {
            let proc_lower = proc.to_lowercase();
            proc_lower.contains("unknown") ||
            proc_lower.contains("suspicious") ||
            proc_lower.contains("unverified")
        })
        .count();

    if suspicious_processes > 0 {
        patterns.push(BehavioralPattern {
            pattern_type: "suspicious".to_string(),
            description: format!("{} suspicious processes detected", suspicious_processes),
            frequency: "ongoing".to_string(),
            risk_level: "medium".to_string(),
            observed_behaviors: process_list.iter()
                .filter(|proc| proc.to_lowercase().contains("suspicious"))
                .cloned()
                .collect(),
            analysis: "Suspicious processes may indicate malware or unauthorized software".to_string(),
        });
    }

    // Analyze network patterns
    let external_connections = network_connections.iter()
        .filter(|conn| conn.contains("external") || conn.contains("unknown"))
        .count();

    if external_connections > 10 {
        patterns.push(BehavioralPattern {
            pattern_type: "anomalous".to_string(),
            description: format!("High number of external connections ({})", external_connections),
            frequency: "ongoing".to_string(),
            risk_level: "high".to_string(),
            observed_behaviors: network_connections.iter()
                .filter(|conn| conn.contains("external"))
                .take(5)
                .cloned()
                .collect(),
            analysis: "Excessive external connections may indicate data exfiltration or botnet activity".to_string(),
        });
    }

    // Analyze file access patterns
    let sensitive_file_access = file_access_patterns.iter()
        .filter(|access| {
            access.to_lowercase().contains("system32") ||
            access.to_lowercase().contains("config") ||
            access.to_lowercase().contains("password")
        })
        .count();

    if sensitive_file_access > 0 {
        patterns.push(BehavioralPattern {
            pattern_type: "suspicious".to_string(),
            description: "Access to sensitive system files detected".to_string(),
            frequency: "occasional".to_string(),
            risk_level: "medium".to_string(),
            observed_behaviors: file_access_patterns.iter()
                .filter(|access| access.to_lowercase().contains("system32"))
                .take(3)
                .cloned()
                .collect(),
            analysis: "Access to system files is normal but should be monitored for unauthorized changes".to_string(),
        });
    }

    // Add normal pattern if everything looks good
    if patterns.is_empty() {
        patterns.push(BehavioralPattern {
            pattern_type: "normal".to_string(),
            description: "System behavior appears normal".to_string(),
            frequency: "consistent".to_string(),
            risk_level: "low".to_string(),
            observed_behaviors: vec!["Standard system processes active".to_string()],
            analysis: "No anomalous behavior detected in current analysis".to_string(),
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
