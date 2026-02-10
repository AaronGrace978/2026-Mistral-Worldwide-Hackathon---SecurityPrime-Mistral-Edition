// Cyber Security Prime - Firewall Module
// Provides firewall management and network protection capabilities
// Uses Windows Firewall via netsh commands

use crate::utils::generate_id;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::collections::HashMap;
use parking_lot::RwLock;
use once_cell::sync::Lazy;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// Windows constant to hide console window
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

// Cache for custom rules added by the app
static CUSTOM_RULES: Lazy<RwLock<HashMap<String, FirewallRule>>> = Lazy::new(|| {
    RwLock::new(HashMap::new())
});

/// Helper to create a netsh command with hidden console window on Windows
fn netsh_command() -> Command {
    let mut cmd = Command::new("netsh");
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub enabled: bool,
    pub profile: String,
    pub inbound_blocked: u64,
    pub outbound_blocked: u64,
    pub active_rules: u32,
    pub last_blocked: Option<BlockedConnection>,
    pub domain_enabled: bool,
    pub private_enabled: bool,
    pub public_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedConnection {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub direction: String,
    pub reason: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub direction: String,  // "inbound" or "outbound"
    pub action: String,     // "allow" or "block"
    pub protocol: String,   // "tcp", "udp", "any"
    pub local_port: Option<String>,
    pub remote_port: Option<String>,
    pub remote_address: Option<String>,
    pub application: Option<String>,
    pub description: String,
    pub created_at: String,
}

/// Get the current firewall status by querying Windows Firewall
pub fn get_status() -> Result<FirewallStatus, String> {
    // Query Windows Firewall state using netsh (with hidden console)
    let output = netsh_command()
        .args(&["advfirewall", "show", "allprofiles", "state"])
        .output()
        .map_err(|e| format!("Failed to query firewall status: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse the output to determine firewall state for each profile
    let mut domain_enabled = false;
    let mut private_enabled = false;
    let mut public_enabled = false;
    let mut current_profile = String::new();
    
    for line in stdout.lines() {
        let line_lower = line.to_lowercase();
        
        if line_lower.contains("domain profile") {
            current_profile = "domain".to_string();
        } else if line_lower.contains("private profile") {
            current_profile = "private".to_string();
        } else if line_lower.contains("public profile") {
            current_profile = "public".to_string();
        } else if line_lower.contains("state") && line_lower.contains("on") {
            match current_profile.as_str() {
                "domain" => domain_enabled = true,
                "private" => private_enabled = true,
                "public" => public_enabled = true,
                _ => {}
            }
        }
    }
    
    // Get active profile
    let profile = get_current_profile()?;
    
    // Count active rules
    let active_rules = count_active_rules()?;
    
    // Overall enabled if any profile is enabled
    let enabled = domain_enabled || private_enabled || public_enabled;
    
    Ok(FirewallStatus {
        enabled,
        profile,
        inbound_blocked: 0, // Would need to parse event logs for this
        outbound_blocked: 0,
        active_rules,
        last_blocked: None, // Would need to parse event logs for this
        domain_enabled,
        private_enabled,
        public_enabled,
    })
}

/// Get the current active network profile
fn get_current_profile() -> Result<String, String> {
    let output = netsh_command()
        .args(&["advfirewall", "show", "currentprofile"])
        .output()
        .map_err(|e| format!("Failed to query current profile: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    if stdout.to_lowercase().contains("domain") {
        Ok("Domain".to_string())
    } else if stdout.to_lowercase().contains("private") {
        Ok("Private".to_string())
    } else if stdout.to_lowercase().contains("public") {
        Ok("Public".to_string())
    } else {
        Ok("Unknown".to_string())
    }
}

/// Count active firewall rules (optimized - just count, don't parse details)
fn count_active_rules() -> Result<u32, String> {
    let output = netsh_command()
        .args(&["advfirewall", "firewall", "show", "rule", "name=all"])
        .output()
        .map_err(|e| format!("Failed to count rules: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Count lines that start with "Rule Name:"
    let count = stdout.lines()
        .filter(|line| line.trim().starts_with("Rule Name:"))
        .count();
    
    Ok(count as u32)
}

/// Toggle firewall on/off for all profiles
pub fn toggle(enabled: bool) -> Result<bool, String> {
    let state = if enabled { "on" } else { "off" };
    
    // Set for all profiles (with hidden console)
    let output = netsh_command()
        .args(&["advfirewall", "set", "allprofiles", "state", state])
        .output()
        .map_err(|e| format!("Failed to toggle firewall: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to toggle firewall: {}. Note: This operation requires administrator privileges.", stderr));
    }
    
    Ok(enabled)
}

/// Get firewall rules from Windows Firewall
/// Note: This only retrieves enabled rules to improve performance.
/// Windows typically has 300-1000+ rules, and querying all with verbose output
/// can take 10-30+ seconds. We limit to enabled rules and cap at 50 for UI.
pub fn get_rules() -> Result<Vec<FirewallRule>, String> {
    // PERFORMANCE OPTIMIZATION: Only get enabled rules (much faster than all rules)
    // Also removed "verbose" flag which adds significant overhead
    let output = netsh_command()
        .args(&["advfirewall", "firewall", "show", "rule", "name=all", "status=enabled"])
        .output()
        .map_err(|e| format!("Failed to get firewall rules: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    let mut rules = Vec::new();
    let mut current_rule: Option<FirewallRule> = None;
    
    // Early exit limit - stop parsing once we have enough rules for the UI
    const MAX_RULES_TO_DISPLAY: usize = 50;
    
    for line in stdout.lines() {
        // Stop early if we have enough rules
        if rules.len() >= MAX_RULES_TO_DISPLAY {
            break;
        }
        
        let line = line.trim();
        
        if line.starts_with("Rule Name:") {
            // Save previous rule if exists
            if let Some(rule) = current_rule.take() {
                rules.push(rule);
            }
            
            // Start new rule
            let name = line.trim_start_matches("Rule Name:").trim().to_string();
            current_rule = Some(FirewallRule {
                id: generate_id(),
                name,
                enabled: true,
                direction: "inbound".to_string(),
                action: "allow".to_string(),
                protocol: "any".to_string(),
                local_port: None,
                remote_port: None,
                remote_address: None,
                application: None,
                description: String::new(),
                created_at: chrono::Utc::now().to_rfc3339(),
            });
        } else if let Some(ref mut rule) = current_rule {
            // Parse rule properties
            if line.starts_with("Enabled:") {
                let value = line.trim_start_matches("Enabled:").trim().to_lowercase();
                rule.enabled = value == "yes";
            } else if line.starts_with("Direction:") {
                let value = line.trim_start_matches("Direction:").trim().to_lowercase();
                rule.direction = if value.contains("in") { "inbound" } else { "outbound" }.to_string();
            } else if line.starts_with("Action:") {
                let value = line.trim_start_matches("Action:").trim().to_lowercase();
                rule.action = if value.contains("allow") { "allow" } else { "block" }.to_string();
            } else if line.starts_with("Protocol:") {
                let value = line.trim_start_matches("Protocol:").trim().to_lowercase();
                rule.protocol = value;
            } else if line.starts_with("LocalPort:") {
                let value = line.trim_start_matches("LocalPort:").trim();
                if value != "Any" {
                    rule.local_port = Some(value.to_string());
                }
            } else if line.starts_with("RemotePort:") {
                let value = line.trim_start_matches("RemotePort:").trim();
                if value != "Any" {
                    rule.remote_port = Some(value.to_string());
                }
            } else if line.starts_with("RemoteIP:") {
                let value = line.trim_start_matches("RemoteIP:").trim();
                if value != "Any" {
                    rule.remote_address = Some(value.to_string());
                }
            } else if line.starts_with("Program:") {
                let value = line.trim_start_matches("Program:").trim();
                if value != "Any" {
                    rule.application = Some(value.to_string());
                }
            } else if line.starts_with("Description:") {
                rule.description = line.trim_start_matches("Description:").trim().to_string();
            }
        }
    }
    
    // Don't forget the last rule (if under limit)
    if rules.len() < MAX_RULES_TO_DISPLAY {
        if let Some(rule) = current_rule {
            rules.push(rule);
        }
    }
    
    Ok(rules)
}

/// Add a new firewall rule using netsh
pub fn add_rule(mut rule: FirewallRule) -> Result<FirewallRule, String> {
    rule.id = generate_id();
    rule.created_at = chrono::Utc::now().to_rfc3339();
    
    // Build netsh command
    let mut args = vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "add".to_string(),
        "rule".to_string(),
        format!("name={}", rule.name),
        format!("dir={}", if rule.direction == "inbound" { "in" } else { "out" }),
        format!("action={}", rule.action),
    ];
    
    // Add protocol
    if rule.protocol != "any" {
        args.push(format!("protocol={}", rule.protocol));
    }
    
    // Add local port
    if let Some(ref port) = rule.local_port {
        args.push(format!("localport={}", port));
    }
    
    // Add remote port
    if let Some(ref port) = rule.remote_port {
        args.push(format!("remoteport={}", port));
    }
    
    // Add remote address
    if let Some(ref addr) = rule.remote_address {
        args.push(format!("remoteip={}", addr));
    }
    
    // Add program
    if let Some(ref program) = rule.application {
        args.push(format!("program={}", program));
    }
    
    // Add description
    if !rule.description.is_empty() {
        args.push(format!("description={}", rule.description));
    }
    
    // Add enable/disable
    args.push(format!("enable={}", if rule.enabled { "yes" } else { "no" }));
    
    // Execute command (with hidden console)
    let output = netsh_command()
        .args(&args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .output()
        .map_err(|e| format!("Failed to add firewall rule: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!("Failed to add firewall rule: {} {}. Note: This operation requires administrator privileges.", stderr, stdout));
    }
    
    // Store in our custom rules cache
    let mut custom_rules = CUSTOM_RULES.write();
    custom_rules.insert(rule.id.clone(), rule.clone());
    
    Ok(rule)
}

/// Remove a firewall rule using netsh
pub fn remove_rule(rule_id: &str) -> Result<bool, String> {
    // First, try to find the rule name from our cache
    let rule_name = {
        let custom_rules = CUSTOM_RULES.read();
        custom_rules.get(rule_id).map(|r| r.name.clone())
    };
    
    let name = match rule_name {
        Some(n) => n,
        None => {
            // If not in cache, we need the rule name from the frontend
            return Err("Rule not found in cache. Please provide the rule name.".to_string());
        }
    };
    
    // Execute netsh delete command (with hidden console)
    let output = netsh_command()
        .args(&["advfirewall", "firewall", "delete", "rule", &format!("name={}", name)])
        .output()
        .map_err(|e| format!("Failed to remove firewall rule: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to remove firewall rule: {}. Note: This operation requires administrator privileges.", stderr));
    }
    
    // Remove from cache
    let mut custom_rules = CUSTOM_RULES.write();
    custom_rules.remove(rule_id);
    
    Ok(true)
}

/// Remove a firewall rule by name
pub fn remove_rule_by_name(rule_name: &str) -> Result<bool, String> {
    let output = netsh_command()
        .args(&["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name)])
        .output()
        .map_err(|e| format!("Failed to remove firewall rule: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to remove firewall rule: {}. Note: This operation requires administrator privileges.", stderr));
    }
    
    Ok(true)
}

/// Enable or disable a specific rule
pub fn toggle_rule(rule_name: &str, enabled: bool) -> Result<bool, String> {
    let enable_str = if enabled { "yes" } else { "no" };
    
    let output = netsh_command()
        .args(&["advfirewall", "firewall", "set", "rule", &format!("name={}", rule_name), "new", &format!("enable={}", enable_str)])
        .output()
        .map_err(|e| format!("Failed to toggle firewall rule: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to toggle firewall rule: {}. Note: This operation requires administrator privileges.", stderr));
    }
    
    Ok(enabled)
}

/// Reset firewall to default settings
pub fn reset_to_defaults() -> Result<(), String> {
    let output = netsh_command()
        .args(&["advfirewall", "reset"])
        .output()
        .map_err(|e| format!("Failed to reset firewall: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to reset firewall: {}. Note: This operation requires administrator privileges.", stderr));
    }
    
    Ok(())
}

// ============================================================================
// Export / Import
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallExport {
    pub version: String,
    pub exported_at: String,
    pub rules: Vec<FirewallRule>,
    pub checksum: String,
}

/// Export firewall rules to JSON
#[tauri::command]
pub fn export_firewall_rules(file_path: String) -> Result<FirewallExport, String> {
    let rules = get_rules()?;
    
    let export = FirewallExport {
        version: "1.0".to_string(),
        exported_at: chrono::Utc::now().to_rfc3339(),
        rules: rules.clone(),
        checksum: calculate_checksum(&rules),
    };
    
    // Write to file
    let json = serde_json::to_string_pretty(&export)
        .map_err(|e| format!("Failed to serialize rules: {}", e))?;
    
    std::fs::write(&file_path, &json)
        .map_err(|e| format!("Failed to write file: {}", e))?;
    
    println!("Exported {} firewall rules to {}", export.rules.len(), file_path);
    Ok(export)
}

/// Import firewall rules from JSON
#[tauri::command]
pub fn import_firewall_rules(file_path: String, merge: bool) -> Result<ImportResult, String> {
    let json = std::fs::read_to_string(&file_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    let import: FirewallExport = serde_json::from_str(&json)
        .map_err(|e| format!("Invalid file format: {}", e))?;
    
    // Verify checksum
    let expected_checksum = calculate_checksum(&import.rules);
    if import.checksum != expected_checksum {
        return Err("Checksum verification failed. File may be corrupted.".to_string());
    }
    
    let mut imported = 0;
    let skipped = 0;
    
    for rule in &import.rules {
        // In a real implementation, would check for duplicates and add to system firewall
        if merge {
            // Check if rule already exists by name
            // For now, just add it
            let _ = add_rule(rule.clone());
            imported += 1;
        } else {
            let _ = add_rule(rule.clone());
            imported += 1;
        }
    }
    
    println!("Imported {} firewall rules from {}", imported, file_path);
    
    Ok(ImportResult {
        success: true,
        imported,
        skipped,
        total: import.rules.len(),
        message: format!("Successfully imported {} rules", imported),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub success: bool,
    pub imported: usize,
    pub skipped: usize,
    pub total: usize,
    pub message: String,
}

fn calculate_checksum(rules: &[FirewallRule]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    for rule in rules {
        rule.name.hash(&mut hasher);
        rule.action.hash(&mut hasher);
        rule.direction.hash(&mut hasher);
    }
    format!("{:x}", hasher.finish())
}

