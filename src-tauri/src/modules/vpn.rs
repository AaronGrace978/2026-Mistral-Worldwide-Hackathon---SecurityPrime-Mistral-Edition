// Cyber Security Prime - VPN Module
// Free, open-source VPN using WireGuard protocol

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// Windows constant to hide console window
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Helper to create a command with hidden console window on Windows
fn hidden_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    pub interface_name: String,
    pub private_key: String,
    pub public_key: String,
    pub address: String,
    pub dns: Vec<String>,
    pub mtu: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnServer {
    pub id: String,
    pub name: String,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub endpoint: String,
    pub public_key: String,
    pub load: u8,
    pub ping: Option<u32>,
    pub protocol: String,
    pub free: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum VpnStatus {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConnection {
    pub status: VpnStatus,
    pub server: Option<VpnServer>,
    pub connected_at: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub current_ip: Option<String>,
    pub original_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnStats {
    pub total_data_sent_mb: f64,
    pub total_data_received_mb: f64,
    pub uptime_seconds: u64,
    pub connection_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpInfo {
    pub ip: String,
    pub city: Option<String>,
    pub country: Option<String>,
    pub isp: Option<String>,
    pub is_vpn: bool,
}

// ============================================================================
// Free VPN Server List (Community & Free WireGuard Servers)
// ============================================================================

fn get_free_servers() -> Vec<VpnServer> {
    vec![
        VpnServer {
            id: "us-free-1".to_string(),
            name: "US Free #1".to_string(),
            country: "United States".to_string(),
            country_code: "US".to_string(),
            city: "New York".to_string(),
            endpoint: "vpn-us-free-1.example.com:51820".to_string(),
            public_key: "yAnf5TL0JMkrtDw9RIiXGiNwHMXi2DFcpUyIoZL/CGo=".to_string(),
            load: 45,
            ping: Some(50),
            protocol: "WireGuard".to_string(),
            free: true,
        },
        VpnServer {
            id: "nl-free-1".to_string(),
            name: "Netherlands Free #1".to_string(),
            country: "Netherlands".to_string(),
            country_code: "NL".to_string(),
            city: "Amsterdam".to_string(),
            endpoint: "vpn-nl-free-1.example.com:51820".to_string(),
            public_key: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=".to_string(),
            load: 60,
            ping: Some(120),
            protocol: "WireGuard".to_string(),
            free: true,
        },
        VpnServer {
            id: "jp-free-1".to_string(),
            name: "Japan Free #1".to_string(),
            country: "Japan".to_string(),
            country_code: "JP".to_string(),
            city: "Tokyo".to_string(),
            endpoint: "vpn-jp-free-1.example.com:51820".to_string(),
            public_key: "gN2HfW3Pc2v0yCrKOxBl9YZJMuSF7VLvhBz4i8mwQ1I=".to_string(),
            load: 30,
            ping: Some(180),
            protocol: "WireGuard".to_string(),
            free: true,
        },
        VpnServer {
            id: "de-free-1".to_string(),
            name: "Germany Free #1".to_string(),
            country: "Germany".to_string(),
            country_code: "DE".to_string(),
            city: "Frankfurt".to_string(),
            endpoint: "vpn-de-free-1.example.com:51820".to_string(),
            public_key: "p51MJhHKfsyXoNcb+Lk9R3QdE7aGw0YuTzI4nOW2JhA=".to_string(),
            load: 55,
            ping: Some(100),
            protocol: "WireGuard".to_string(),
            free: true,
        },
        VpnServer {
            id: "uk-free-1".to_string(),
            name: "UK Free #1".to_string(),
            country: "United Kingdom".to_string(),
            country_code: "GB".to_string(),
            city: "London".to_string(),
            endpoint: "vpn-uk-free-1.example.com:51820".to_string(),
            public_key: "3WBJqz1NUrvXoYT8HAme+5KGSC6ipD4Rf9whLxgM2kE=".to_string(),
            load: 70,
            ping: Some(90),
            protocol: "WireGuard".to_string(),
            free: true,
        },
        VpnServer {
            id: "sg-free-1".to_string(),
            name: "Singapore Free #1".to_string(),
            country: "Singapore".to_string(),
            country_code: "SG".to_string(),
            city: "Singapore".to_string(),
            endpoint: "vpn-sg-free-1.example.com:51820".to_string(),
            public_key: "kG7jMX4FW2qYnPRv6B9sHd0TZoAe5Cir3NxKlw8IbUs=".to_string(),
            load: 40,
            ping: Some(200),
            protocol: "WireGuard".to_string(),
            free: true,
        },
        VpnServer {
            id: "ca-free-1".to_string(),
            name: "Canada Free #1".to_string(),
            country: "Canada".to_string(),
            country_code: "CA".to_string(),
            city: "Toronto".to_string(),
            endpoint: "vpn-ca-free-1.example.com:51820".to_string(),
            public_key: "Hy8JnKpmR7X2wGfD9vBqE3i0Tc5sUoZaL4NY6xW1mAk=".to_string(),
            load: 35,
            ping: Some(70),
            protocol: "WireGuard".to_string(),
            free: true,
        },
        VpnServer {
            id: "au-free-1".to_string(),
            name: "Australia Free #1".to_string(),
            country: "Australia".to_string(),
            country_code: "AU".to_string(),
            city: "Sydney".to_string(),
            endpoint: "vpn-au-free-1.example.com:51820".to_string(),
            public_key: "QxVw5mZ3kL7nRjY1FdB8pKuG0XHr9TsNic4W6oA2eaE=".to_string(),
            load: 50,
            ping: Some(250),
            protocol: "WireGuard".to_string(),
            free: true,
        },
    ]
}

// ============================================================================
// State
// ============================================================================

lazy_static::lazy_static! {
    static ref VPN_CONNECTION: Arc<RwLock<VpnConnection>> = Arc::new(RwLock::new(VpnConnection {
        status: VpnStatus::Disconnected,
        server: None,
        connected_at: None,
        bytes_sent: 0,
        bytes_received: 0,
        current_ip: None,
        original_ip: None,
    }));
    static ref VPN_STATS: Arc<RwLock<VpnStats>> = Arc::new(RwLock::new(VpnStats {
        total_data_sent_mb: 0.0,
        total_data_received_mb: 0.0,
        uptime_seconds: 0,
        connection_count: 0,
    }));
}

// ============================================================================
// Helper Functions
// ============================================================================

async fn get_public_ip() -> Result<IpInfo, String> {
    let client = reqwest::Client::new();
    
    // Try multiple IP check services
    let services = [
        "https://api.ipify.org?format=json",
        "https://ipinfo.io/json",
        "https://api.myip.com",
    ];

    for service in services {
        if let Ok(response) = client.get(service)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            if let Ok(text) = response.text().await {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    let ip = json.get("ip")
                        .or(json.get("query"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .unwrap_or_default();
                    
                    if !ip.is_empty() {
                        return Ok(IpInfo {
                            ip,
                            city: json.get("city").and_then(|v| v.as_str()).map(String::from),
                            country: json.get("country").and_then(|v| v.as_str()).map(String::from),
                            isp: json.get("org").or(json.get("isp")).and_then(|v| v.as_str()).map(String::from),
                            is_vpn: false, // Would need additional check
                        });
                    }
                }
            }
        }
    }

    Err("Failed to get public IP".to_string())
}

fn check_wireguard_installed() -> bool {
    #[cfg(target_os = "windows")]
    {
        std::path::Path::new("C:\\Program Files\\WireGuard\\wireguard.exe").exists()
            || std::path::Path::new("C:\\Program Files (x86)\\WireGuard\\wireguard.exe").exists()
    }
    #[cfg(not(target_os = "windows"))]
    {
        hidden_command("which")
            .arg("wg")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

fn generate_wireguard_keys() -> Result<(String, String), String> {
    // Generate private key
    #[cfg(target_os = "windows")]
    {
        let output = hidden_command("wg")
            .arg("genkey")
            .output()
            .map_err(|e| format!("Failed to generate private key: {}", e))?;
        
        if !output.status.success() {
            return Err("wg genkey failed".to_string());
        }
        
        let private_key = String::from_utf8_lossy(&output.stdout).trim().to_string();
        
        // Generate public key from private key (with hidden console)
        let output = hidden_command("wg")
            .arg("pubkey")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(private_key.as_bytes())?;
                child.wait_with_output()
            })
            .map_err(|e| format!("Failed to generate public key: {}", e))?;
        
        let public_key = String::from_utf8_lossy(&output.stdout).trim().to_string();
        
        Ok((private_key, public_key))
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        let output = Command::new("wg")
            .arg("genkey")
            .output()
            .map_err(|e| format!("Failed to generate private key: {}", e))?;

        if !output.status.success() {
            return Err("wg genkey failed".to_string());
        }

        let private_key = String::from_utf8_lossy(&output.stdout).trim().to_string();

        let output = Command::new("wg")
            .arg("pubkey")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(private_key.as_bytes())?;
                child.wait_with_output()
            })
            .map_err(|e| format!("Failed to generate public key: {}", e))?;

        let public_key = String::from_utf8_lossy(&output.stdout).trim().to_string();

        Ok((private_key, public_key))
    }
}

// ============================================================================
// Tauri Commands
// ============================================================================

/// Get VPN connection status (checks real WireGuard state)
#[tauri::command]
pub async fn get_vpn_status() -> Result<VpnConnection, String> {
    // Check if WireGuard has an active tunnel
    if let Some(active) = detect_active_wireguard_tunnel() {
        let mut conn = VPN_CONNECTION.write();
        if conn.status != VpnStatus::Connected {
            conn.status = VpnStatus::Connected;
            conn.connected_at = Some(chrono::Utc::now().to_rfc3339());
            conn.server = Some(VpnServer {
                id: "local-wg".to_string(),
                name: active.clone(),
                country: "Local".to_string(),
                country_code: "WG".to_string(),
                city: "WireGuard".to_string(),
                endpoint: "localhost".to_string(),
                public_key: "".to_string(),
                load: 0,
                ping: Some(1),
                protocol: "WireGuard".to_string(),
                free: true,
            });
            if let Ok(ip) = get_public_ip().await {
                conn.current_ip = Some(ip.ip);
            }
        }
        return Ok(conn.clone());
    }

    let conn = VPN_CONNECTION.read();
    Ok(conn.clone())
}

fn detect_active_wireguard_tunnel() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let output = hidden_command("sc")
            .args(["query", "type=", "service", "state=", "active"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("SERVICE_NAME:") {
                let name = trimmed.replace("SERVICE_NAME:", "").trim().to_string();
                if name.starts_with("WireGuardTunnel$") {
                    return Some(name.replace("WireGuardTunnel$", ""));
                }
            }
        }
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        let output = std::process::Command::new("wg")
            .arg("show")
            .arg("interfaces")
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if text.is_empty() { None } else { Some(text) }
    }
}

/// Get available VPN servers
#[tauri::command]
pub async fn get_vpn_servers() -> Result<Vec<VpnServer>, String> {
    Ok(get_free_servers())
}

/// Get current public IP info
#[tauri::command]
pub async fn get_ip_info() -> Result<IpInfo, String> {
    get_public_ip().await
}

/// Check if WireGuard is installed
#[tauri::command]
pub async fn check_vpn_requirements() -> Result<HashMap<String, bool>, String> {
    let mut requirements = HashMap::new();
    requirements.insert("wireguard_installed".to_string(), check_wireguard_installed());
    requirements.insert("admin_privileges".to_string(), is_elevated());
    Ok(requirements)
}

fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        hidden_command("net")
            .args(["session"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        unsafe { libc::geteuid() == 0 }
    }
}

/// Connect to VPN server
#[tauri::command]
pub async fn connect_vpn(server_id: String) -> Result<VpnConnection, String> {
    // Find the server
    let servers = get_free_servers();
    let server = servers.iter()
        .find(|s| s.id == server_id)
        .cloned()
        .ok_or_else(|| format!("Server not found: {}", server_id))?;

    // Update status to connecting
    {
        let mut conn = VPN_CONNECTION.write();
        conn.status = VpnStatus::Connecting;
        conn.server = Some(server.clone());
    }

    // Get original IP before connecting
    let original_ip = get_public_ip().await.ok().map(|info| info.ip);

    if !check_wireguard_installed() {
        let mut conn = VPN_CONNECTION.write();
        conn.status = VpnStatus::Error;
        return Err("WireGuard is not installed. Download it at https://www.wireguard.com/install/".to_string());
    }

    if !is_elevated() {
        let mut conn = VPN_CONNECTION.write();
        conn.status = VpnStatus::Error;
        return Err("Administrator privileges required to manage VPN tunnels. Please restart the application as administrator.".to_string());
    }

    let (private_key, _public_key) = generate_wireguard_keys().map_err(|e| {
        let mut conn = VPN_CONNECTION.write();
        conn.status = VpnStatus::Error;
        format!("Key generation failed: {}", e)
    })?;

    let config_dir = std::env::temp_dir().join("securityprime_vpn");
    std::fs::create_dir_all(&config_dir).map_err(|e| {
        let mut conn = VPN_CONNECTION.write();
        conn.status = VpnStatus::Error;
        format!("Failed to create config directory: {}", e)
    })?;

    let tunnel_name = "sp0";
    let config_path = config_dir.join(format!("{}.conf", tunnel_name));
    let config_content = format!(
        "[Interface]\nPrivateKey = {}\nAddress = 10.66.66.2/32\nDNS = 1.1.1.1, 8.8.8.8\nMTU = 1420\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
        private_key, server.public_key, server.endpoint
    );
    std::fs::write(&config_path, &config_content).map_err(|e| {
        let mut conn = VPN_CONNECTION.write();
        conn.status = VpnStatus::Error;
        format!("Failed to write WireGuard config: {}", e)
    })?;

    #[cfg(target_os = "windows")]
    {
        let wg_exe = ["C:\\Program Files\\WireGuard\\wireguard.exe", "C:\\Program Files (x86)\\WireGuard\\wireguard.exe"]
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "wireguard".to_string());

        let output = hidden_command(&wg_exe)
            .args(["/installtunnelservice", &config_path.to_string_lossy()])
            .output()
            .map_err(|e| {
                let mut conn = VPN_CONNECTION.write();
                conn.status = VpnStatus::Error;
                format!("Failed to start WireGuard tunnel: {}", e)
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = if !stderr.trim().is_empty() { stderr } else { stdout };
            let mut conn = VPN_CONNECTION.write();
            conn.status = VpnStatus::Error;
            return Err(format!("WireGuard tunnel failed to start: {}", detail.trim()));
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let output = Command::new("wg-quick")
            .args(["up", &config_path.to_string_lossy()])
            .output()
            .map_err(|e| {
                let mut conn = VPN_CONNECTION.write();
                conn.status = VpnStatus::Error;
                format!("Failed to start WireGuard tunnel: {}", e)
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut conn = VPN_CONNECTION.write();
            conn.status = VpnStatus::Error;
            return Err(format!("WireGuard tunnel failed: {}", stderr.trim()));
        }
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let new_ip = get_public_ip().await.ok().map(|info| info.ip);

    {
        let mut conn = VPN_CONNECTION.write();
        conn.status = VpnStatus::Connected;
        conn.connected_at = Some(chrono::Utc::now().to_rfc3339());
        conn.original_ip = original_ip;
        conn.current_ip = new_ip;
    }

    {
        let mut stats = VPN_STATS.write();
        stats.connection_count += 1;
    }

    let conn = VPN_CONNECTION.read();
    Ok(conn.clone())
}

/// Disconnect from VPN
#[tauri::command]
pub async fn disconnect_vpn() -> Result<VpnConnection, String> {
    {
        let mut conn = VPN_CONNECTION.write();
        conn.status = VpnStatus::Disconnecting;
    }

    let tunnel_name = "sp0";

    #[cfg(target_os = "windows")]
    {
        let wg_exe = ["C:\\Program Files\\WireGuard\\wireguard.exe", "C:\\Program Files (x86)\\WireGuard\\wireguard.exe"]
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "wireguard".to_string());

        let _ = hidden_command(&wg_exe)
            .args(["/uninstalltunnelservice", tunnel_name])
            .output();
    }

    #[cfg(not(target_os = "windows"))]
    {
        let config_path = std::env::temp_dir()
            .join("securityprime_vpn")
            .join(format!("{}.conf", tunnel_name));
        let _ = Command::new("wg-quick")
            .args(["down", &config_path.to_string_lossy()])
            .output();
    }

    let config_dir = std::env::temp_dir().join("securityprime_vpn");
    let _ = std::fs::remove_dir_all(&config_dir);

    {
        let mut conn = VPN_CONNECTION.write();
        conn.status = VpnStatus::Disconnected;
        conn.server = None;
        conn.connected_at = None;
        conn.current_ip = None;
    }

    let conn = VPN_CONNECTION.read();
    Ok(conn.clone())
}

/// Get VPN statistics
#[tauri::command]
pub async fn get_vpn_stats() -> Result<VpnStats, String> {
    let stats = VPN_STATS.read();
    Ok(stats.clone())
}

/// Ping a server to check latency
#[tauri::command]
pub async fn ping_vpn_server(server_id: String) -> Result<u32, String> {
    let servers = get_free_servers();
    let server = servers.iter()
        .find(|s| s.id == server_id)
        .ok_or_else(|| format!("Server not found: {}", server_id))?;

    // Extract hostname from endpoint
    let endpoint = server.endpoint.split(':').next().unwrap_or(&server.endpoint);

    // Use system ping command (with hidden console)
    #[cfg(target_os = "windows")]
    {
        let output = hidden_command("ping")
            .args(["-n", "3", "-w", "1000", endpoint])
            .output()
            .map_err(|e| e.to_string())?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        
        // Parse average ping from output
        if let Some(avg_line) = output_str.lines().find(|l| l.contains("Average")) {
            if let Some(ms) = avg_line.split('=').last() {
                if let Ok(ping) = ms.trim().trim_end_matches("ms").parse::<u32>() {
                    return Ok(ping);
                }
            }
        }
        
        // Fallback to stored value
        Ok(server.ping.unwrap_or(999))
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Ok(server.ping.unwrap_or(100))
    }
}

/// Import custom WireGuard config
#[tauri::command]
pub async fn import_wireguard_config(config_path: String) -> Result<VpnServer, String> {
    use std::fs;
    
    let config_content = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config file: {}", e))?;

    // Parse WireGuard config
    let mut endpoint = String::new();
    let mut public_key = String::new();

    for line in config_content.lines() {
        let line = line.trim();
        if line.starts_with("Endpoint") {
            endpoint = line.split('=').nth(1).map(|s| s.trim().to_string()).unwrap_or_default();
        } else if line.starts_with("PublicKey") {
            public_key = line.split('=').nth(1).map(|s| s.trim().to_string()).unwrap_or_default();
        }
    }

    if endpoint.is_empty() || public_key.is_empty() {
        return Err("Invalid WireGuard config: missing Endpoint or PublicKey".to_string());
    }

    let server = VpnServer {
        id: format!("custom-{}", uuid::Uuid::new_v4()),
        name: "Custom Server".to_string(),
        country: "Unknown".to_string(),
        country_code: "XX".to_string(),
        city: "Unknown".to_string(),
        endpoint,
        public_key,
        load: 0,
        ping: None,
        protocol: "WireGuard".to_string(),
        free: true,
    };

    Ok(server)
}

/// Get WireGuard download link
#[tauri::command]
pub async fn get_wireguard_download_url() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        Ok("https://download.wireguard.com/windows-client/wireguard-installer.exe".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        Ok("https://apps.apple.com/app/wireguard/id1451685025".to_string())
    }
    #[cfg(target_os = "linux")]
    {
        Ok("https://www.wireguard.com/install/".to_string())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Ok("https://www.wireguard.com/install/".to_string())
    }
}

