// Cyber Security Prime - Network Monitor Module
// Monitors network connections and traffic using real system data

use crate::utils::generate_id;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::collections::HashMap;
use sysinfo::{Networks, System};
use parking_lot::RwLock;
use once_cell::sync::Lazy;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// Windows constant to hide console window
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

// Cache for network stats to calculate per-second rates
static NETWORK_CACHE: Lazy<RwLock<NetworkCache>> = Lazy::new(|| {
    RwLock::new(NetworkCache::default())
});

#[derive(Debug, Clone, Default)]
struct NetworkCache {
    last_bytes_sent: u64,
    last_bytes_received: u64,
    last_check: Option<std::time::Instant>,
    bytes_sent_per_sec: u64,
    bytes_received_per_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub id: String,
    pub process_name: String,
    pub process_id: u32,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub established_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_connections: u32,
    pub active_connections: u32,
    pub bytes_sent_total: u64,
    pub bytes_received_total: u64,
    pub bytes_sent_per_sec: u64,
    pub bytes_received_per_sec: u64,
    pub blocked_connections: u32,
    pub suspicious_connections: u32,
}

/// Known suspicious IP ranges and ports
const SUSPICIOUS_PORTS: &[u16] = &[
    4444, 5555, 6666, 31337, 12345, 27374, 1234, 6667, 6668, 6669, // Common malware/RAT ports
];

/// Helper to create a command with hidden console window on Windows
fn hidden_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

/// Get all active network connections using netstat
pub fn get_connections() -> Result<Vec<NetworkConnection>, String> {
    // Run netstat -ano to get all connections with PIDs (with hidden console)
    let output = hidden_command("netstat")
        .args(&["-ano"])
        .output()
        .map_err(|e| format!("Failed to run netstat: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Get process names for PIDs
    let process_names = get_process_names()?;
    
    let mut connections = Vec::new();
    
    for line in stdout.lines().skip(4) { // Skip header lines
        if let Some(conn) = parse_netstat_line(line, &process_names) {
            connections.push(conn);
        }
    }
    
    // Limit to reasonable number for display
    if connections.len() > 200 {
        // Sort by state (ESTABLISHED first) and truncate
        connections.sort_by(|a, b| {
            if a.state == "ESTABLISHED" && b.state != "ESTABLISHED" {
                std::cmp::Ordering::Less
            } else if a.state != "ESTABLISHED" && b.state == "ESTABLISHED" {
                std::cmp::Ordering::Greater
            } else {
                a.process_name.cmp(&b.process_name)
            }
        });
        connections.truncate(200);
    }
    
    Ok(connections)
}

/// Parse a single netstat output line
fn parse_netstat_line(line: &str, process_names: &HashMap<u32, String>) -> Option<NetworkConnection> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    
    // TCP lines have: Proto LocalAddr ForeignAddr State PID
    // UDP lines have: Proto LocalAddr ForeignAddr PID (no state)
    if parts.len() < 4 {
        return None;
    }
    
    let protocol = parts[0].to_uppercase();
    if protocol != "TCP" && protocol != "UDP" {
        return None;
    }
    
    // Parse local address
    let (local_address, local_port) = parse_address(parts[1])?;
    
    // Parse remote/foreign address
    let (remote_address, remote_port) = parse_address(parts[2])?;
    
    // Parse state and PID based on protocol
    let (state, pid) = if protocol == "TCP" {
        if parts.len() < 5 {
            return None;
        }
        (parts[3].to_string(), parts[4].parse::<u32>().ok()?)
    } else {
        // UDP has no state
        ("".to_string(), parts[3].parse::<u32>().ok()?)
    };
    
    // Get process name
    let process_name = process_names
        .get(&pid)
        .cloned()
        .unwrap_or_else(|| format!("PID:{}", pid));
    
    let remote_hostname = if remote_address != "0.0.0.0" && remote_address != "*" && remote_address != "::" {
        resolve_hostname(&remote_address)
    } else {
        None
    };

    Some(NetworkConnection {
        id: generate_id(),
        process_name,
        process_id: pid,
        local_address,
        local_port,
        remote_address,
        remote_port,
        protocol,
        state,
        bytes_sent: 0,
        bytes_received: 0,
        established_at: chrono::Utc::now().to_rfc3339(),
        remote_hostname,
    })
}

/// Parse an address string like "192.168.1.1:443" or "[::1]:443"
fn parse_address(addr: &str) -> Option<(String, u16)> {
    // Handle IPv6 addresses in brackets
    if addr.starts_with('[') {
        let bracket_end = addr.find(']')?;
        let ip = &addr[1..bracket_end];
        let port_str = &addr[bracket_end + 2..]; // Skip ']:
        let port = port_str.parse::<u16>().ok()?;
        return Some((ip.to_string(), port));
    }
    
    // Handle IPv4 addresses
    let last_colon = addr.rfind(':')?;
    let ip = &addr[..last_colon];
    let port_str = &addr[last_colon + 1..];
    
    // Handle wildcard addresses
    let ip = if ip == "0.0.0.0" || ip == "*" {
        "0.0.0.0".to_string()
    } else {
        ip.to_string()
    };
    
    let port = port_str.parse::<u16>().unwrap_or(0);
    
    Some((ip, port))
}

/// Get process names for all running processes
fn get_process_names() -> Result<HashMap<u32, String>, String> {
    let mut sys = System::new();
    sys.refresh_processes();
    
    let mut names = HashMap::new();
    
    for (pid, process) in sys.processes() {
        names.insert(pid.as_u32(), process.name().to_string());
    }
    
    Ok(names)
}

/// Get network statistics using sysinfo
/// Optimized to avoid calling the slow get_connections() function
pub fn get_stats() -> Result<NetworkStats, String> {
    // Get connection counts directly from netstat (much faster than parsing all details)
    let (total_connections, active_connections) = count_connections_fast()?;
    
    // Get network interface stats
    let networks = Networks::new_with_refreshed_list();
    
    let mut bytes_sent_total: u64 = 0;
    let mut bytes_received_total: u64 = 0;
    
    for (_name, network) in networks.iter() {
        bytes_sent_total += network.total_transmitted();
        bytes_received_total += network.total_received();
    }
    
    // Calculate per-second rates
    let (bytes_sent_per_sec, bytes_received_per_sec) = {
        let mut cache = NETWORK_CACHE.write();
        let now = std::time::Instant::now();
        
        let (sent_rate, recv_rate) = if let Some(last_check) = cache.last_check {
            let elapsed = now.duration_since(last_check).as_secs_f64();
            if elapsed > 0.0 {
                let sent_diff = bytes_sent_total.saturating_sub(cache.last_bytes_sent);
                let recv_diff = bytes_received_total.saturating_sub(cache.last_bytes_received);
                (
                    (sent_diff as f64 / elapsed) as u64,
                    (recv_diff as f64 / elapsed) as u64,
                )
            } else {
                (cache.bytes_sent_per_sec, cache.bytes_received_per_sec)
            }
        } else {
            (0, 0)
        };
        
        cache.last_bytes_sent = bytes_sent_total;
        cache.last_bytes_received = bytes_received_total;
        cache.last_check = Some(now);
        cache.bytes_sent_per_sec = sent_rate;
        cache.bytes_received_per_sec = recv_rate;
        
        (sent_rate, recv_rate)
    };
    
    // Count suspicious connections by inspecting current connections
    let suspicious_connections = count_suspicious_connections();
    // Count blocked connections from Windows Firewall logs
    let blocked_connections = count_blocked_connections();

    Ok(NetworkStats {
        total_connections,
        active_connections,
        bytes_sent_total,
        bytes_received_total,
        bytes_sent_per_sec,
        bytes_received_per_sec,
        blocked_connections,
        suspicious_connections,
    })
}

/// Fast connection counting without full parsing
fn count_connections_fast() -> Result<(u32, u32), String> {
    // Run netstat with minimal output (just counting lines is faster than parsing)
    let output = hidden_command("netstat")
        .args(&["-an"])
        .output()
        .map_err(|e| format!("Failed to run netstat: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    let mut total = 0u32;
    let mut established = 0u32;
    
    for line in stdout.lines().skip(4) {
        let line = line.trim();
        if line.starts_with("TCP") || line.starts_with("UDP") {
            total += 1;
            if line.contains("ESTABLISHED") {
                established += 1;
            } else if line.starts_with("UDP") {
                // UDP connections are considered "active"
                established += 1;
            }
        }
    }
    
    Ok((total, established))
}

/// Check if a connection appears suspicious
fn is_suspicious_connection(conn: &NetworkConnection) -> bool {
    // Check for suspicious ports
    if SUSPICIOUS_PORTS.contains(&conn.remote_port) {
        return true;
    }
    
    // Check for connections to common malware IPs (example ranges)
    // In production, this would use a threat intelligence feed
    let suspicious_ip_prefixes = [
        "185.234.", // Known malicious range (example)
        "45.33.",   // Common VPS provider used for malware
    ];
    
    for prefix in suspicious_ip_prefixes {
        if conn.remote_address.starts_with(prefix) {
            return true;
        }
    }
    
    // Check for unknown processes with external connections
    if conn.process_name.starts_with("PID:") && conn.state == "ESTABLISHED" {
        return true;
    }
    
    false
}

/// Get detailed information about network interfaces
pub fn get_interfaces() -> Result<Vec<NetworkInterfaceInfo>, String> {
    let networks = Networks::new_with_refreshed_list();
    let mut interfaces = Vec::new();
    
    for (name, network) in networks.iter() {
        interfaces.push(NetworkInterfaceInfo {
            name: name.to_string(),
            mac_address: format_mac_address(network.mac_address()),
            bytes_sent: network.total_transmitted(),
            bytes_received: network.total_received(),
            packets_sent: network.total_packets_transmitted(),
            packets_received: network.total_packets_received(),
            errors_in: network.total_errors_on_received(),
            errors_out: network.total_errors_on_transmitted(),
        });
    }
    
    Ok(interfaces)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub mac_address: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub errors_in: u64,
    pub errors_out: u64,
}

fn format_mac_address(mac: sysinfo::MacAddr) -> String {
    format!("{}", mac)
}

/// DNS cache for resolved hostnames
static DNS_CACHE: Lazy<RwLock<HashMap<String, Option<String>>>> = Lazy::new(|| {
    RwLock::new(HashMap::new())
});

/// Resolve IP address to hostname via real reverse DNS lookup (with cache)
pub fn resolve_hostname(ip: &str) -> Option<String> {
    if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" || ip == "::" || ip == "*" {
        return Some("localhost".to_string());
    }

    // Check cache first
    {
        let cache = DNS_CACHE.read();
        if let Some(result) = cache.get(ip) {
            return result.clone();
        }
    }

    // Perform real reverse DNS lookup
    let result = {
        use std::net::IpAddr;
        match ip.parse::<IpAddr>() {
            Ok(addr) => {
                match dns_lookup::lookup_addr(&addr) {
                    Ok(hostname) => {
                        if hostname == ip {
                            None
                        } else {
                            Some(hostname)
                        }
                    }
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    };

    // Cache the result (limit cache size)
    {
        let mut cache = DNS_CACHE.write();
        if cache.len() < 2000 {
            cache.insert(ip.to_string(), result.clone());
        }
    }

    result
}

/// Count suspicious connections from current netstat output
fn count_suspicious_connections() -> u32 {
    let output = match hidden_command("netstat")
        .args(&["-an"])
        .output() {
        Ok(o) => o,
        Err(_) => return 0,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut count = 0u32;

    for line in stdout.lines().skip(4) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 { continue; }

        let protocol = parts[0].to_uppercase();
        if protocol != "TCP" && protocol != "UDP" { continue; }

        // Check remote address for suspicious ports
        if let Some(remote) = parts.get(2) {
            if let Some(port_str) = remote.rsplit(':').next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    if SUSPICIOUS_PORTS.contains(&port) {
                        count += 1;
                    }
                }
            }
        }
    }

    count
}

/// Count recently blocked connections from Windows Firewall event log
fn count_blocked_connections() -> u32 {
    #[cfg(windows)]
    {
        let output = match hidden_command("powershell")
            .args(&[
                "-NoProfile", "-Command",
                "(Get-WinEvent -FilterHashtable @{LogName='Security';Id=5157} -MaxEvents 100 -ErrorAction SilentlyContinue | Measure-Object).Count"
            ])
            .output() {
            Ok(o) => o,
            Err(_) => return 0,
        };

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        stdout.parse::<u32>().unwrap_or(0)
    }

    #[cfg(not(windows))]
    { 0 }
}

