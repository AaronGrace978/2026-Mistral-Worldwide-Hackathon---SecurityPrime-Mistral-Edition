// Cyber Security Prime — Audit Report Generator
// Generates structured HTML/JSON audit reports from live system telemetry

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use parking_lot::RwLock;
use lazy_static::lazy_static;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

// ============================================================================
// Data structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub id: String,
    pub title: String,
    pub framework: String,
    pub generated_at: String,
    pub generated_by: String,
    pub sections: Vec<ReportSection>,
    pub summary: ReportSummary,
    pub html_content: String,
    pub json_content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSection {
    pub title: String,
    pub status: String,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
    pub score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub overall_score: f32,
    pub critical_findings: u32,
    pub total_findings: u32,
    pub compliance_status: String,
}

lazy_static! {
    static ref REPORT_STORE: RwLock<HashMap<String, AuditReport>> =
        RwLock::new(HashMap::new());
}

// ============================================================================
// System data collectors
// ============================================================================

fn run_cmd(program: &str, args: &[&str]) -> String {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

fn collect_process_list() -> String {
    run_cmd("tasklist", &["/v", "/fo", "csv"])
}

fn collect_firewall_status() -> String {
    run_cmd("netsh", &["advfirewall", "show", "allprofiles"])
}

fn collect_network_connections() -> String {
    run_cmd("netstat", &["-ano"])
}

fn collect_services() -> String {
    run_cmd("sc", &["query", "type=", "service", "state=", "all"])
}

fn collect_hostname() -> String {
    run_cmd("hostname", &[]).trim().to_string()
}

fn collect_os_version() -> String {
    let raw = run_cmd("cmd", &["/c", "ver"]);
    raw.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("Unknown")
        .trim()
        .to_string()
}

fn collect_system_info_short() -> String {
    run_cmd("systeminfo", &["/fo", "csv"])
}

// ============================================================================
// Analysis helpers
// ============================================================================

fn analyze_processes(csv: &str) -> ReportSection {
    let lines: Vec<&str> = csv.lines().collect();
    let total = if lines.len() > 1 { lines.len() - 1 } else { 0 };

    let suspicious_keywords = [
        "mimikatz", "cobaltstrike", "meterpreter", "psexec",
        "ncat", "netcat", "lazagne", "procdump",
    ];

    let mut findings: Vec<String> = Vec::new();
    let mut recommendations: Vec<String> = Vec::new();
    let mut suspicious_count = 0u32;

    for line in lines.iter().skip(1) {
        let lower = line.to_lowercase();
        for kw in &suspicious_keywords {
            if lower.contains(kw) {
                suspicious_count += 1;
                findings.push(format!("Suspicious process detected matching '{}': {}", kw,
                    line.split(',').next().unwrap_or("").trim_matches('"')));
            }
        }
    }

    let unsigned_shells: Vec<&str> = lines.iter().skip(1).filter(|l| {
        let lo = l.to_lowercase();
        (lo.contains("powershell") || lo.contains("cmd.exe")) && lo.contains("n/a")
    }).copied().collect();

    if !unsigned_shells.is_empty() {
        findings.push(format!("{} shell processes running without verified signature", unsigned_shells.len()));
        recommendations.push("Review unsigned shell processes for legitimacy".to_string());
    }

    findings.insert(0, format!("Total running processes: {}", total));

    let score = if suspicious_count > 0 {
        (100.0 - (suspicious_count as f32 * 15.0)).max(0.0)
    } else if unsigned_shells.is_empty() {
        100.0
    } else {
        85.0
    };

    if suspicious_count > 0 {
        recommendations.push("Immediately investigate flagged processes and consider isolation".to_string());
    }
    if recommendations.is_empty() {
        recommendations.push("No immediate action required — continue periodic monitoring".to_string());
    }

    let status = if suspicious_count > 0 { "FAIL" } else { "PASS" };

    ReportSection {
        title: "Running Processes".to_string(),
        status: status.to_string(),
        findings,
        recommendations,
        score,
    }
}

fn analyze_firewall(raw: &str) -> ReportSection {
    let mut findings: Vec<String> = Vec::new();
    let mut recommendations: Vec<String> = Vec::new();
    let mut profiles_on = 0u32;
    let mut profiles_off = 0u32;

    let lower = raw.to_lowercase();
    for profile in &["domain", "private", "public"] {
        if let Some(idx) = lower.find(&format!("{} profile", profile)) {
            let section = &lower[idx..];
            if section.contains("state                                 on") || section.contains("state                                  on") {
                profiles_on += 1;
                findings.push(format!("{} profile firewall: ON", profile.to_uppercase()));
            } else {
                profiles_off += 1;
                findings.push(format!("{} profile firewall: OFF ⚠", profile.to_uppercase()));
                recommendations.push(format!("Enable the {} profile firewall immediately", profile));
            }
        }
    }

    if profiles_off == 0 && profiles_on == 0 {
        // Fallback: just count "ON" / "OFF" keywords
        let on_count = lower.matches("state").count();
        findings.push(format!("Firewall state entries detected: {}", on_count));
        if lower.contains("off") {
            profiles_off = 1;
            findings.push("At least one firewall profile appears disabled".to_string());
            recommendations.push("Review and enable all firewall profiles".to_string());
        }
    }

    let score = if profiles_off == 0 { 100.0 } else { (100.0 - profiles_off as f32 * 30.0).max(0.0) };

    if recommendations.is_empty() {
        recommendations.push("All firewall profiles active — maintain current configuration".to_string());
    }

    let status = if profiles_off > 0 { "FAIL" } else { "PASS" };

    ReportSection {
        title: "Firewall Status".to_string(),
        status: status.to_string(),
        findings,
        recommendations,
        score,
    }
}

fn analyze_network(raw: &str) -> ReportSection {
    let lines: Vec<&str> = raw.lines().collect();
    let mut findings: Vec<String> = Vec::new();
    let mut recommendations: Vec<String> = Vec::new();

    let mut established = 0u32;
    let mut listening = 0u32;
    let mut high_risk_ports: Vec<String> = Vec::new();

    let risky_ports = [
        (4444, "Metasploit default"),
        (5555, "Common RAT"),
        (1337, "Hacker convention"),
        (31337, "Back Orifice"),
        (6667, "IRC C2"),
        (8443, "Alternate HTTPS / C2"),
    ];

    for line in &lines {
        let lower = line.to_lowercase();
        if lower.contains("established") { established += 1; }
        if lower.contains("listening") { listening += 1; }

        for (port, label) in &risky_ports {
            let token = format!(":{}", port);
            if lower.contains(&token) {
                high_risk_ports.push(format!("Port {} ({}) — {}", port, label, line.trim()));
            }
        }
    }

    findings.push(format!("ESTABLISHED connections: {}", established));
    findings.push(format!("LISTENING ports: {}", listening));

    if !high_risk_ports.is_empty() {
        findings.push(format!("{} connection(s) on high-risk ports", high_risk_ports.len()));
        for hp in &high_risk_ports {
            findings.push(hp.clone());
        }
        recommendations.push("Investigate connections on unusual ports for C2 or RAT activity".to_string());
    }

    if listening > 50 {
        recommendations.push("Unusually high number of listening ports — review for unnecessary services".to_string());
    }

    let score = if !high_risk_ports.is_empty() {
        (100.0 - high_risk_ports.len() as f32 * 20.0).max(0.0)
    } else if listening > 50 {
        75.0
    } else {
        100.0
    };

    if recommendations.is_empty() {
        recommendations.push("Network connections appear normal — continue monitoring".to_string());
    }

    let status = if !high_risk_ports.is_empty() { "FAIL" } else { "PASS" };

    ReportSection {
        title: "Network Connections".to_string(),
        status: status.to_string(),
        findings,
        recommendations,
        score,
    }
}

fn analyze_services(raw: &str) -> ReportSection {
    let mut findings: Vec<String> = Vec::new();
    let mut recommendations: Vec<String> = Vec::new();

    let mut running = 0u32;
    let mut stopped = 0u32;

    let security_services = [
        "wuauserv",        // Windows Update
        "wscsvc",          // Security Center
        "mpssvc",          // Windows Firewall
        "windefend",       // Windows Defender
        "eventlog",        // Event Log
        "bits",            // Background Intelligent Transfer
    ];

    let lower = raw.to_lowercase();
    for chunk in lower.split("service_name:") {
        if chunk.contains("running") { running += 1; }
        if chunk.contains("stopped") { stopped += 1; }
    }

    findings.push(format!("Running services: {}", running));
    findings.push(format!("Stopped services: {}", stopped));

    for svc in &security_services {
        if let Some(idx) = lower.find(svc) {
            let section = &lower[idx..idx + 300.min(lower.len() - idx)];
            if section.contains("stopped") {
                findings.push(format!("Critical security service '{}' is STOPPED ⚠", svc));
                recommendations.push(format!("Start the '{}' service immediately", svc));
            }
        }
    }

    let critical_stopped: u32 = findings.iter().filter(|f| f.contains("STOPPED")).count() as u32;
    let score = (100.0 - critical_stopped as f32 * 20.0).max(0.0);

    if recommendations.is_empty() {
        recommendations.push("All critical security services running — no action needed".to_string());
    }

    let status = if critical_stopped > 0 { "WARN" } else { "PASS" };

    ReportSection {
        title: "Windows Services".to_string(),
        status: status.to_string(),
        findings,
        recommendations,
        score,
    }
}

// ============================================================================
// HTML template
// ============================================================================

fn render_html(report: &AuditReport) -> String {
    let mut section_html = String::new();
    for (i, s) in report.sections.iter().enumerate() {
        let status_color = match s.status.as_str() {
            "PASS" => "#22c55e",
            "WARN" => "#f59e0b",
            _ => "#ef4444",
        };
        let findings_li: String = s.findings.iter()
            .map(|f| format!("<li>{}</li>", html_escape(f)))
            .collect::<Vec<_>>()
            .join("\n");
        let recs_li: String = s.recommendations.iter()
            .map(|r| format!("<li>{}</li>", html_escape(r)))
            .collect::<Vec<_>>()
            .join("\n");

        section_html.push_str(&format!(r#"
        <div class="section">
            <div class="section-header">
                <h2>{idx}. {title}</h2>
                <span class="badge" style="background:{color}">{status}</span>
                <span class="score">{score:.0}/100</span>
            </div>
            <h3>Findings</h3>
            <ul>{findings}</ul>
            <h3>Recommendations</h3>
            <ul class="recs">{recs}</ul>
        </div>"#,
            idx = i + 1,
            title = html_escape(&s.title),
            color = status_color,
            status = s.status,
            score = s.score,
            findings = findings_li,
            recs = recs_li,
        ));
    }

    let overall_color = if report.summary.overall_score >= 80.0 { "#22c55e" }
        else if report.summary.overall_score >= 50.0 { "#f59e0b" }
        else { "#ef4444" };

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}}
.container{{max-width:960px;margin:0 auto}}
header{{text-align:center;padding:2rem 0;border-bottom:2px solid #1e293b}}
header h1{{font-size:1.8rem;color:#38bdf8}}
header .subtitle{{color:#94a3b8;margin-top:.3rem}}
.meta{{display:flex;justify-content:space-between;color:#64748b;margin-top:1rem;font-size:.85rem}}
.summary{{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin:2rem 0}}
.summary-card{{background:#1e293b;border-radius:12px;padding:1.2rem;text-align:center}}
.summary-card .value{{font-size:2rem;font-weight:700;margin:.4rem 0}}
.summary-card .label{{font-size:.8rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em}}
.section{{background:#1e293b;border-radius:12px;padding:1.5rem;margin-bottom:1.5rem}}
.section-header{{display:flex;align-items:center;gap:.8rem;margin-bottom:1rem}}
.section-header h2{{font-size:1.15rem;flex:1}}
.badge{{padding:.25rem .7rem;border-radius:6px;font-size:.75rem;font-weight:600;color:#fff}}
.score{{font-weight:600;color:#38bdf8}}
h3{{font-size:.95rem;color:#94a3b8;margin:.8rem 0 .4rem;text-transform:uppercase;letter-spacing:.04em}}
ul{{list-style:none;padding:0}}
ul li{{padding:.35rem 0;padding-left:1rem;position:relative;font-size:.9rem}}
ul li::before{{content:"›";position:absolute;left:0;color:#38bdf8;font-weight:700}}
ul.recs li::before{{content:"→";color:#22c55e}}
footer{{text-align:center;margin-top:3rem;padding-top:1.5rem;border-top:1px solid #1e293b;color:#475569;font-size:.78rem}}
@media print{{body{{background:#fff;color:#1e293b}} .section,.summary-card{{border:1px solid #e2e8f0}} header h1{{color:#0ea5e9}} footer{{color:#94a3b8}}}}
</style>
</head>
<body>
<div class="container">
<header>
    <h1>🛡 SecurityPrime — {title}</h1>
    <div class="subtitle">{framework}</div>
    <div class="meta">
        <span>Report ID: {id}</span>
        <span>Generated: {generated_at}</span>
        <span>By: {generated_by}</span>
    </div>
</header>

<div class="summary">
    <div class="summary-card">
        <div class="label">Overall Score</div>
        <div class="value" style="color:{overall_color}">{overall_score:.0}</div>
    </div>
    <div class="summary-card">
        <div class="label">Critical Findings</div>
        <div class="value" style="color:#ef4444">{critical}</div>
    </div>
    <div class="summary-card">
        <div class="label">Total Findings</div>
        <div class="value">{total}</div>
    </div>
    <div class="summary-card">
        <div class="label">Compliance</div>
        <div class="value" style="font-size:1rem">{compliance}</div>
    </div>
</div>

{sections}

<footer>
    <p>This report was auto-generated by SecurityPrime Audit Engine. Findings are based on live
    system telemetry collected at the time of generation. This report does not constitute a
    certified compliance assessment. For official compliance, engage a qualified auditor.</p>
</footer>
</div>
</body>
</html>"#,
        title = html_escape(&report.title),
        framework = html_escape(&report.framework),
        id = report.id,
        generated_at = report.generated_at,
        generated_by = html_escape(&report.generated_by),
        overall_color = overall_color,
        overall_score = report.summary.overall_score,
        critical = report.summary.critical_findings,
        total = report.summary.total_findings,
        compliance = html_escape(&report.summary.compliance_status),
        sections = section_html,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

// ============================================================================
// Report builders
// ============================================================================

fn build_report(title: &str, framework: &str, sections: Vec<ReportSection>) -> AuditReport {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let hostname = collect_hostname();

    let total_findings: u32 = sections.iter().map(|s| s.findings.len() as u32).sum();
    let critical_findings: u32 = sections.iter()
        .filter(|s| s.status == "FAIL")
        .map(|s| s.findings.len() as u32)
        .sum();
    let overall_score: f32 = if sections.is_empty() {
        0.0
    } else {
        sections.iter().map(|s| s.score).sum::<f32>() / sections.len() as f32
    };
    let compliance_status = if overall_score >= 80.0 { "Compliant" }
        else if overall_score >= 50.0 { "Partially Compliant" }
        else { "Non-Compliant" };

    let summary = ReportSummary {
        overall_score,
        critical_findings,
        total_findings,
        compliance_status: compliance_status.to_string(),
    };

    let mut report = AuditReport {
        id: id.clone(),
        title: title.to_string(),
        framework: framework.to_string(),
        generated_at: now,
        generated_by: format!("SecurityPrime on {}", hostname),
        sections,
        summary,
        html_content: String::new(),
        json_content: String::new(),
    };

    report.html_content = render_html(&report);
    report.json_content = serde_json::to_string_pretty(&report).unwrap_or_default();

    REPORT_STORE.write().insert(id, report.clone());
    report
}

// ============================================================================
// GDPR compliance checks
// ============================================================================

fn gdpr_sections() -> Vec<ReportSection> {
    let mut sections = Vec::new();

    // Encryption assessment
    let bitlocker_raw = run_cmd("manage-bde", &["-status"]);
    let bl_lower = bitlocker_raw.to_lowercase();
    let encrypted = bl_lower.contains("percentage encrypted") && bl_lower.contains("100");
    sections.push(ReportSection {
        title: "Data Encryption (Art. 32)".to_string(),
        status: if encrypted { "PASS" } else { "WARN" }.to_string(),
        findings: vec![
            if encrypted {
                "BitLocker full-disk encryption is active".to_string()
            } else {
                "BitLocker encryption not fully enabled or not detected".to_string()
            },
        ],
        recommendations: if encrypted {
            vec!["Maintain current encryption configuration".to_string()]
        } else {
            vec![
                "Enable BitLocker on all fixed drives".to_string(),
                "Ensure recovery keys are escrowed in Active Directory or a secure vault".to_string(),
            ]
        },
        score: if encrypted { 100.0 } else { 40.0 },
    });

    // Audit logging
    let audit_raw = run_cmd("auditpol", &["/get", "/category:*"]);
    let audit_lower = audit_raw.to_lowercase();
    let logging_ok = audit_lower.contains("success") && audit_lower.contains("failure");
    sections.push(ReportSection {
        title: "Audit Logging (Art. 30)".to_string(),
        status: if logging_ok { "PASS" } else { "WARN" }.to_string(),
        findings: if logging_ok {
            vec!["Windows audit policy includes success and failure logging".to_string()]
        } else {
            vec!["Audit policy may be incomplete — not all categories have success+failure enabled".to_string()]
        },
        recommendations: if logging_ok {
            vec!["Review audit log retention period to meet 72-hour breach notification window".to_string()]
        } else {
            vec![
                "Enable success and failure auditing for Logon, Object Access, and Policy Change categories".to_string(),
                "Configure centralized log forwarding (SIEM)".to_string(),
            ]
        },
        score: if logging_ok { 90.0 } else { 50.0 },
    });

    // User account hygiene
    let users_raw = run_cmd("net", &["user"]);
    let user_lines: Vec<&str> = users_raw.lines()
        .filter(|l| !l.trim().is_empty() && !l.contains("---") && !l.contains("User accounts") && !l.contains("The command"))
        .collect();
    let user_count = user_lines.iter()
        .flat_map(|l| l.split_whitespace())
        .count();
    sections.push(ReportSection {
        title: "Access Control (Art. 25 / Art. 32)".to_string(),
        status: if user_count <= 5 { "PASS" } else { "WARN" }.to_string(),
        findings: vec![
            format!("Local user accounts detected: ~{}", user_count),
        ],
        recommendations: vec![
            "Disable or remove unnecessary local accounts".to_string(),
            "Enforce strong password policy via Group Policy".to_string(),
            "Implement multi-factor authentication where feasible".to_string(),
        ],
        score: if user_count <= 5 { 90.0 } else { 65.0 },
    });

    // Firewall
    let fw_raw = collect_firewall_status();
    sections.push(analyze_firewall(&fw_raw));

    sections
}

// ============================================================================
// HIPAA compliance checks
// ============================================================================

fn hipaa_sections() -> Vec<ReportSection> {
    let mut sections = gdpr_sections(); // HIPAA shares many controls with GDPR

    // Additional: anti-malware
    let defender_raw = run_cmd("powershell", &[
        "-NoProfile", "-Command",
        "Get-MpComputerStatus | Select-Object -Property AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | Format-List"
    ]);
    let def_lower = defender_raw.to_lowercase();
    let av_on = def_lower.contains("true");
    sections.push(ReportSection {
        title: "Anti-Malware (§ 164.308(a)(5))".to_string(),
        status: if av_on { "PASS" } else { "FAIL" }.to_string(),
        findings: if av_on {
            vec!["Windows Defender anti-malware is active".to_string(), defender_raw.trim().to_string()]
        } else {
            vec!["Anti-malware protection could not be confirmed as active".to_string()]
        },
        recommendations: if av_on {
            vec!["Ensure signature updates are applied within 24 hours of release".to_string()]
        } else {
            vec![
                "Enable real-time anti-malware protection immediately".to_string(),
                "Deploy endpoint detection and response (EDR) solution".to_string(),
            ]
        },
        score: if av_on { 95.0 } else { 20.0 },
    });

    // Screen lock / idle timeout
    let screensaver_raw = run_cmd("powershell", &[
        "-NoProfile", "-Command",
        "Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaverIsSecure,ScreenSaveTimeOut -ErrorAction SilentlyContinue | Format-List"
    ]);
    let ss_lower = screensaver_raw.to_lowercase();
    let lock_ok = ss_lower.contains("screensaverissecure") && ss_lower.contains("1");
    sections.push(ReportSection {
        title: "Workstation Security (§ 164.310(b))".to_string(),
        status: if lock_ok { "PASS" } else { "WARN" }.to_string(),
        findings: if lock_ok {
            vec!["Secure screen saver with password-on-resume is enabled".to_string()]
        } else {
            vec!["Secure screen lock policy could not be confirmed".to_string()]
        },
        recommendations: vec![
            "Enforce automatic screen lock after 15 minutes of inactivity via Group Policy".to_string(),
        ],
        score: if lock_ok { 100.0 } else { 60.0 },
    });

    sections
}

// ============================================================================
// Tauri commands
// ============================================================================

#[tauri::command]
pub async fn generate_soc_report() -> Result<AuditReport, String> {
    let process_data = collect_process_list();
    let firewall_data = collect_firewall_status();
    let network_data = collect_network_connections();
    let service_data = collect_services();

    let sections = vec![
        analyze_processes(&process_data),
        analyze_firewall(&firewall_data),
        analyze_network(&network_data),
        analyze_services(&service_data),
    ];

    Ok(build_report(
        "Security Operations Center Report",
        "SOC Operational Review",
        sections,
    ))
}

#[tauri::command]
pub async fn generate_compliance_audit_report(framework: String) -> Result<AuditReport, String> {
    let fw_upper = framework.to_uppercase();
    let (title, sections) = match fw_upper.as_str() {
        "GDPR" => ("GDPR Compliance Audit Report", gdpr_sections()),
        "HIPAA" => ("HIPAA Compliance Audit Report", hipaa_sections()),
        _ => return Err(format!("Unsupported framework '{}'. Supported: GDPR, HIPAA", framework)),
    };

    Ok(build_report(title, &fw_upper, sections))
}

#[tauri::command]
pub async fn export_report_json(report_id: String) -> Result<String, String> {
    REPORT_STORE
        .read()
        .get(&report_id)
        .map(|r| r.json_content.clone())
        .ok_or_else(|| format!("Report '{}' not found", report_id))
}

#[tauri::command]
pub async fn export_report_html(report_id: String) -> Result<String, String> {
    REPORT_STORE
        .read()
        .get(&report_id)
        .map(|r| r.html_content.clone())
        .ok_or_else(|| format!("Report '{}' not found", report_id))
}
