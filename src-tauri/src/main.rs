// Cyber Security Prime - Main Entry Point
// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(dead_code)]

mod cmd;
mod database;
mod modules;
mod service;
mod utils;

use tauri::{CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem};

fn create_system_tray() -> SystemTray {
    let quit = CustomMenuItem::new("quit".to_string(), "Quit");
    let show = CustomMenuItem::new("show".to_string(), "Show Window");
    let hide = CustomMenuItem::new("hide".to_string(), "Hide Window");
    
    let tray_menu = SystemTrayMenu::new()
        .add_item(show)
        .add_item(hide)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(quit);
    
    SystemTray::new().with_menu(tray_menu)
}

fn main() {
    // Check for --service flag to run as Windows service
    let args: Vec<String> = std::env::args().collect();
    if args.contains(&"--service".to_string()) {
        #[cfg(windows)]
        {
            if let Err(e) = service::windows_service::run_service() {
                eprintln!("Service error: {}", e);
                std::process::exit(1);
            }
            return;
        }
        #[cfg(not(windows))]
        {
            eprintln!("Service mode is only supported on Windows");
            std::process::exit(1);
        }
    }
    
    // Initialize database
    if let Err(e) = database::initialize_database() {
        eprintln!("Warning: Failed to initialize database: {}", e);
        // Continue anyway - app can work without persistence
    }
    
    // Initialize MSP reporting (loads config and starts heartbeat if configured)
    modules::reporting::initialize();
    
    let system_tray = create_system_tray();
    
    tauri::Builder::default()
        .system_tray(system_tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick { .. } => {
                if let Some(window) = app.get_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "quit" => {
                    std::process::exit(0);
                }
                "show" => {
                    if let Some(window) = app.get_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "hide" => {
                    if let Some(window) = app.get_window("main") {
                        let _ = window.hide();
                    }
                }
                _ => {}
            },
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            // Core commands
            cmd::get_system_info,
            cmd::get_security_score,
            cmd::get_module_status,
            cmd::toggle_module,
            cmd::get_recent_activity,
            cmd::get_threat_alerts,
            cmd::get_benchmark_comparison,
            cmd::get_hardening_steps,
            // Real-time monitoring commands
            cmd::start_real_time_monitoring,
            cmd::stop_real_time_monitoring,
            cmd::get_monitoring_status,
            // Scanner commands
            cmd::start_scan,
            cmd::start_custom_scan,
            cmd::get_scan_status,
            cmd::get_scan_results,
            cmd::stop_scan,
            cmd::quarantine_threats,
            // Advanced Scanner commands
            cmd::scan_memory_forensics,
            cmd::analyze_behavioral_patterns,
            cmd::get_yara_rules,
            cmd::add_yara_rule,
            cmd::scan_with_yara,
            cmd::perform_advanced_scan,
            cmd::initialize_yara_rules,
            // Firewall commands
            cmd::get_firewall_status,
            cmd::toggle_firewall,
            cmd::get_firewall_rules,
            cmd::add_firewall_rule,
            cmd::remove_firewall_rule,
            cmd::toggle_firewall_rule,
            // Encryption commands
            cmd::encrypt_file,
            cmd::decrypt_file,
            cmd::get_encrypted_files,
            cmd::remove_encrypted_file,
            // Vulnerability commands
            cmd::scan_vulnerabilities,
            cmd::get_vulnerabilities,
            // Network commands
            cmd::get_network_connections,
            cmd::get_network_stats,
            cmd::get_little_snitch_status,
            cmd::get_little_snitch_rules,
            cmd::get_little_snitch_domain_trust,
            cmd::export_little_snitch_profile,
            // Settings commands
            cmd::get_settings,
            cmd::update_settings,
            // AI Agent commands
            modules::agent::get_agent_status,
            // Compliance commands
            modules::compliance::get_gdpr_compliance_data,
            // Isolation commands
            modules::isolation::get_isolation_profiles,
            // Tamper detection commands
            modules::tamper_detection::get_integrity_checks,
            // Security hardening commands
            modules::security_hardening::get_memory_protection_status,
            modules::security_hardening::get_secure_logging_status,
            modules::security_hardening::get_rate_limiting_status,
            modules::security_hardening::check_rate_limit,
            modules::security_hardening::log_security_event,
            modules::security_hardening::get_security_events,
            modules::security_hardening::get_hardening_metrics,
            modules::security_hardening::report_memory_violation,
            modules::security_hardening::verify_log_integrity,
            modules::security_hardening::get_security_hardening_dashboard,
            modules::tamper_detection::run_integrity_check,
            modules::tamper_detection::get_anomaly_detectors,
            modules::tamper_detection::get_secure_boot_status,
            modules::tamper_detection::get_tamper_alerts,
            modules::tamper_detection::resolve_tamper_alert,
            modules::tamper_detection::capture_system_baseline,
            modules::tamper_detection::get_tamper_events,
            modules::tamper_detection::perform_anomaly_detection,
            modules::tamper_detection::get_tamper_detection_dashboard,
            modules::isolation::create_sandbox,
            modules::isolation::start_sandbox,
            modules::isolation::stop_sandbox,
            modules::isolation::get_sandboxes,
            modules::isolation::create_container,
            modules::isolation::start_container,
            modules::isolation::stop_container,
            modules::isolation::get_containers,
            modules::isolation::get_running_processes,
            modules::isolation::isolate_process,
            modules::isolation::get_isolation_events,
            modules::isolation::get_isolation_dashboard,
            modules::compliance::get_hipaa_compliance_data,
            modules::compliance::get_data_inventory,
            modules::compliance::add_data_asset,
            modules::compliance::get_consent_records,
            modules::compliance::record_consent,
            modules::compliance::withdraw_consent,
            modules::compliance::get_breach_incidents,
            modules::compliance::report_breach_incident,
            modules::compliance::update_breach_status,
            modules::compliance::submit_subject_rights_request,
            modules::compliance::get_subject_rights_requests,
            modules::compliance::generate_compliance_report,
            modules::compliance::get_compliance_dashboard,
            modules::compliance::register_phi_asset,
            modules::compliance::add_business_associate_agreement,
            modules::compliance::escalate_breach,
            modules::agent::configure_agent,
            modules::agent::get_agent_models,
            modules::agent::start_agent_session,
            modules::agent::chat_with_agent,
            modules::agent::chat_with_agent_stream,
            modules::agent::analyze_security,
            modules::agent::get_security_recommendations,
            modules::agent::clear_agent_session,
            modules::agent::get_agent_session,
            modules::agent::scan_directory_for_analysis,
            // Advanced AI Security Analysis commands
            modules::agent::analyze_threat_prediction,
            modules::agent::analyze_behavioral_patterns_ai,
            modules::agent::get_security_intelligence,
            modules::agent::perform_comprehensive_ai_analysis,
            // API Key management commands (Ollama + Mistral direct)
            modules::agent::store_ollama_api_key,
            modules::agent::has_ollama_api_key,
            modules::agent::delete_ollama_api_key,
            modules::agent::store_mistral_api_key,
            modules::agent::has_mistral_api_key,
            modules::agent::delete_mistral_api_key,
            modules::agent::get_ai_provider,
            modules::agent::reset_agent_client,
            // ElevenLabs TTS commands
            modules::agent::store_elevenlabs_api_key,
            modules::agent::has_elevenlabs_api_key,
            modules::agent::delete_elevenlabs_api_key,
            modules::agent::text_to_speech,
            modules::agent::get_elevenlabs_voices,
            // Pixtral Vision commands
            modules::agent::analyze_image_with_pixtral,
            // Investigation Dossier commands
            modules::agent::generate_investigation_dossier,
            modules::agent::narrate_dossier,
            // PRIME Briefing
            modules::agent::generate_prime_briefing,
            // Firewall export/import commands
            modules::firewall::export_firewall_rules,
            modules::firewall::import_firewall_rules,
            // Encryption export/import commands
            modules::encryption::export_encryption_keys,
            modules::encryption::import_encryption_keys,
            // History/Analytics commands
            modules::history::get_threat_history,
            modules::history::get_threat_stats,
            modules::history::add_threat_event,
            modules::history::get_edr_timeline,
            // Plugin commands
            modules::plugins::get_plugins,
            modules::plugins::install_plugin,
            modules::plugins::uninstall_plugin,
            modules::plugins::toggle_plugin,
            modules::plugins::get_plugin_info,
            // VPN commands
            modules::vpn::get_vpn_status,
            modules::vpn::get_vpn_servers,
            modules::vpn::get_ip_info,
            modules::vpn::check_vpn_requirements,
            modules::vpn::connect_vpn,
            modules::vpn::disconnect_vpn,
            modules::vpn::get_vpn_stats,
            modules::vpn::ping_vpn_server,
            modules::vpn::import_wireguard_config,
            modules::vpn::get_wireguard_download_url,
            // Management commands
            modules::management::get_managed_instances,
            modules::management::register_instance,
            modules::management::update_instance_status,
            modules::management::get_users,
            modules::management::create_user,
            modules::management::get_audit_logs,
            modules::management::log_audit_event,
            modules::management::get_security_policies,
            modules::management::create_security_policy,
            modules::management::get_management_alerts,
            modules::management::create_management_alert,
            modules::management::resolve_management_alert,
            modules::management::get_management_dashboard_data,
            // Database commands
            cmd::db_get_recent_scans,
            cmd::db_get_threat_stats,
            cmd::db_get_recent_activity,
            cmd::db_get_setting,
            cmd::db_set_setting,
            // Licensing commands
            cmd::get_license_info,
            cmd::activate_license,
            cmd::deactivate_license,
            cmd::validate_license,
            cmd::get_endpoint_id,
            // Service management commands
            cmd::install_service,
            cmd::uninstall_service,
            cmd::start_service,
            cmd::stop_service,
            cmd::get_service_status,
            cmd::is_service_installed,
            // MSP Reporting commands
            modules::reporting::configure_msp_server,
            modules::reporting::get_msp_status,
            modules::reporting::disconnect_msp_server,
            modules::reporting::send_heartbeat_now,
            modules::reporting::report_security_event,
            // Report generator commands
            modules::report_generator::generate_soc_report,
            modules::report_generator::generate_compliance_audit_report,
            modules::report_generator::export_report_json,
            modules::report_generator::export_report_html,
            // Flagship enhancement commands
            modules::flagship::get_autonomous_response_playbooks,
            modules::flagship::run_autonomous_response_dry_run,
            modules::flagship::execute_playbook,
            modules::flagship::get_playbook_audit_trail,
            modules::flagship::get_attack_surface_snapshot,
            modules::flagship::refresh_attack_surface_snapshot,
            modules::flagship::get_signed_rule_pack_status,
            modules::flagship::verify_rule_pack_signature,
            // Application Control commands
            modules::app_control::verify_application,
            modules::app_control::check_app_signature,
            modules::app_control::get_process_chain,
            modules::app_control::get_app_control_status,
            modules::app_control::add_to_allowlist,
            modules::app_control::add_to_denylist,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Cyber Security Prime");
}

