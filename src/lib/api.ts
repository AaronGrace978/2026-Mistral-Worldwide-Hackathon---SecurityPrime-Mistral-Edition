// Cyber Security Prime - Tauri API Layer
// Type-safe wrappers for all Tauri commands

import { invoke } from '@tauri-apps/api/tauri';

// ============================================================================
// Types
// ============================================================================

export interface SmartHealth {
	overall_health: string; // "good", "caution", "bad"
	temperature?: number;
	power_on_hours?: number;
	reallocated_sectors?: number;
	pending_sectors?: number;
	uncorrectable_errors?: number;
}

export interface DriveInfo {
	name: string;
	mount_point: string;
	total_space_gb: number;
	available_space_gb: number;
	used_space_gb: number;
	health_status: string; // "healthy", "warning", "critical", "unknown"
	file_system: string;
	smart_health?: SmartHealth;
}

export interface HardwareSensors {
	cpu_temperature?: number;
	gpu_temperature?: number;
	motherboard_temperature?: number;
	fan_speeds: FanSpeed[];
}

export interface FanSpeed {
	name: string;
	speed_rpm: number;
}

export interface NetworkStats {
	interface_name: string;
	bytes_sent: number;
	bytes_received: number;
	packets_sent: number;
	packets_received: number;
	errors_in: number;
	errors_out: number;
}

export interface SystemLoad {
	cpu_usage_percent: number;
	memory_usage_percent: number;
	disk_io_percent: number;
}

export interface AdvancedSystemInfo {
	sensors: HardwareSensors;
	network_interfaces: NetworkStats[];
	system_load: SystemLoad;
}

export interface SystemInfo {
	os_name: string;
	os_version: string;
	hostname: string;
	cpu_cores: number;
	total_memory_gb: number;
	available_memory_gb: number;
	used_memory_gb: number;
	drives: DriveInfo[];
	advanced: AdvancedSystemInfo;
}

export interface SecurityBreakdown {
	firewall: number;
	antivirus: number;
	encryption: number;
	updates: number;
	vulnerabilities: number;
}

export interface SecurityScore {
	score: number;
	grade: string;
	breakdown: SecurityBreakdown;
}

export type ModuleStatusType = 'active' | 'inactive' | 'warning' | 'error' | 'scanning';

export interface ModuleStatus {
	name: string;
	status: ModuleStatusType;
	enabled: boolean;
	description: string;
	last_activity: string | null;
}

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type ActivityType = 
	| 'scan_started'
	| 'scan_completed'
	| 'threat_detected'
	| 'threat_quarantined'
	| 'firewall_blocked'
	| 'file_encrypted'
	| 'file_decrypted'
	| 'vulnerability_found'
	| 'system_update'
	| 'settings_changed'
	| 'module_enabled'
	| 'module_disabled';

export interface ActivityEvent {
	id: string;
	event_type: ActivityType;
	title: string;
	description: string;
	severity: Severity;
	timestamp: string;
	module: string;
}

export interface ThreatAlert {
	id: string;
	title: string;
	description: string;
	severity: Severity;
	source: string;
	timestamp: string;
	resolved: boolean;
}

// Scanner types
export interface ScanSession {
	id: string;
	scan_type: string;
	status: string;
	started_at: string;
	total_files: number;
	scanned_files: number;
	threats_found: number;
}

export interface ScanStatus {
	id: string;
	status: string;
	progress: number;
	current_file: string | null;
	scanned_files: number;
	threats_found: number;
	estimated_time_remaining: string | null;
}

export interface ThreatInfo {
	id: string;
	name: string;
	threat_type: string;
	severity: Severity;
	file_path: string;
	detected_at: string;
	status: string;
	description: string;
}

export interface ScanResults {
	id: string;
	scan_type: string;
	status: string;
	started_at: string;
	completed_at: string | null;
	total_files: number;
	scanned_files: number;
	threats: ThreatInfo[];
	duration_seconds: number;
}

// ============================================================================
// Advanced Scanning Types
// ============================================================================

export type ScanType = 'basic' | 'memory' | 'behavioral' | 'yara' | 'comprehensive';

export interface MemoryScanResult {
	process_id: number;
	process_name: string;
	memory_regions: MemoryRegion[];
	detected_signatures: MemorySignature[];
	suspicious_patterns: string[];
	scan_duration_ms: number;
}

export interface MemoryRegion {
	base_address: number;
	size: number;
	protection: string;
	allocation_type: string;
	suspicious: boolean;
	entropy: number;
}

export interface MemorySignature {
	signature_id: string;
	name: string;
	offset: number;
	pattern: string;
	severity: Severity;
	description: string;
}

export interface BehavioralAnalysis {
	process_id: number;
	process_name: string;
	behavior_score: number;
	anomalies: BehavioralAnomaly[];
	risk_level: string;
	recommendations: string[];
}

export interface BehavioralAnomaly {
	anomaly_type: string;
	severity: Severity;
	description: string;
	confidence: number;
	timestamp: string;
}

export interface YaraRule {
	id: string;
	name: string;
	namespace: string;
	condition: string;
	strings: YaraString[];
	metadata: Record<string, string>;
	enabled: boolean;
}

export interface YaraString {
	identifier: string;
	pattern: string;
	modifiers: string[];
}

export interface YaraScanResult {
	rule_id: string;
	rule_name: string;
	matches: YaraMatch[];
	severity: Severity;
}

export interface YaraMatch {
	file_path: string;
	offset: number;
	string_identifier: string;
	string_data: string;
}

export interface AdvancedScanResults {
	basic_results?: ScanResults;
	memory_results?: MemoryScanResult[];
	behavioral_results?: BehavioralAnalysis[];
	yara_results?: YaraScanResult[];
	comprehensive_score: number;
	overall_risk_assessment: string;
}

// Firewall types
export interface BlockedConnection {
	ip: string;
	port: number;
	protocol: string;
	direction: string;
	reason: string;
	timestamp: string;
}

export interface FirewallStatus {
	enabled: boolean;
	profile: string;
	inbound_blocked: number;
	outbound_blocked: number;
	active_rules: number;
	last_blocked: BlockedConnection | null;
}

export interface FirewallRule {
	id: string;
	name: string;
	enabled: boolean;
	direction: string;
	action: string;
	protocol: string;
	local_port: string | null;
	remote_port: string | null;
	remote_address: string | null;
	application: string | null;
	description: string;
	created_at: string;
}

// Encryption types
export interface EncryptionResult {
	success: boolean;
	file_path: string;
	encrypted_path: string;
	original_size: number;
	encrypted_size: number;
	algorithm: string;
	encrypted_at: string;
}

export interface DecryptionResult {
	success: boolean;
	encrypted_path: string;
	decrypted_path: string;
	decrypted_at: string;
}

export interface EncryptedFile {
	id: string;
	original_name: string;
	encrypted_path: string;
	original_size: number;
	encrypted_size: number;
	algorithm: string;
	encrypted_at: string;
	last_accessed: string | null;
}

// Vulnerability types
export interface VulnerabilityScan {
	id: string;
	status: string;
	started_at: string;
	completed_at: string | null;
	vulnerabilities_found: number;
	items_scanned: number;
}

export interface Vulnerability {
	id: string;
	cve_id: string | null;
	title: string;
	description: string;
	severity: Severity;
	affected_software: string;
	current_version: string;
	fixed_version: string | null;
	detected_at: string;
	status: string;
	remediation: string;
}

// Network types
export interface NetworkConnection {
	id: string;
	process_name: string;
	process_id: number;
	local_address: string;
	local_port: number;
	remote_address: string;
	remote_port: number;
	protocol: string;
	state: string;
	bytes_sent: number;
	bytes_received: number;
	established_at: string;
}

export interface NetworkStats {
	total_connections: number;
	active_connections: number;
	bytes_sent_total: number;
	bytes_received_total: number;
	bytes_sent_per_sec: number;
	bytes_received_per_sec: number;
	blocked_connections: number;
	suspicious_connections: number;
}

export interface LittleSnitchStatus {
	supported: boolean;
	installed: boolean;
	app_path: string | null;
	docs_url: string;
	status_message: string;
}

export interface LittleSnitchRule {
	id: string;
	action: string;
	direction: string;
	process: string;
	remote_host: string;
	ports: string;
	protocol: string;
	notes: string;
	category: string;
	priority: string;
}

export interface DomainTrustEntry {
	domain: string;
	trust_level: string;
	category: string;
	first_seen: string;
	connection_count: number;
	notes: string;
}

export interface LittleSnitchRuleProfile {
	name: string;
	description: string;
	created_at: string;
	rules_json: string;
	rule_count: number;
}

// Settings types
export interface ModulesEnabled {
	scanner: boolean;
	firewall: boolean;
	encryption: boolean;
	vulnerability: boolean;
	network: boolean;
	agent: boolean;
}

export interface AppSettings {
	theme: string;
	auto_start: boolean;
	real_time_protection: boolean;
	auto_update: boolean;
	notifications_enabled: boolean;
	scan_on_startup: boolean;
	modules_enabled: ModulesEnabled;
}

// ============================================================================
// API Functions
// ============================================================================

/**
 * Check if running in Tauri environment
 */
function isTauri(): boolean {
	return typeof window !== 'undefined' && '__TAURI__' in window;
}

/**
 * Check if in development mode (for mock data fallback)
 * Set VITE_USE_MOCK_DATA=true in .env to enable mock data
 */
function useMockData(): boolean {
	// @ts-ignore - VITE env variable
	const useMock = import.meta.env?.VITE_USE_MOCK_DATA === 'true';
	return !isTauri() && useMock;
}

/**
 * Wrapper for invoke that calls real Tauri backend
 * Falls back to mock data ONLY in development when not in Tauri AND VITE_USE_MOCK_DATA=true
 */
async function safeInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
	if (isTauri()) {
		try {
			return await invoke<T>(command, args);
		} catch (error) {
			console.error(`[API] Command '${command}' failed:`, error);
			throw error;
		}
	}
	
	// Only use mock data in development mode with explicit flag
	if (useMockData()) {
		console.warn(`[API] Development mode: using mock data for: ${command}`);
		const mockResult = getMockData(command, args);
		if (mockResult !== null) {
			return mockResult as T;
		}
	}
	
	// In production without Tauri, throw an error
	throw new Error(`Tauri backend not available. Command: ${command}`);
}

// ============================================================================
// Core API
// ============================================================================

export async function getSystemInfo(): Promise<SystemInfo> {
	return safeInvoke<SystemInfo>('get_system_info');
}

export async function getSecurityScore(): Promise<SecurityScore> {
	return safeInvoke<SecurityScore>('get_security_score');
}

export async function getModuleStatus(): Promise<ModuleStatus[]> {
	return safeInvoke<ModuleStatus[]>('get_module_status');
}

export async function toggleModule(moduleName: string, enabled: boolean): Promise<boolean> {
	return safeInvoke<boolean>('toggle_module', { moduleName, enabled });
}

export async function getRecentActivity(limit?: number): Promise<ActivityEvent[]> {
	return safeInvoke<ActivityEvent[]>('get_recent_activity', { limit });
}

// ============================================================================
// Real-Time Monitoring
// ============================================================================

export interface SecurityEvent {
	id: string;
	event_type: string;
	title: string;
	description: string;
	severity: string;
	timestamp: string;
	data: any;
}

export interface MonitoringStatus {
	is_active: boolean;
	last_check: string;
	total_events: number;
	alerts_today: number;
}

export async function startRealTimeMonitoring(): Promise<boolean> {
	return safeInvoke<boolean>('start_real_time_monitoring');
}

export async function stopRealTimeMonitoring(): Promise<boolean> {
	return safeInvoke<boolean>('stop_real_time_monitoring');
}

export async function getMonitoringStatus(): Promise<MonitoringStatus> {
	return safeInvoke<MonitoringStatus>('get_monitoring_status');
}

export async function getThreatAlerts(): Promise<ThreatAlert[]> {
	return safeInvoke<ThreatAlert[]>('get_threat_alerts');
}

// ============================================================================
// Scanner API
// ============================================================================

export async function startScan(scanType: string): Promise<ScanSession> {
	return safeInvoke<ScanSession>('start_scan', { scanType });
}

export async function getScanStatus(scanId: string): Promise<ScanStatus> {
	return safeInvoke<ScanStatus>('get_scan_status', { scanId });
}

export async function getScanResults(scanId: string): Promise<ScanResults> {
	return safeInvoke<ScanResults>('get_scan_results', { scanId });
}

export async function stopScan(scanId: string): Promise<boolean> {
	return safeInvoke<boolean>('stop_scan', { scanId });
}

export async function quarantineThreats(threatIds: string[]): Promise<number> {
	return safeInvoke<number>('quarantine_threats', { threatIds });
}

// ============================================================================
// Firewall API
// ============================================================================

export async function getFirewallStatus(): Promise<FirewallStatus> {
	return safeInvoke<FirewallStatus>('get_firewall_status');
}

export async function toggleFirewall(enabled: boolean): Promise<boolean> {
	return safeInvoke<boolean>('toggle_firewall', { enabled });
}

export async function getFirewallRules(): Promise<FirewallRule[]> {
	return safeInvoke<FirewallRule[]>('get_firewall_rules');
}

export async function addFirewallRule(rule: Omit<FirewallRule, 'id' | 'created_at'>): Promise<FirewallRule> {
	return safeInvoke<FirewallRule>('add_firewall_rule', { rule });
}

export async function removeFirewallRule(ruleId: string): Promise<boolean> {
	return safeInvoke<boolean>('remove_firewall_rule', { ruleId });
}

// ============================================================================
// Encryption API
// ============================================================================

export async function encryptFile(filePath: string, password: string): Promise<EncryptionResult> {
	return safeInvoke<EncryptionResult>('encrypt_file', { filePath, password });
}

export async function decryptFile(filePath: string, password: string): Promise<DecryptionResult> {
	return safeInvoke<DecryptionResult>('decrypt_file', { filePath, password });
}

export async function getEncryptedFiles(): Promise<EncryptedFile[]> {
	return safeInvoke<EncryptedFile[]>('get_encrypted_files');
}

export async function removeEncryptedFile(fileId: string, deleteFile: boolean): Promise<void> {
	return safeInvoke<void>('remove_encrypted_file', { fileId, deleteFile });
}

// ============================================================================
// Vulnerability API
// ============================================================================

export async function scanVulnerabilities(): Promise<VulnerabilityScan> {
	return safeInvoke<VulnerabilityScan>('scan_vulnerabilities');
}

export async function getVulnerabilities(): Promise<Vulnerability[]> {
	return safeInvoke<Vulnerability[]>('get_vulnerabilities');
}

// ============================================================================
// Network API
// ============================================================================

export async function getNetworkConnections(): Promise<NetworkConnection[]> {
	return safeInvoke<NetworkConnection[]>('get_network_connections');
}

export async function getNetworkStats(): Promise<NetworkStats> {
	return safeInvoke<NetworkStats>('get_network_stats');
}

export async function getLittleSnitchStatus(): Promise<LittleSnitchStatus> {
	return safeInvoke<LittleSnitchStatus>('get_little_snitch_status');
}

export async function getLittleSnitchRules(): Promise<LittleSnitchRule[]> {
	return safeInvoke<LittleSnitchRule[]>('get_little_snitch_rules');
}

export async function getLittleSnitchDomainTrust(): Promise<DomainTrustEntry[]> {
	return safeInvoke<DomainTrustEntry[]>('get_little_snitch_domain_trust');
}

export async function exportLittleSnitchProfile(): Promise<LittleSnitchRuleProfile> {
	return safeInvoke<LittleSnitchRuleProfile>('export_little_snitch_profile');
}

// ============================================================================
// Settings API
// ============================================================================

export async function getSettings(): Promise<AppSettings> {
	return safeInvoke<AppSettings>('get_settings');
}

export async function updateSettings(settings: AppSettings): Promise<AppSettings> {
	return safeInvoke<AppSettings>('update_settings', { settings });
}

// ============================================================================
// Firewall Export/Import API
// ============================================================================

export interface FirewallExport {
	version: string;
	exported_at: string;
	rules: FirewallRule[];
	checksum: string;
}

export interface ImportResult {
	success: boolean;
	imported: number;
	skipped: number;
	total: number;
	message: string;
}

export async function exportFirewallRules(filePath: string): Promise<FirewallExport> {
	return safeInvoke<FirewallExport>('export_firewall_rules', { filePath });
}

export async function importFirewallRules(filePath: string, merge: boolean): Promise<ImportResult> {
	return safeInvoke<ImportResult>('import_firewall_rules', { filePath, merge });
}

// ============================================================================
// Encryption Key Export/Import API
// ============================================================================

export interface KeyExport {
	version: string;
	exported_at: string;
	key_id: string;
	encrypted_key: string;
	algorithm: string;
	salt: string;
	iterations: number;
}

export interface KeyImportResult {
	success: boolean;
	key_id: string;
	message: string;
}

export async function exportEncryptionKeys(filePath: string, exportPassword: string): Promise<KeyExport> {
	return safeInvoke<KeyExport>('export_encryption_keys', { filePath, exportPassword });
}

export async function importEncryptionKeys(filePath: string, importPassword: string): Promise<KeyImportResult> {
	return safeInvoke<KeyImportResult>('import_encryption_keys', { filePath, importPassword });
}

// ============================================================================
// Threat History & Analytics API
// ============================================================================

export type ThreatType = 
	| 'malware'
	| 'ransomware'
	| 'phishing'
	| 'network_intrusion'
	| 'data_breach'
	| 'vulnerability'
	| 'suspicious_activity'
	| 'blocked_connection'
	| 'unauthorized_access'
	| 'other';

export interface ThreatEvent {
	id: string;
	threat_type: ThreatType;
	severity: Severity;
	source: string;
	description: string;
	timestamp: string;
	resolved: boolean;
	resolved_at: string | null;
	action_taken: string | null;
}

export interface HistoryQuery {
	days?: number;
	severity?: string;
	threat_type?: string;
	resolved?: boolean;
	limit?: number;
}

export interface ThreatStats {
	total_threats: number;
	threats_today: number;
	threats_this_week: number;
	threats_this_month: number;
	resolved_threats: number;
	unresolved_threats: number;
	by_severity: SeverityBreakdown;
	by_type: ThreatTypeCount[];
	daily_counts: DailyCount[];
	hourly_distribution: HourlyCount[];
	trend: ThreatTrend;
}

export interface SeverityBreakdown {
	low: number;
	medium: number;
	high: number;
	critical: number;
}

export interface ThreatTypeCount {
	threat_type: string;
	count: number;
	percentage: number;
}

export interface DailyCount {
	date: string;
	count: number;
	blocked: number;
	resolved: number;
}

export interface HourlyCount {
	hour: number;
	count: number;
}

export interface ThreatTrend {
	direction: string;
	percentage_change: number;
	comparison_period: string;
}

export async function getThreatHistory(query?: HistoryQuery): Promise<ThreatEvent[]> {
	return safeInvoke<ThreatEvent[]>('get_threat_history', { query });
}

export async function getThreatStats(): Promise<ThreatStats> {
	return safeInvoke<ThreatStats>('get_threat_stats');
}

export async function addThreatEvent(
	threatType: string,
	severity: string,
	source: string,
	description: string
): Promise<ThreatEvent> {
	return safeInvoke<ThreatEvent>('add_threat_event', { threatType, severity, source, description });
}

// ============================================================================
// Plugin System API
// ============================================================================

export type PluginCategory = 
	| 'scanner'
	| 'firewall'
	| 'encryption'
	| 'network_monitor'
	| 'vulnerability_scanner'
	| 'threat_intelligence'
	| 'data_protection'
	| 'authentication'
	| 'reporting'
	| 'integration'
	| 'other';

export type PluginPermission =
	| 'file_system_read'
	| 'file_system_write'
	| 'network_access'
	| 'system_info'
	| 'process_list'
	| 'registry_access'
	| 'admin_privileges'
	| 'notification_send'
	| 'settings_modify';

export type PluginStatus = 'active' | 'inactive' | 'error' | 'updating' | 'installing';

export interface Plugin {
	id: string;
	name: string;
	version: string;
	description: string;
	author: string;
	homepage: string | null;
	category: PluginCategory;
	enabled: boolean;
	installed_at: string;
	updated_at: string | null;
	permissions: PluginPermission[];
	config: Record<string, unknown>;
	status: PluginStatus;
}

export interface PluginManifest {
	name: string;
	version: string;
	description: string;
	author: string;
	homepage: string | null;
	category: PluginCategory;
	permissions: PluginPermission[];
	min_app_version: string;
	entry_point: string;
	config_schema: unknown | null;
}

export interface PluginInfo {
	plugin: Plugin;
	manifest: PluginManifest;
	health: {
		healthy: boolean;
		message: string;
		last_check: string;
		uptime_seconds: number;
	};
	stats: {
		invocations: number;
		errors: number;
		avg_response_ms: number;
		last_invoked: string | null;
	};
}

export async function getPlugins(): Promise<Plugin[]> {
	return safeInvoke<Plugin[]>('get_plugins');
}

export async function installPlugin(manifest: PluginManifest): Promise<Plugin> {
	return safeInvoke<Plugin>('install_plugin', { manifest });
}

export async function uninstallPlugin(pluginId: string): Promise<boolean> {
	return safeInvoke<boolean>('uninstall_plugin', { pluginId });
}

export async function togglePlugin(pluginId: string, enabled: boolean): Promise<Plugin> {
	return safeInvoke<Plugin>('toggle_plugin', { pluginId, enabled });
}

export async function getPluginInfo(pluginId: string): Promise<PluginInfo> {
	return safeInvoke<PluginInfo>('get_plugin_info', { pluginId });
}

// ============================================================================
// AI Agent API
// ============================================================================

export interface AgentStatus {
	connected: boolean;
	available_models: ModelInfo[];
	current_model: string;
	session_active: boolean;
}

export interface ModelInfo {
	name: string;
	size?: number;
	modified_at?: string;
	digest?: string;
}

export interface OllamaConfig {
	base_url: string;
	api_key?: string;
	default_model: string;
	fast_model: string;
	deep_model: string;
	timeout_secs: number;
}

export interface AgentSession {
	id: string;
	created_at: string;
	messages: ChatMessage[];
	model: string;
	context: AgentContext;
}

export interface ChatMessage {
	role: string;
	content: string;
}

export interface AgentContext {
	security_score?: number;
	active_threats: string[];
	recent_scans: string[];
	system_info?: string;
}

export interface StreamChunk {
	content: string;
	done: boolean;
	model: string;
}

export async function getAgentStatus(): Promise<AgentStatus> {
	return safeInvoke<AgentStatus>('get_agent_status');
}

export async function configureAgent(config: OllamaConfig): Promise<AgentStatus> {
	return safeInvoke<AgentStatus>('configure_agent', { config });
}

export async function getAgentModels(): Promise<ModelInfo[]> {
	return safeInvoke<ModelInfo[]>('get_agent_models');
}

export async function startAgentSession(model?: string): Promise<AgentSession> {
	return safeInvoke<AgentSession>('start_agent_session', { model });
}

export async function chatWithAgent(message: string, model?: string): Promise<string> {
	return safeInvoke<string>('chat_with_agent', { message, model });
}

export async function chatWithAgentStream(message: string, model?: string): Promise<string> {
	return safeInvoke<string>('chat_with_agent_stream', { message, model });
}

export async function getAgentSession(): Promise<AgentSession | null> {
	return safeInvoke<AgentSession | null>('get_agent_session');
}

export async function clearAgentSession(): Promise<void> {
	return safeInvoke<void>('clear_agent_session');
}

// ============================================================================
// Directory Scanning API
// ============================================================================

export interface DirectoryScanResult {
	path: string;
	total_files: number;
	total_dirs: number;
	total_size_bytes: number;
	file_types: Record<string, number>;
	largest_files: FileInfo[];
	suspicious_files: SuspiciousFile[];
	health_issues: HealthIssue[];
	summary: string;
}

export interface FileInfo {
	path: string;
	size_bytes: number;
	file_type: string;
	modified: string | null;
}

export interface SuspiciousFile {
	path: string;
	reason: string;
	severity: string;
}

export interface HealthIssue {
	category: string;
	severity: string;
	description: string;
	recommendation: string;
}

export async function scanDirectoryForAnalysis(path: string): Promise<DirectoryScanResult> {
	return safeInvoke<DirectoryScanResult>('scan_directory_for_analysis', { path });
}

// ============================================================================
// Advanced AI Security Analysis
// ============================================================================

export interface ThreatPrediction {
	threat_level: string;
	confidence: number;
	predicted_threats: string[];
	risk_factors: string[];
	recommendations: string[];
	time_window: string;
}

export interface BehavioralPattern {
	pattern_type: string;
	description: string;
	frequency: string;
	risk_level: string;
	observed_behaviors: string[];
	analysis: string;
}

export interface SecurityIntelligence {
	threat_indicators: string[];
	emerging_threats: string[];
	recommended_actions: string[];
	intelligence_sources: string[];
	last_updated: string;
}

export interface AIAnalysisResult {
	threat_prediction: ThreatPrediction;
	behavioral_analysis: BehavioralPattern[];
	security_intelligence: SecurityIntelligence;
	overall_risk_assessment: string;
	priority_actions: string[];
}

export async function analyzeThreatPrediction(
	systemInfo: string,
	recentEvents: string[],
	networkActivity: string
): Promise<ThreatPrediction> {
	return safeInvoke<ThreatPrediction>('analyze_threat_prediction', {
		systemInfo,
		recentEvents,
		networkActivity
	});
}


export async function getSecurityIntelligence(): Promise<SecurityIntelligence> {
	return safeInvoke<SecurityIntelligence>('get_security_intelligence');
}

export async function performComprehensiveAIAnalysis(
	systemInfo: string,
	recentEvents: string[],
	networkActivity: string,
	processList: string[],
	networkConnections: string[],
	fileAccessPatterns: string[]
): Promise<AIAnalysisResult> {
	return safeInvoke<AIAnalysisResult>('perform_comprehensive_ai_analysis', {
		systemInfo,
		recentEvents,
		networkActivity,
		processList,
		networkConnections,
		fileAccessPatterns
	});
}

// ============================================================================
// Advanced Scanning & Threat Detection
// ============================================================================

export interface MemoryForensicResult {
	process_id: number;
	process_name: string;
	suspicious_regions: MemoryRegion[];
	total_regions: number;
	scanned_regions: number;
}

export interface MemoryRegion {
	start_address: string;
	size: number;
	permissions: string;
	suspicious_patterns: string[];
	risk_level: string;
}

export interface BehavioralAnalysisResult {
	process_id: number;
	process_name: string;
	behavior_score: number;
	anomalous_behaviors: string[];
	risk_assessment: string;
	recommendations: string[];
}

export interface YaraRule {
	rule_name: string;
	description: string;
	condition: string;
	strings: string[];
	tags: string[];
	enabled: boolean;
}

export interface YaraScanResult {
	file_path: string;
	matched_rules: string[];
	total_matches: number;
	scan_duration: number;
}

export interface AdvancedScanResult {
	memory_forensics: MemoryForensicResult[];
	behavioral_analysis: BehavioralAnalysisResult[];
	yara_matches: YaraScanResult[];
	overall_threat_level: string;
	scan_duration: number;
}

export async function scanMemoryForensics(): Promise<MemoryForensicResult[]> {
	return safeInvoke<MemoryForensicResult[]>('scan_memory_forensics');
}

export async function analyzeBehavioralPatterns(
	processList: string[],
	networkConnections: string[],
	fileAccessPatterns: string[]
): Promise<BehavioralAnalysisResult[]> {
	return safeInvoke<BehavioralAnalysisResult[]>('analyze_behavioral_patterns', {
		processList,
		networkConnections,
		fileAccessPatterns
	});
}

export async function getYaraRules(): Promise<YaraRule[]> {
	return safeInvoke<YaraRule[]>('get_yara_rules');
}

export async function addYaraRule(rule: Omit<YaraRule, 'enabled'>): Promise<void> {
	return safeInvoke<void>('add_yara_rule', { rule });
}

export async function scanWithYara(filePaths: string[]): Promise<YaraScanResult[]> {
	return safeInvoke<YaraScanResult[]>('scan_with_yara', { filePaths });
}

export async function performAdvancedScan(targetPaths: string[]): Promise<AdvancedScanResult> {
	return safeInvoke<AdvancedScanResult>('perform_advanced_scan', { targetPaths });
}

export async function initializeYaraRules(): Promise<void> {
	return safeInvoke<void>('initialize_yara_rules');
}

// ============================================================================
// Compliance Management
// ============================================================================

export interface GdprComplianceData {
	data_processing_register: DataProcessingActivity[];
	subject_rights_requests: SubjectRightsRequest[];
	data_protection_officer?: DataProtectionOfficer;
	privacy_policy_version: string;
	compliance_score: number;
	last_audit_date: string;
}

export interface DataProcessingActivity {
	activity_id: string;
	purpose: string;
	categories_of_data: string[];
	legal_basis: string;
	recipients: string[];
	retention_period: string;
}

export interface SubjectRightsRequest {
	request_id: string;
	subject_id: string;
	request_type: 'access' | 'rectification' | 'erasure' | 'restriction' | 'portability' | 'objection';
	status: 'pending' | 'processing' | 'completed' | 'rejected';
	requested_at: string;
	completed_at?: string;
}

export interface DataProtectionOfficer {
	name: string;
	email: string;
	phone?: string;
	designated_date: string;
}

export async function getGdprComplianceData(): Promise<GdprComplianceData> {
	return safeInvoke<GdprComplianceData>('get_gdpr_compliance_data');
}

// ============================================================================
// Process Isolation
// ============================================================================

export interface IsolationProfile {
	profile_id: string;
	name: string;
	description: string;
	isolation_level: 'basic' | 'standard' | 'strict' | 'maximum';
	resource_limits: ResourceLimits;
	network_access: NetworkAccess;
	allowed_paths: string[];
	blocked_paths: string[];
	enabled: boolean;
}

export interface ResourceLimits {
	max_cpu_percent: number;
	max_memory_mb: number;
	max_disk_io: number;
	max_network_bandwidth: number;
}

export interface NetworkAccess {
	allow_internet: boolean;
	allow_local_network: boolean;
	allowed_ports: number[];
	blocked_ports: number[];
	allowed_domains: string[];
}

export async function getIsolationProfiles(): Promise<IsolationProfile[]> {
	return safeInvoke<IsolationProfile[]>('get_isolation_profiles');
}

// ============================================================================
// Tamper Detection & Integrity
// ============================================================================

export interface IntegrityCheck {
	id: string;
	name: string;
	target_path: string;
	check_type: 'FileHash' | 'DirectoryHash' | 'RegistryKey' | 'SystemFile' | 'CriticalProcess';
	expected_hash: string;
	last_check: string;
	status: 'Valid' | 'Modified' | 'Missing' | 'AccessDenied' | 'Unknown';
	check_interval: number;
	enabled: boolean;
}

export interface TamperAlert {
	alert_id: string;
	title: string;
	description: string;
	severity: 'low' | 'medium' | 'high' | 'critical';
	target_path: string;
	detected_at: string;
	status: 'active' | 'resolved' | 'dismissed';
}

export interface SecureBootStatus {
	enabled: boolean;
	secure_boot_supported: boolean;
	last_check: string;
	status_message: string;
}

export interface TamperDashboard {
	integrity_checks_total: number;
	integrity_checks_passing: number;
	anomaly_detectors_active: number;
	anomaly_detectors_alerting: number;
	tamper_alerts_total: number;
	tamper_alerts_unresolved: number;
	secure_boot_enabled: boolean;
	system_baseline_valid: boolean;
	recent_events: number;
}

export async function getIntegrityChecks(): Promise<IntegrityCheck[]> {
	return safeInvoke<IntegrityCheck[]>('get_integrity_checks');
}

export async function runIntegrityCheck(): Promise<IntegrityCheck[]> {
	return safeInvoke<IntegrityCheck[]>('run_integrity_check');
}

export async function getTamperAlerts(): Promise<TamperAlert[]> {
	return safeInvoke<TamperAlert[]>('get_tamper_alerts');
}

export async function resolveTamperAlert(alertId: string): Promise<void> {
	return safeInvoke<void>('resolve_tamper_alert', { alertId });
}

export async function captureSystemBaseline(): Promise<void> {
	return safeInvoke<void>('capture_system_baseline');
}

export async function getSecureBootStatus(): Promise<SecureBootStatus> {
	return safeInvoke<SecureBootStatus>('get_secure_boot_status');
}

// ============================================================================
// Security Hardening
// ============================================================================

export interface MemoryProtectionStatus {
	enabled: boolean;
	dep_enabled: boolean;
	aslr_enabled: boolean;
	cfg_enabled: boolean;
	last_check: string;
}

export interface SecureLoggingStatus {
	enabled: boolean;
	log_encryption: boolean;
	tamper_proof: boolean;
	integrity_checks: boolean;
	last_validation: string;
}

export interface RateLimitingStatus {
	enabled: boolean;
	max_requests_per_minute: number;
	current_requests: number;
	blocked_requests: number;
	last_reset: string;
}

export interface SecurityEvent {
	event_id: string;
	event_type: string;
	message: string;
	severity: 'low' | 'medium' | 'high' | 'critical';
	timestamp: string;
	source: string;
}

export interface HardeningMetrics {
	memory_violations: number;
	log_integrity_failures: number;
	rate_limit_exceeded: number;
	security_events_today: number;
	uptime_hours: number;
	hardening_score: number;
}

export async function getMemoryProtectionStatus(): Promise<MemoryProtectionStatus> {
	return safeInvoke<MemoryProtectionStatus>('get_memory_protection_status');
}

export async function getSecureLoggingStatus(): Promise<SecureLoggingStatus> {
	return safeInvoke<SecureLoggingStatus>('get_secure_logging_status');
}

export async function getRateLimitingStatus(): Promise<RateLimitingStatus> {
	return safeInvoke<RateLimitingStatus>('get_rate_limiting_status');
}

export async function checkRateLimit(action: string): Promise<boolean> {
	return safeInvoke<boolean>('check_rate_limit', { action });
}

export async function logSecurityEvent(eventType: string, message: string, severity: string): Promise<void> {
	return safeInvoke<void>('log_security_event', { eventType, message, severity });
}

export async function getSecurityEvents(): Promise<SecurityEvent[]> {
	return safeInvoke<SecurityEvent[]>('get_security_events');
}

export async function getHardeningMetrics(): Promise<HardeningMetrics> {
	return safeInvoke<HardeningMetrics>('get_hardening_metrics');
}

export async function reportMemoryViolation(violation: string): Promise<void> {
	return safeInvoke<void>('report_memory_violation', { violation });
}

export async function verifyLogIntegrity(): Promise<boolean> {
	return safeInvoke<boolean>('verify_log_integrity');
}

export async function getSecurityHardeningDashboard(): Promise<HardeningMetrics> {
	return safeInvoke<HardeningMetrics>('get_security_hardening_dashboard');
}

// ============================================================================
// Flagship Enhancements API
// ============================================================================

export interface AutonomousResponsePlaybook {
	id: string;
	name: string;
	description: string;
	enabled: boolean;
	trigger_score: number;
	severity_threshold: string;
	actions: string[];
	last_executed: string | null;
}

export interface PlaybookDryRunResult {
	playbook_id: string;
	target: string;
	actions_preview: string[];
	estimated_impact: string;
	recommendation: string;
}

export interface ExposureItem {
	id: string;
	category: string;
	asset: string;
	severity: Severity | string;
	status: string;
	recommended_action: string;
}

export interface AttackSurfaceSnapshot {
	overall_exposure_score: number;
	open_exposures: number;
	critical_exposures: number;
	last_updated: string;
	items: ExposureItem[];
}

export interface RulePack {
	id: string;
	name: string;
	version: string;
	publisher: string;
	signature_status: string;
	last_verified: string;
	installed: boolean;
}

export interface SignedRulePackStatus {
	enforcement_enabled: boolean;
	last_sync: string;
	packs: RulePack[];
}

export interface RulePackVerificationResult {
	pack_id: string;
	verified: boolean;
	signer: string;
	details: string;
}

export async function getAutonomousResponsePlaybooks(): Promise<AutonomousResponsePlaybook[]> {
	return safeInvoke<AutonomousResponsePlaybook[]>('get_autonomous_response_playbooks');
}

export async function runAutonomousResponseDryRun(
	playbookId: string,
	target: string
): Promise<PlaybookDryRunResult> {
	return safeInvoke<PlaybookDryRunResult>('run_autonomous_response_dry_run', {
		playbookId,
		target
	});
}

export async function getAttackSurfaceSnapshot(): Promise<AttackSurfaceSnapshot> {
	return safeInvoke<AttackSurfaceSnapshot>('get_attack_surface_snapshot');
}

export async function refreshAttackSurfaceSnapshot(): Promise<AttackSurfaceSnapshot> {
	return safeInvoke<AttackSurfaceSnapshot>('refresh_attack_surface_snapshot');
}

export async function getSignedRulePackStatus(): Promise<SignedRulePackStatus> {
	return safeInvoke<SignedRulePackStatus>('get_signed_rule_pack_status');
}

export async function verifyRulePackSignature(packId: string): Promise<RulePackVerificationResult> {
	return safeInvoke<RulePackVerificationResult>('verify_rule_pack_signature', { packId });
}

// ============================================================================
// Secure API Key Management
// ============================================================================

/**
 * Store Ollama API key securely in OS keychain
 */
export async function storeOllamaApiKey(apiKey: string): Promise<void> {
	return safeInvoke<void>('store_ollama_api_key', { apiKey });
}

/**
 * Check if Ollama API key exists in secure storage
 */
export async function hasOllamaApiKey(): Promise<boolean> {
	return safeInvoke<boolean>('has_ollama_api_key');
}

/**
 * Delete Ollama API key from secure storage
 */
export async function deleteOllamaApiKey(): Promise<void> {
	return safeInvoke<void>('delete_ollama_api_key');
}

/**
 * Store Mistral API key securely in OS keychain (for direct api.mistral.ai access)
 */
export async function storeMistralApiKey(apiKey: string): Promise<void> {
	return safeInvoke<void>('store_mistral_api_key', { apiKey });
}

/**
 * Check if Mistral API key exists in secure storage
 */
export async function hasMistralApiKey(): Promise<boolean> {
	return safeInvoke<boolean>('has_mistral_api_key');
}

/**
 * Delete Mistral API key from secure storage
 */
export async function deleteMistralApiKey(): Promise<void> {
	return safeInvoke<void>('delete_mistral_api_key');
}

/**
 * Get which AI provider is currently active: "mistral", "ollama-cloud", or "ollama-local"
 */
export async function getAiProvider(): Promise<string> {
	return safeInvoke<string>('get_ai_provider');
}

// ============================================================================
// Licensing API
// ============================================================================

export interface LicenseInfo {
	is_licensed: boolean;
	license_key: string | null;
	organization_name: string | null;
	expires_at: string | null;
	features: string[];
	endpoint_id: string;
	max_endpoints: number | null;
	is_expired: boolean;
}

/**
 * Get current license information
 */
export async function getLicenseInfo(): Promise<LicenseInfo> {
	return safeInvoke<LicenseInfo>('get_license_info');
}

/**
 * Activate a license key
 */
export async function activateLicense(licenseKey: string): Promise<LicenseInfo> {
	return safeInvoke<LicenseInfo>('activate_license', { licenseKey });
}

/**
 * Deactivate the current license
 */
export async function deactivateLicense(): Promise<void> {
	return safeInvoke<void>('deactivate_license');
}

/**
 * Validate a license key without activating
 */
export async function validateLicense(licenseKey: string): Promise<boolean> {
	return safeInvoke<boolean>('validate_license', { licenseKey });
}

/**
 * Get the unique endpoint ID for this machine
 */
export async function getEndpointId(): Promise<string> {
	return safeInvoke<string>('get_endpoint_id');
}

// ============================================================================
// Database API
// ============================================================================

export interface DbScanRecord {
	id: string;
	scan_type: string;
	status: string;
	started_at: string;
	completed_at: string | null;
	threats_found: number;
	files_scanned: number;
}

export interface DbThreatStats {
	total_threats: number;
	threats_today: number;
	threats_this_week: number;
	unresolved_threats: number;
	by_severity: Record<string, number>;
}

export interface DbActivityRecord {
	id: string;
	event_type: string;
	title: string;
	description: string;
	severity: string;
	module: string;
	timestamp: string;
}

/**
 * Get recent scans from database
 */
export async function dbGetRecentScans(limit?: number): Promise<DbScanRecord[]> {
	return safeInvoke<DbScanRecord[]>('db_get_recent_scans', { limit });
}

/**
 * Get threat statistics from database
 */
export async function dbGetThreatStats(): Promise<DbThreatStats> {
	return safeInvoke<DbThreatStats>('db_get_threat_stats');
}

/**
 * Get recent activity from database
 */
export async function dbGetRecentActivity(limit?: number): Promise<DbActivityRecord[]> {
	return safeInvoke<DbActivityRecord[]>('db_get_recent_activity', { limit });
}

/**
 * Get a setting from database
 */
export async function dbGetSetting(key: string): Promise<string | null> {
	return safeInvoke<string | null>('db_get_setting', { key });
}

/**
 * Set a setting in database
 */
export async function dbSetSetting(key: string, value: string): Promise<void> {
	return safeInvoke<void>('db_set_setting', { key, value });
}

// ============================================================================
// Mock Data for Development
// ============================================================================

function getMockData(command: string, _args?: Record<string, unknown>): unknown {
	// Generate mock threat history
	const generateMockHistory = (): ThreatEvent[] => {
		const types: ThreatType[] = ['malware', 'phishing', 'blocked_connection', 'vulnerability', 'suspicious_activity'];
		const severities: Severity[] = ['low', 'medium', 'high', 'critical'];
		const sources = ['Firewall', 'Scanner', 'Network Monitor', 'AI Agent'];
		
		return Array.from({ length: 50 }, (_, i) => ({
			id: `threat-${i}`,
			threat_type: types[i % types.length],
			severity: severities[i % severities.length],
			source: sources[i % sources.length],
			description: `Security event detected by ${sources[i % sources.length]}`,
			timestamp: new Date(Date.now() - i * 3600000).toISOString(),
			resolved: i > 5,
			resolved_at: i > 5 ? new Date(Date.now() - i * 3600000 + 1800000).toISOString() : null,
			action_taken: i > 5 ? 'Automatically blocked' : null,
		}));
	};

	// Generate mock threat stats
	const generateMockStats = (): ThreatStats => ({
		total_threats: 247,
		threats_today: 12,
		threats_this_week: 45,
		threats_this_month: 156,
		resolved_threats: 230,
		unresolved_threats: 17,
		by_severity: { low: 89, medium: 98, high: 45, critical: 15 },
		by_type: [
			{ threat_type: 'BlockedConnection', count: 78, percentage: 31.6 },
			{ threat_type: 'SuspiciousActivity', count: 56, percentage: 22.7 },
			{ threat_type: 'Vulnerability', count: 45, percentage: 18.2 },
			{ threat_type: 'Malware', count: 38, percentage: 15.4 },
			{ threat_type: 'Phishing', count: 30, percentage: 12.1 },
		],
		daily_counts: Array.from({ length: 14 }, (_, i) => ({
			date: new Date(Date.now() - (13 - i) * 86400000).toISOString().split('T')[0],
			count: Math.floor(Math.random() * 20) + 5,
			blocked: Math.floor(Math.random() * 10) + 2,
			resolved: Math.floor(Math.random() * 15) + 3,
		})),
		hourly_distribution: Array.from({ length: 24 }, (_, h) => ({
			hour: h,
			count: Math.floor(Math.random() * 15) + (h > 8 && h < 18 ? 10 : 2),
		})),
		trend: { direction: 'down', percentage_change: -12.5, comparison_period: 'vs. previous 30 days' },
	});

	// Generate mock plugins
	const generateMockPlugins = (): Plugin[] => [
		{
			id: 'vt-1',
			name: 'VirusTotal Scanner',
			version: '1.2.0',
			description: 'Scan files and URLs against 70+ antivirus engines',
			author: 'Security Prime Labs',
			homepage: 'https://virustotal.com',
			category: 'scanner',
			enabled: true,
			installed_at: new Date().toISOString(),
			updated_at: null,
			permissions: ['file_system_read', 'network_access'],
			config: {},
			status: 'active',
		},
		{
			id: 'hibp-1',
			name: 'Breach Monitor',
			version: '1.0.0',
			description: 'Check if your emails have been compromised in data breaches',
			author: 'Security Prime Labs',
			homepage: 'https://haveibeenpwned.com',
			category: 'data_protection',
			enabled: true,
			installed_at: new Date().toISOString(),
			updated_at: null,
			permissions: ['network_access', 'notification_send'],
			config: {},
			status: 'active',
		},
		{
			id: 'shodan-1',
			name: 'Shodan Network Intel',
			version: '2.0.1',
			description: 'Lookup IPs and domains against Shodan database',
			author: 'Security Prime Labs',
			homepage: 'https://shodan.io',
			category: 'threat_intelligence',
			enabled: false,
			installed_at: new Date().toISOString(),
			updated_at: null,
			permissions: ['network_access'],
			config: {},
			status: 'inactive',
		},
	];

	const mocks: Record<string, unknown> = {
		// New API mocks
		get_threat_history: generateMockHistory(),
		get_threat_stats: generateMockStats(),
		get_plugins: generateMockPlugins(),
		export_firewall_rules: { version: '1.0', exported_at: new Date().toISOString(), rules: [], checksum: 'abc123' },
		import_firewall_rules: { success: true, imported: 4, skipped: 0, total: 4, message: 'Imported 4 rules successfully' },
		export_encryption_keys: { version: '1.0', exported_at: new Date().toISOString(), key_id: 'key-123', encrypted_key: 'ENC:...', algorithm: 'AES-256-GCM', salt: 'salt123', iterations: 100000 },
		import_encryption_keys: { success: true, key_id: 'key-123', message: 'Key imported successfully' },
		toggle_plugin: { id: 'vt-1', enabled: true },
		
		// Existing mocks
		get_system_info: {
			os_name: 'windows',
			os_version: 'Windows 11 Pro 23H2',
			hostname: 'CYBER-PRIME-DEV',
			cpu_cores: 12,
			total_memory_gb: 32.0,
			available_memory_gb: 24.5,
			used_memory_gb: 7.5,
			drives: [
				{
					name: 'C:',
					mount_point: 'C:\\',
					total_space_gb: 500.0,
					available_space_gb: 120.5,
					used_space_gb: 379.5,
					health_status: 'healthy',
					file_system: 'NTFS',
					smart_health: {
						overall_health: 'good',
						temperature: 35.5,
						power_on_hours: 15420,
						reallocated_sectors: 0,
						pending_sectors: 0,
						uncorrectable_errors: 0
					}
				},
				{
					name: 'D:',
					mount_point: 'D:\\',
					total_space_gb: 1000.0,
					available_space_gb: 850.2,
					used_space_gb: 149.8,
					health_status: 'healthy',
					file_system: 'NTFS',
					smart_health: {
						overall_health: 'good',
						temperature: 32.0,
						power_on_hours: 8750,
						reallocated_sectors: 0,
						pending_sectors: 0,
						uncorrectable_errors: 0
					}
				}
			],
			advanced: {
				sensors: {
					cpu_temperature: 45.2,
					gpu_temperature: 52.8,
					motherboard_temperature: 38.5,
					fan_speeds: [
						{ name: 'CPU Fan', speed_rpm: 1200 },
						{ name: 'System Fan 1', speed_rpm: 800 },
						{ name: 'System Fan 2', speed_rpm: 750 }
					]
				},
				network_interfaces: [
					{
						interface_name: 'Ethernet',
						bytes_sent: 1547892340,
						bytes_received: 2894567890,
						packets_sent: 1234567,
						packets_received: 2345678,
						errors_in: 0,
						errors_out: 0
					},
					{
						interface_name: 'Wi-Fi',
						bytes_sent: 456789123,
						bytes_received: 789456123,
						packets_sent: 345678,
						packets_received: 567890,
						errors_in: 2,
						errors_out: 0
					}
				],
				system_load: {
					cpu_usage_percent: 23.5,
					memory_usage_percent: 67.8,
					disk_io_percent: 12.3
				}
			}
		},
		get_security_score: {
			score: 85,
			grade: 'A',
			breakdown: {
				firewall: 90,
				antivirus: 85,
				encryption: 75,
				updates: 88,
				vulnerabilities: 80
			}
		},
		get_module_status: [
			{ name: 'scanner', status: 'active', enabled: true, description: 'Real-time malware scanner', last_activity: '2 minutes ago' },
			{ name: 'firewall', status: 'active', enabled: true, description: 'Advanced firewall manager', last_activity: 'Active now' },
			{ name: 'encryption', status: 'active', enabled: true, description: 'File & folder encryption', last_activity: '1 hour ago' },
			{ name: 'vulnerability', status: 'active', enabled: true, description: 'Vulnerability scanner', last_activity: 'Today, 3:00 PM' },
			{ name: 'network', status: 'active', enabled: true, description: 'Network monitor', last_activity: 'Active now' },
			{ name: 'agent', status: 'inactive', enabled: false, description: 'AI Security Assistant', last_activity: null }
		],
		get_recent_activity: [
			{ id: '1', event_type: 'scan_completed', title: 'System Scan Completed', description: 'Full system scan completed successfully.', severity: 'low', timestamp: new Date().toISOString(), module: 'scanner' },
			{ id: '2', event_type: 'firewall_blocked', title: 'Connection Blocked', description: 'Blocked suspicious outbound connection.', severity: 'medium', timestamp: new Date().toISOString(), module: 'firewall' },
			{ id: '3', event_type: 'system_update', title: 'Definitions Updated', description: 'Malware definitions updated.', severity: 'low', timestamp: new Date().toISOString(), module: 'scanner' }
		],
		start_real_time_monitoring: true,
		stop_real_time_monitoring: true,
		get_monitoring_status: {
			is_active: true,
			last_check: new Date().toISOString(),
			total_events: 15,
			alerts_today: 3
		},
		get_threat_alerts: [
			{ id: '1', title: 'Potential Malware Detected', description: 'Suspicious file behavior detected.', severity: 'high', source: 'Real-time Scanner', timestamp: new Date().toISOString(), resolved: false },
			{ id: '2', title: 'Unusual Network Activity', description: 'Multiple connection attempts detected.', severity: 'medium', source: 'Network Monitor', timestamp: new Date().toISOString(), resolved: false }
		],
		get_firewall_status: {
			enabled: true,
			profile: 'Home',
			inbound_blocked: 1247,
			outbound_blocked: 89,
			active_rules: 24,
			last_blocked: { ip: '185.234.72.19', port: 443, protocol: 'TCP', direction: 'inbound', reason: 'Suspicious origin', timestamp: new Date().toISOString() }
		},
		get_firewall_rules: [
			{ id: '1', name: 'Block Telemetry', enabled: true, direction: 'outbound', action: 'block', protocol: 'any', local_port: null, remote_port: null, remote_address: '*.telemetry.microsoft.com', application: null, description: 'Block Windows telemetry', created_at: '2024-01-01T00:00:00Z' }
		],
		get_encrypted_files: [
			{ id: '1', original_name: 'financial_records.xlsx', encrypted_path: 'C:\\Encrypted\\financial_records.xlsx.encrypted', original_size: 2500000, encrypted_size: 2500256, algorithm: 'AES-256-GCM', encrypted_at: new Date().toISOString(), last_accessed: new Date().toISOString() }
		],
		get_vulnerabilities: [
			{ id: '1', cve_id: 'CVE-2024-21351', title: 'Windows SmartScreen Bypass', description: 'Security feature bypass vulnerability.', severity: 'high', affected_software: 'Windows 10/11', current_version: '10.0.19045', fixed_version: 'KB5034441', detected_at: new Date().toISOString(), status: 'open', remediation: 'Install latest Windows updates.' }
		],
		get_network_connections: [
			{ id: '1', process_name: 'chrome.exe', process_id: 12456, local_address: '192.168.1.100', local_port: 52341, remote_address: '142.250.185.78', remote_port: 443, protocol: 'TCP', state: 'ESTABLISHED', bytes_sent: 1500000, bytes_received: 45000000, established_at: new Date().toISOString() }
		],
		get_network_stats: {
			total_connections: 47,
			active_connections: 23,
			bytes_sent_total: 1250000000,
			bytes_received_total: 8500000000,
			bytes_sent_per_sec: 125000,
			bytes_received_per_sec: 850000,
			blocked_connections: 156,
			suspicious_connections: 3
		},
		get_little_snitch_rules: [
			{ id: 'lsr-001', action: 'allow', direction: 'outgoing', process: 'any', remote_host: 'api.openai.com', ports: '443', protocol: 'tcp', notes: 'OpenAI API — required if using GPT models', category: 'ai_endpoint', priority: 'critical' },
			{ id: 'lsr-002', action: 'allow', direction: 'outgoing', process: 'any', remote_host: 'api.anthropic.com', ports: '443', protocol: 'tcp', notes: 'Anthropic API — required if using Claude', category: 'ai_endpoint', priority: 'critical' },
			{ id: 'lsr-003', action: 'allow', direction: 'outgoing', process: 'any', remote_host: 'localhost', ports: '11434,1234,8080', protocol: 'tcp', notes: 'Local model servers (Ollama, LM Studio)', category: 'ai_endpoint', priority: 'critical' },
			{ id: 'lsr-004', action: 'allow', direction: 'outgoing', process: 'any', remote_host: 'update.microsoft.com', ports: '443', protocol: 'tcp', notes: 'Windows Update', category: 'update', priority: 'recommended' },
			{ id: 'lsr-005', action: 'deny', direction: 'outgoing', process: 'any', remote_host: 'telemetry.microsoft.com', ports: 'any', protocol: 'any', notes: 'Microsoft Telemetry', category: 'telemetry', priority: 'recommended' },
			{ id: 'lsr-006', action: 'deny', direction: 'outgoing', process: 'any', remote_host: 'analytics.google.com', ports: 'any', protocol: 'any', notes: 'Google Analytics tracking', category: 'telemetry', priority: 'recommended' },
			{ id: 'lsr-007', action: 'deny', direction: 'outgoing', process: 'chrome.exe', remote_host: '185.234.72.19', ports: '8080', protocol: 'tcp', notes: 'Unknown destination seen from chrome.exe — review before allowing', category: 'uncategorized', priority: 'optional' },
		],
		get_little_snitch_domain_trust: [
			{ domain: 'telemetry.microsoft.com', trust_level: 'suspicious', category: 'telemetry', first_seen: new Date().toISOString(), connection_count: 14, notes: 'Microsoft Telemetry' },
			{ domain: 'analytics.google.com', trust_level: 'suspicious', category: 'telemetry', first_seen: new Date().toISOString(), connection_count: 8, notes: 'Google Analytics tracking' },
			{ domain: '185.234.72.19', trust_level: 'unknown', category: 'uncategorized', first_seen: new Date().toISOString(), connection_count: 3, notes: 'Not in known-domain registry' },
			{ domain: '45.33.12.56', trust_level: 'unknown', category: 'uncategorized', first_seen: new Date().toISOString(), connection_count: 1, notes: 'Not in known-domain registry' },
			{ domain: 'api.openai.com', trust_level: 'trusted', category: 'ai_endpoint', first_seen: new Date().toISOString(), connection_count: 42, notes: 'OpenAI API' },
			{ domain: '142.250.185.78', trust_level: 'unknown', category: 'uncategorized', first_seen: new Date().toISOString(), connection_count: 25, notes: 'Not in known-domain registry' },
			{ domain: 'update.microsoft.com', trust_level: 'trusted', category: 'update', first_seen: new Date().toISOString(), connection_count: 6, notes: 'Windows Update' },
		],
		export_little_snitch_profile: {
			name: 'SecurityPrime Recommended Rules',
			description: 'Import this file into Little Snitch as a Rule Group.',
			created_at: new Date().toISOString(),
			rules_json: '{"name":"SecurityPrime Recommended Rules","rules":[]}',
			rule_count: 7,
		},
		get_settings: {
			theme: 'dark',
			auto_start: false,
			real_time_protection: true,
			auto_update: true,
			notifications_enabled: true,
			scan_on_startup: false,
			modules_enabled: {
				scanner: true,
				firewall: true,
				encryption: true,
				vulnerability: true,
				network: true,
				agent: false
			}
		},
		// Advanced AI Security Analysis mocks
		analyze_threat_prediction: {
			threat_level: 'medium',
			confidence: 0.75,
			predicted_threats: [
				'Potential ransomware infection',
				'Suspicious network scanning activity'
			],
			risk_factors: [
				'Outdated Windows version',
				'Multiple suspicious network connections'
			],
			recommendations: [
				'Update to Windows 11 immediately',
				'Run full system scan',
				'Monitor network traffic closely'
			],
			time_window: 'days'
		},
		get_security_intelligence: {
			threat_indicators: [
				'Ransomware campaigns targeting Windows systems',
				'New phishing campaigns using AI-generated content',
				'Supply chain attacks on popular software libraries'
			],
			emerging_threats: [
				'AI-powered malware that adapts to defenses',
				'Quantum computing threats to encryption',
				'IoT device-based botnets'
			],
			recommended_actions: [
				'Update all software to latest versions',
				'Enable multi-factor authentication everywhere',
				'Implement regular security training'
			],
			intelligence_sources: [
				'Microsoft Security Intelligence',
				'CrowdStrike Threat Intelligence',
				'Mandiant Threat Reports'
			],
			last_updated: new Date().toISOString()
		},
		perform_comprehensive_ai_analysis: {
			threat_prediction: {
				threat_level: 'medium',
				confidence: 0.75,
				predicted_threats: [
					'Potential ransomware infection',
					'Suspicious network scanning activity'
				],
				risk_factors: [
					'Outdated Windows version',
					'Multiple suspicious network connections'
				],
				recommendations: [
					'Update to Windows 11 immediately',
					'Run full system scan'
				],
				time_window: 'days'
			},
			behavioral_analysis: [
				{
					pattern_type: 'suspicious',
					description: '2 suspicious processes detected',
					frequency: 'ongoing',
					risk_level: 'medium',
					observed_behaviors: ['Unknown process accessing system files'],
					analysis: 'Suspicious processes may indicate malware'
				}
			],
			security_intelligence: {
				threat_indicators: ['Ransomware campaigns targeting Windows systems'],
				emerging_threats: ['AI-powered malware that adapts to defenses'],
				recommended_actions: [
					'Update all software to latest versions',
					'Enable multi-factor authentication'
				],
				intelligence_sources: ['Microsoft Security Intelligence'],
				last_updated: new Date().toISOString()
			},
			overall_risk_assessment: 'MEDIUM RISK - Monitor closely and address issues',
			priority_actions: [
				'Update to Windows 11 immediately',
				'Run full system scan',
				'Update all software to latest versions',
				'Enable multi-factor authentication everywhere'
			]
		},
		// Advanced Scanning
		scan_memory_forensics: [
			{
				process_id: 1234,
				process_name: 'chrome.exe',
				suspicious_regions: [
					{
						start_address: '0x00007FF8E5A10000',
						size: 4096,
						permissions: 'RWX',
						suspicious_patterns: ['shellcode'],
						risk_level: 'high'
					}
				],
				total_regions: 150,
				scanned_regions: 150
			}
		],
		analyze_behavioral_patterns: [
			{
				process_id: 5678,
				process_name: 'unknown_process.exe',
				behavior_score: 85.5,
				anomalous_behaviors: [
					'Excessive network connections',
					'Registry modifications',
					'File system access to sensitive areas'
				],
				risk_assessment: 'High risk - Potential malware',
				recommendations: [
					'Quarantine the process',
					'Run full system scan',
					'Check network traffic'
				]
			}
		],
		get_yara_rules: [
			{
				rule_name: 'Ransomware_Detection',
				description: 'Detects common ransomware patterns',
				condition: 'any of them',
				strings: ['$encrypt_ext = ".encrypted"', '$ransom_note = "Your files are encrypted"'],
				tags: ['ransomware', 'encryption'],
				enabled: true
			}
		],
		scan_with_yara: [
			{
				file_path: 'C:\\Users\\user\\Downloads\\suspicious.exe',
				matched_rules: ['Ransomware_Detection'],
				total_matches: 2,
				scan_duration: 1250
			}
		],
		perform_advanced_scan: {
			memory_forensics: [],
			behavioral_analysis: [],
			yara_matches: [],
			overall_threat_level: 'low',
			scan_duration: 45230
		},
		initialize_yara_rules: undefined,
		add_yara_rule: undefined,
		// Compliance
		get_gdpr_compliance_data: {
			data_processing_register: [
				{
					activity_id: 'dp-001',
					purpose: 'User authentication and authorization',
					categories_of_data: ['Email addresses', 'Passwords'],
					legal_basis: 'Contract performance',
					recipients: ['Internal systems'],
					retention_period: 'Account active + 2 years'
				}
			],
			subject_rights_requests: [
				{
					request_id: 'srr-001',
					subject_id: 'user@example.com',
					request_type: 'access',
					status: 'completed',
					requested_at: '2024-01-15T10:30:00Z',
					completed_at: '2024-01-20T14:45:00Z'
				}
			],
			data_protection_officer: {
				name: 'Jane Smith',
				email: 'dpo@company.com',
				phone: '+1-555-0123',
				designated_date: '2023-06-01'
			},
			privacy_policy_version: '2.1.0',
			compliance_score: 87.5,
			last_audit_date: '2024-01-01T00:00:00Z'
		},
		// Isolation
		get_isolation_profiles: [
			{
				profile_id: 'web-browsing',
				name: 'Web Browsing',
				description: 'Isolated environment for web browsers',
				isolation_level: 'standard',
				resource_limits: {
					max_cpu_percent: 50,
					max_memory_mb: 1024,
					max_disk_io: 100,
					max_network_bandwidth: 10
				},
				network_access: {
					allow_internet: true,
					allow_local_network: false,
					allowed_ports: [80, 443],
					blocked_ports: [],
					allowed_domains: ['*.google.com', '*.microsoft.com']
				},
				allowed_paths: ['C:\\Users\\*\\Downloads'],
				blocked_paths: ['C:\\Windows\\System32'],
				enabled: true
			}
		],
		// Tamper Detection
		get_integrity_checks: [
			{
				id: 'ic-001',
				name: 'System32 Integrity',
				target_path: 'C:\\Windows\\System32',
				check_type: 'DirectoryHash',
				expected_hash: 'a1b2c3d4e5f6...',
				last_check: '2024-01-20T15:30:00Z',
				status: 'Valid',
				check_interval: 3600,
				enabled: true
			}
		],
		run_integrity_check: [],
		get_tamper_alerts: [
			{
				alert_id: 'ta-001',
				title: 'File Integrity Violation',
				description: 'Critical system file has been modified',
				severity: 'high',
				target_path: 'C:\\Windows\\System32\\kernel32.dll',
				detected_at: '2024-01-20T14:22:00Z',
				status: 'active'
			}
		],
		resolve_tamper_alert: undefined,
		capture_system_baseline: undefined,
		get_secure_boot_status: {
			enabled: true,
			secure_boot_supported: true,
			last_check: '2024-01-20T15:45:00Z',
			status_message: 'Secure Boot is enabled and functioning properly'
		},
		// Security Hardening
		get_memory_protection_status: {
			enabled: true,
			dep_enabled: true,
			aslr_enabled: true,
			cfg_enabled: false,
			last_check: '2024-01-20T15:50:00Z'
		},
		get_secure_logging_status: {
			enabled: true,
			log_encryption: true,
			tamper_proof: true,
			integrity_checks: true,
			last_validation: '2024-01-20T15:55:00Z'
		},
		get_rate_limiting_status: {
			enabled: true,
			max_requests_per_minute: 100,
			current_requests: 23,
			blocked_requests: 2,
			last_reset: '2024-01-20T15:45:00Z'
		},
		check_rate_limit: true,
		log_security_event: undefined,
		get_security_events: [
			{
				event_id: 'se-001',
				event_type: 'authentication',
				message: 'Failed login attempt',
				severity: 'medium',
				timestamp: '2024-01-20T15:30:00Z',
				source: 'login_system'
			}
		],
		get_hardening_metrics: {
			memory_violations: 0,
			log_integrity_failures: 0,
			rate_limit_exceeded: 2,
			security_events_today: 15,
			uptime_hours: 168.5,
			hardening_score: 94.2
		},
		report_memory_violation: undefined,
		verify_log_integrity: true,
		get_security_hardening_dashboard: {
			memory_violations: 0,
			log_integrity_failures: 0,
			rate_limit_exceeded: 2,
			security_events_today: 15,
			uptime_hours: 168.5,
			hardening_score: 94.2
		}
	};

	return mocks[command] ?? null;
}

