<script lang="ts">
	import { onMount } from 'svelte';
	import { invoke } from '@tauri-apps/api/tauri';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Progress } from '$lib/components/ui/progress';
	import { Separator } from '$lib/components/ui/separator';
	import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
	import { Shield, AlertTriangle, CheckCircle, XCircle, Activity, Lock, Cpu, Database, Zap } from 'lucide-svelte';

	interface TamperDashboard {
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

	interface IntegrityCheck {
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

	interface AnomalyDetector {
		id: string;
		name: string;
		detector_type: 'FileSystemActivity' | 'NetworkTraffic' | 'ProcessBehavior' | 'SystemLoad' | 'MemoryUsage' | 'LoginAttempts';
		target: string;
		threshold: number;
		baseline_values: number[];
		last_detection: string;
		status: 'Learning' | 'Active' | 'Alert' | 'Disabled';
		sensitivity: number;
		enabled: boolean;
	}

	interface SecureBootStatus {
		enabled: boolean;
		secure_boot_supported: boolean;
		measured_boot: boolean;
		tpm_present: boolean;
		tpm_version: string | null;
		boot_measurements: any[];
		last_verification: string;
		status: 'Enabled' | 'Disabled' | 'Compromised' | 'Unknown';
	}

	interface TamperAlert {
		id: string;
		timestamp: string;
		alert_type: 'IntegrityViolation' | 'AnomalyDetected' | 'SecureBootFailure' | 'UnauthorizedAccess' | 'SuspiciousActivity';
		severity: 'Low' | 'Medium' | 'High' | 'Critical';
		description: string;
		affected_resource: string;
		detected_changes: string[];
		recommended_actions: string[];
		resolved: boolean;
		resolved_at: string | null;
	}

	let loading = true;
	let dashboard: TamperDashboard | null = null;
	let integrityChecks: IntegrityCheck[] = [];
	let anomalyDetectors: AnomalyDetector[] = [];
	let secureBootStatus: SecureBootStatus | null = null;
	let tamperAlerts: TamperAlert[] = [];
	let activeTab = 'dashboard';

	async function loadDashboardData() {
		try {
			dashboard = await invoke('get_tamper_detection_dashboard');
			integrityChecks = await invoke('get_integrity_checks');
			anomalyDetectors = await invoke('get_anomaly_detectors');
			secureBootStatus = await invoke('get_secure_boot_status');
			tamperAlerts = await invoke('get_tamper_alerts');
		} catch (error) {
			console.error('Failed to load tamper detection data:', error);
		} finally {
			loading = false;
		}
	}

	async function runIntegrityCheck(checkId: string) {
		try {
			const status = await invoke('run_integrity_check', { checkId });
			await loadDashboardData(); // Refresh data
			alert(`Integrity check completed: ${status}`);
		} catch (error) {
			console.error('Failed to run integrity check:', error);
			alert('Failed to run integrity check');
		}
	}

	async function resolveAlert(alertId: string) {
		try {
			await invoke('resolve_tamper_alert', { alertId });
			await loadDashboardData(); // Refresh data
		} catch (error) {
			console.error('Failed to resolve alert:', error);
			alert('Failed to resolve alert');
		}
	}

	async function captureBaseline() {
		try {
			await invoke('capture_system_baseline');
			await loadDashboardData(); // Refresh data
			alert('System baseline captured successfully');
		} catch (error) {
			console.error('Failed to capture baseline:', error);
			alert('Failed to capture system baseline');
		}
	}

	async function runAnomalyDetection() {
		try {
			const alerts = await invoke('perform_anomaly_detection');
			await loadDashboardData(); // Refresh data
			if (alerts.length > 0) {
				alert(`Anomaly detection completed. ${alerts.length} detectors triggered alerts.`);
			} else {
				alert('Anomaly detection completed. No anomalies detected.');
			}
		} catch (error) {
			console.error('Failed to run anomaly detection:', error);
			alert('Failed to run anomaly detection');
		}
	}

	function getStatusColor(status: string) {
		switch (status) {
			case 'Valid':
				return 'bg-green-500';
			case 'Modified':
			case 'Missing':
			case 'Compromised':
				return 'bg-red-500';
			case 'AccessDenied':
				return 'bg-yellow-500';
			case 'Unknown':
			case 'Disabled':
				return 'bg-gray-500';
			case 'Active':
				return 'bg-blue-500';
			case 'Learning':
				return 'bg-purple-500';
			case 'Alert':
				return 'bg-orange-500';
			case 'Enabled':
				return 'bg-green-500';
			default:
				return 'bg-gray-500';
		}
	}

	function getSeverityColor(severity: string) {
		switch (severity) {
			case 'Low':
				return 'bg-green-500';
			case 'Medium':
				return 'bg-yellow-500';
			case 'High':
				return 'bg-orange-500';
			case 'Critical':
				return 'bg-red-500';
			default:
				return 'bg-gray-500';
		}
	}

	function getCheckTypeIcon(checkType: string) {
		switch (checkType) {
			case 'FileHash':
				return '📄';
			case 'DirectoryHash':
				return '📁';
			case 'RegistryKey':
				return '🔑';
			case 'SystemFile':
				return '⚙️';
			case 'CriticalProcess':
				return '🔧';
			default:
				return '❓';
		}
	}

	function getDetectorTypeIcon(detectorType: string) {
		switch (detectorType) {
			case 'FileSystemActivity':
				return '💾';
			case 'NetworkTraffic':
				return '🌐';
			case 'ProcessBehavior':
				return '⚙️';
			case 'SystemLoad':
				return '📊';
			case 'MemoryUsage':
				return '🧠';
			case 'LoginAttempts':
				return '🔐';
			default:
				return '❓';
		}
	}

	onMount(() => {
		loadDashboardData();
	});
</script>

<svelte:head>
	<title>Tamper Detection - Cyber Security Prime</title>
</svelte:head>

<div class="container mx-auto p-6">
	<div class="mb-8">
		<h1 class="text-3xl font-bold mb-2">Tamper Detection</h1>
		<p class="text-gray-600 dark:text-gray-400">
			Integrity checking, anomaly detection, and secure boot verification
		</p>
	</div>

	{#if loading}
		<LoadingSpinner />
	{:else if dashboard}
		<!-- Navigation Tabs -->
		<div class="mb-6">
			<div class="flex space-x-1 bg-gray-100 dark:bg-gray-800 p-1 rounded-lg">
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'dashboard' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'dashboard'}
				>
					<Activity class="inline w-4 h-4 mr-2" />
					Dashboard
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'integrity' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'integrity'}
				>
					<Shield class="inline w-4 h-4 mr-2" />
					Integrity
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'anomalies' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'anomalies'}
				>
					<AlertTriangle class="inline w-4 h-4 mr-2" />
					Anomalies
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'secure-boot' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'secure-boot'}
				>
					<Lock class="inline w-4 h-4 mr-2" />
					Secure Boot
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'alerts' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'alerts'}
				>
					<AlertTriangle class="inline w-4 h-4 mr-2" />
					Alerts
				</button>
			</div>
		</div>

		<!-- Dashboard Tab -->
		{#if activeTab === 'dashboard'}
			<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Integrity Checks</CardTitle>
						<Shield class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.integrity_checks_passing}/{dashboard.integrity_checks_total}</div>
						<p class="text-xs text-muted-foreground">
							Checks passing
						</p>
						<Progress value={(dashboard.integrity_checks_passing / Math.max(dashboard.integrity_checks_total, 1)) * 100} class="mt-2" />
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Anomaly Detectors</CardTitle>
						<Activity class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.anomaly_detectors_active}</div>
						<p class="text-xs text-muted-foreground">
							{dashboard.anomaly_detectors_alerting} alerting
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Tamper Alerts</CardTitle>
						<AlertTriangle class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.tamper_alerts_unresolved}</div>
						<p class="text-xs text-muted-foreground">
							Unresolved alerts
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Secure Boot</CardTitle>
						<Lock class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">
							{#if dashboard.secure_boot_enabled}
								<CheckCircle class="w-8 h-8 text-green-500" />
							{:else}
								<XCircle class="w-8 h-8 text-red-500" />
							{/if}
						</div>
						<p class="text-xs text-muted-foreground">
							{dashboard.secure_boot_enabled ? 'Enabled' : 'Disabled'}
						</p>
					</CardContent>
				</Card>
			</div>

			<!-- System Status -->
			<div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
				<Card>
					<CardHeader>
						<CardTitle>System Baseline</CardTitle>
					</CardHeader>
					<CardContent>
						<div class="flex items-center justify-between">
							<div>
								<p class="text-sm font-medium">Baseline Status</p>
								<p class="text-xs text-muted-foreground">
									{dashboard.system_baseline_valid ? 'Valid and up to date' : 'Needs updating'}
								</p>
							</div>
							{#if dashboard.system_baseline_valid}
								<CheckCircle class="w-8 h-8 text-green-500" />
							{:else}
								<XCircle class="w-8 h-8 text-red-500" />
							{/if}
						</div>
						<Separator class="my-4" />
						<Button on:click={captureBaseline} class="w-full">
							<Database class="w-4 h-4 mr-2" />
							Capture New Baseline
						</Button>
					</CardContent>
				</Card>

				<Card>
					<CardHeader>
						<CardTitle>Quick Actions</CardTitle>
					</CardHeader>
					<CardContent class="space-y-2">
						<Button on:click={runAnomalyDetection} variant="outline" class="w-full">
							<Activity class="w-4 h-4 mr-2" />
							Run Anomaly Detection
						</Button>
						<Button on:click={() => activeTab = 'integrity'} variant="outline" class="w-full">
							<Shield class="w-4 h-4 mr-2" />
							Run Integrity Checks
						</Button>
						<Button on:click={() => activeTab = 'alerts'} variant="outline" class="w-full">
							<AlertTriangle class="w-4 h-4 mr-2" />
							View Active Alerts
						</Button>
					</CardContent>
				</Card>
			</div>
		{/if}

		<!-- Integrity Tab -->
		{#if activeTab === 'integrity'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Integrity Checks</h2>
					<Button>
						<Shield class="w-4 h-4 mr-2" />
						Add Check
					</Button>
				</div>

				<div class="grid gap-4">
					{#each integrityChecks as check}
						<Card>
							<CardHeader>
								<div class="flex justify-between items-start">
									<div>
										<CardTitle class="flex items-center gap-2">
											<span class="text-lg">{getCheckTypeIcon(check.check_type)}</span>
											{check.name}
										</CardTitle>
										<p class="text-sm text-muted-foreground">{check.target_path}</p>
									</div>
									<div class="flex gap-2">
										<Badge class={getStatusColor(check.status)}>{check.status}</Badge>
										<Badge variant="outline">{check.check_type}</Badge>
									</div>
								</div>
							</CardHeader>
							<CardContent>
								<div class="grid grid-cols-2 gap-4 text-sm mb-4">
									<div>
										<span class="font-medium">Last Check:</span>
										{new Date(check.last_check).toLocaleString()}
									</div>
									<div>
										<span class="font-medium">Interval:</span>
										{Math.floor(check.check_interval / 60)} minutes
									</div>
									<div>
										<span class="font-medium">Expected Hash:</span>
										<code class="text-xs bg-gray-100 dark:bg-gray-800 px-1 rounded">
											{check.expected_hash.substring(0, 16)}...
										</code>
									</div>
									<div>
										<span class="font-medium">Status:</span>
										{check.enabled ? 'Enabled' : 'Disabled'}
									</div>
								</div>
								<Separator class="my-4" />
								<div class="flex gap-2">
									<Button
										variant="outline"
										size="sm"
										on:click={() => runIntegrityCheck(check.id)}
									>
										<Shield class="w-4 h-4 mr-2" />
										Run Check
									</Button>
									<Button variant="outline" size="sm">Configure</Button>
									<Button variant="outline" size="sm" class="text-red-600">Disable</Button>
								</div>
							</CardContent>
						</Card>
					{/each}
				</div>
			</div>
		{/if}

		<!-- Anomalies Tab -->
		{#if activeTab === 'anomalies'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Anomaly Detectors</h2>
					<Button on:click={runAnomalyDetection}>
						<Activity class="w-4 h-4 mr-2" />
						Run Detection
					</Button>
				</div>

				<div class="grid gap-4">
					{#each anomalyDetectors as detector}
						<Card>
							<CardHeader>
								<div class="flex justify-between items-start">
									<div>
										<CardTitle class="flex items-center gap-2">
											<span class="text-lg">{getDetectorTypeIcon(detector.detector_type)}</span>
											{detector.name}
										</CardTitle>
										<p class="text-sm text-muted-foreground">Target: {detector.target}</p>
									</div>
									<div class="flex gap-2">
										<Badge class={getStatusColor(detector.status)}>{detector.status}</Badge>
										<Badge variant="outline">{detector.detector_type}</Badge>
									</div>
								</div>
							</CardHeader>
							<CardContent>
								<div class="grid grid-cols-2 gap-4 text-sm mb-4">
									<div>
										<span class="font-medium">Threshold:</span>
										{detector.threshold.toFixed(1)}
									</div>
									<div>
										<span class="font-medium">Sensitivity:</span>
										{(detector.sensitivity * 100).toFixed(0)}%
									</div>
									<div>
										<span class="font-medium">Last Detection:</span>
										{new Date(detector.last_detection).toLocaleString()}
									</div>
									<div>
										<span class="font-medium">Baseline Values:</span>
										{detector.baseline_values.length} samples
									</div>
								</div>
								<Separator class="my-4" />
								<div class="flex gap-2">
									<Button variant="outline" size="sm">Configure</Button>
									<Button variant="outline" size="sm" class={detector.enabled ? 'text-red-600' : ''}>
										{detector.enabled ? 'Disable' : 'Enable'}
									</Button>
								</div>
							</CardContent>
						</Card>
					{/each}
				</div>
			</div>
		{/if}

		<!-- Secure Boot Tab -->
		{#if activeTab === 'secure-boot' && secureBootStatus}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Secure Boot Status</h2>
					<Button>
						<Lock class="w-4 h-4 mr-2" />
						Verify Boot
					</Button>
				</div>

				<!-- Boot Status Overview -->
				<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
					<Card>
						<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
							<CardTitle class="text-sm font-medium">Secure Boot</CardTitle>
							<Lock class="h-4 w-4 text-muted-foreground" />
						</CardHeader>
						<CardContent>
							<div class="text-2xl font-bold">
								{#if secureBootStatus.enabled}
									<CheckCircle class="w-8 h-8 text-green-500" />
								{:else}
									<XCircle class="w-8 h-8 text-red-500" />
								{/if}
							</div>
							<p class="text-xs text-muted-foreground">
								{secureBootStatus.status}
							</p>
						</CardContent>
					</Card>

					<Card>
						<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
							<CardTitle class="text-sm font-medium">Measured Boot</CardTitle>
							<Cpu class="h-4 w-4 text-muted-foreground" />
						</CardHeader>
						<CardContent>
							<div class="text-2xl font-bold">
								{#if secureBootStatus.measured_boot}
									<CheckCircle class="w-8 h-8 text-green-500" />
								{:else}
									<XCircle class="w-8 h-8 text-red-500" />
								{/if}
							</div>
							<p class="text-xs text-muted-foreground">
								{secureBootStatus.measured_boot ? 'Enabled' : 'Disabled'}
							</p>
						</CardContent>
					</Card>

					<Card>
						<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
							<CardTitle class="text-sm font-medium">TPM</CardTitle>
							<Database class="h-4 w-4 text-muted-foreground" />
						</CardHeader>
						<CardContent>
							<div class="text-2xl font-bold">
								{#if secureBootStatus.tpm_present}
									<CheckCircle class="w-8 h-8 text-green-500" />
								{:else}
									<XCircle class="w-8 h-8 text-red-500" />
								{/if}
							</div>
							<p class="text-xs text-muted-foreground">
								{secureBootStatus.tpm_version || 'Not present'}
							</p>
						</CardContent>
					</Card>

					<Card>
						<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
							<CardTitle class="text-sm font-medium">Last Verification</CardTitle>
							<Activity class="h-4 w-4 text-muted-foreground" />
						</CardHeader>
						<CardContent>
							<div class="text-2xl font-bold">
								{new Date(secureBootStatus.last_verification).toLocaleDateString()}
							</div>
							<p class="text-xs text-muted-foreground">
								{new Date(secureBootStatus.last_verification).toLocaleTimeString()}
							</p>
						</CardContent>
					</Card>
				</div>

				<!-- Boot Measurements -->
				<Card>
					<CardHeader>
						<CardTitle>Boot Measurements (TPM PCRs)</CardTitle>
						<p class="text-sm text-muted-foreground">Cryptographic measurements of the boot process</p>
					</CardHeader>
					<CardContent>
						<div class="space-y-4">
							{#each secureBootStatus.boot_measurements as measurement}
								<div class="flex items-center justify-between p-4 border rounded-lg">
									<div class="flex-1">
										<div class="flex items-center gap-2 mb-1">
											<span class="font-medium">PCR {measurement.pcr_index}</span>
											<Badge variant="secondary">{measurement.description}</Badge>
										</div>
										<code class="text-xs bg-gray-100 dark:bg-gray-800 p-2 rounded block">
											{measurement.measurement}
										</code>
									</div>
									<div class="text-right text-sm text-muted-foreground">
										{new Date(measurement.timestamp).toLocaleString()}
									</div>
								</div>
							{/each}
						</div>
					</CardContent>
				</Card>
			</div>
		{/if}

		<!-- Alerts Tab -->
		{#if activeTab === 'alerts'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Tamper Alerts</h2>
					<Button variant="outline">
						<AlertTriangle class="w-4 h-4 mr-2" />
						Export Report
					</Button>
				</div>

				<div class="grid gap-4">
					{#each tamperAlerts as alert}
						<Card class={!alert.resolved ? 'border-red-500 dark:border-red-400' : ''}>
							<CardHeader>
								<div class="flex justify-between items-start">
									<div>
										<CardTitle class="flex items-center gap-2">
											{alert.description}
											{#if !alert.resolved}
												<div class="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
											{/if}
										</CardTitle>
										<p class="text-sm text-muted-foreground">
											Affected: {alert.affected_resource}
										</p>
									</div>
									<div class="flex gap-2">
										<Badge class={getSeverityColor(alert.severity)}>{alert.severity}</Badge>
										<Badge variant="outline">{alert.alert_type}</Badge>
										{#if alert.resolved}
											<Badge variant="secondary">Resolved</Badge>
										{:else}
											<Badge class="bg-red-500">Active</Badge>
										{/if}
									</div>
								</div>
							</CardHeader>
							<CardContent>
								<div class="space-y-4">
									<div>
										<h4 class="font-medium mb-2">Detected Changes</h4>
										<ul class="text-sm text-muted-foreground space-y-1">
											{#each alert.detected_changes as change}
												<li>• {change}</li>
											{/each}
										</ul>
									</div>
									<div>
										<h4 class="font-medium mb-2">Recommended Actions</h4>
										<ul class="text-sm space-y-1">
											{#each alert.recommended_actions as action}
												<li class="flex items-center gap-2">
													<Zap class="w-4 h-4 text-blue-500" />
													{action}
												</li>
											{/each}
										</ul>
									</div>
								</div>
								<Separator class="my-4" />
								<div class="flex justify-between items-center text-sm text-muted-foreground">
									<span>{new Date(alert.timestamp).toLocaleString()}</span>
									{#if !alert.resolved}
										<Button
											variant="outline"
											size="sm"
											on:click={() => resolveAlert(alert.id)}
										>
											<CheckCircle class="w-4 h-4 mr-2" />
											Resolve
										</Button>
									{:else}
										<span class="text-green-600">
											Resolved {alert.resolved_at ? new Date(alert.resolved_at).toLocaleString() : ''}
										</span>
									{/if}
								</div>
							</CardContent>
						</Card>
					{/each}

					{#if tamperAlerts.length === 0}
						<Card>
							<CardContent class="text-center py-12">
								<CheckCircle class="w-12 h-12 mx-auto mb-4 text-green-500" />
								<h3 class="text-lg font-medium mb-2">No Tamper Alerts</h3>
								<p class="text-muted-foreground">
									System integrity is intact. No tampering has been detected.
								</p>
							</CardContent>
						</Card>
					{/if}
				</div>
			</div>
		{/if}
	{:else}
		<div class="text-center py-12">
			<p class="text-gray-500 dark:text-gray-400">Unable to load tamper detection data</p>
		</div>
	{/if}
</div>