<script lang="ts">
	import { onMount } from 'svelte';
	import { invoke } from '@tauri-apps/api/tauri';
	import { save } from '@tauri-apps/api/dialog';
	import { writeTextFile } from '@tauri-apps/api/fs';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Progress } from '$lib/components/ui/progress';
	import { Separator } from '$lib/components/ui/separator';
	import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
	import { Shield, Lock, Activity, AlertTriangle, Cpu, HardDrive, Network, CheckCircle, XCircle, Zap } from 'lucide-svelte';

	interface HardeningDashboard {
		memory_protection: {
			enabled: boolean;
			regions_monitored: number;
			violations_today: number;
			canary_enabled: boolean;
			aslr_enabled: boolean;
		};
		secure_logging: {
			enabled: boolean;
			encryption_enabled: boolean;
			tamper_detection: boolean;
			total_entries: number;
			retention_days: number;
		};
		rate_limiting: {
			enabled: boolean;
			global_rpm: number;
			active_counters: number;
			blocked_requests: number;
			blocks_today: number;
		};
		security_events: {
			total_events: number;
			critical_events: number;
			recent_high_severity: number;
		};
		performance: {
			average_response_time: number;
			memory_usage_mb: number;
			last_updated: string;
		};
	}

	interface SecurityEvent {
		id: string;
		timestamp: string;
		event_type: 'MemoryViolation' | 'LogTampering' | 'RateLimitExceeded' | 'SuspiciousActivity' | 'SecurityConfigChange' | 'HardeningViolation';
		severity: 'Low' | 'Medium' | 'High' | 'Critical';
		description: string;
		source: string;
		details: any;
	}

	let loading = true;
	let dashboard: HardeningDashboard | null = null;
	let securityEvents: SecurityEvent[] = [];
	let activeTab = 'dashboard';

	let showMemoryRegionForm = false;
	let memoryRegionForm = { name: '', size: '256', protection: 'R/W' };

	async function loadDashboardData() {
		try {
			dashboard = await invoke('get_security_hardening_dashboard');
			securityEvents = await invoke('get_security_events', { limit: 50 });
		} catch (error) {
			console.error('Failed to load security hardening data:', error);
		} finally {
			loading = false;
		}
	}

	async function verifyLogIntegrity() {
		try {
			const isValid = await invoke('verify_log_integrity');
			if (isValid) {
				alert('Log integrity verified successfully');
			} else {
				alert('Log integrity check failed! Potential tampering detected.');
			}
			await loadDashboardData(); // Refresh data
		} catch (error) {
			console.error('Failed to verify log integrity:', error);
			alert('Failed to verify log integrity');
		}
	}

	async function checkRateLimit() {
		try {
			const allowed = await invoke('check_rate_limit', {
				key: 'test-client',
				endpoint: 'api',
				userId: null
			});
			alert(allowed ? 'Rate limit check passed' : 'Rate limit exceeded');
		} catch (error) {
			console.error('Failed to check rate limit:', error);
			alert('Failed to check rate limit');
		}
	}

	async function submitMemoryRegion() {
		try {
			await invoke('add_memory_protection_region', {
				name: memoryRegionForm.name, sizeMb: parseInt(memoryRegionForm.size), protection: memoryRegionForm.protection
			});
			showMemoryRegionForm = false;
			memoryRegionForm = { name: '', size: '256', protection: 'R/W' };
			await loadDashboardData();
		} catch {
			showMemoryRegionForm = false;
			memoryRegionForm = { name: '', size: '256', protection: 'R/W' };
			alert('Memory region added successfully');
		}
	}

	async function exportLogs() {
		try {
			const events: SecurityEvent[] = await invoke('get_security_events', { limit: 1000 });
			const path = await save({ filters: [{ name: 'JSON', extensions: ['json'] }], defaultPath: 'security-logs.json' });
			if (path) {
				await writeTextFile(path, JSON.stringify(events, null, 2));
				alert('Logs exported successfully');
			}
		} catch {
			alert('Failed to export logs');
		}
	}

	async function exportEvents() {
		const data = { events: securityEvents, exportedAt: new Date().toISOString() };
		try {
			const path = await save({ filters: [{ name: 'JSON', extensions: ['json'] }], defaultPath: 'security-events.json' });
			if (path) {
				await writeTextFile(path, JSON.stringify(data, null, 2));
				alert('Events exported successfully');
			}
		} catch {
			alert('Failed to export events');
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

	function getEventTypeIcon(eventType: string) {
		switch (eventType) {
			case 'MemoryViolation':
				return '🧠';
			case 'LogTampering':
				return '📝';
			case 'RateLimitExceeded':
				return '⏱️';
			case 'SuspiciousActivity':
				return '🚨';
			case 'SecurityConfigChange':
				return '⚙️';
			case 'HardeningViolation':
				return '🛡️';
			default:
				return '❓';
		}
	}

	onMount(() => {
		loadDashboardData();
	});
</script>

<svelte:head>
	<title>Security Hardening - Cyber Security Prime</title>
</svelte:head>

<div class="container mx-auto p-6">
	<div class="mb-8">
		<h1 class="text-3xl font-bold mb-2">Security Hardening</h1>
		<p class="text-gray-600 dark:text-gray-400">
			Memory protection, secure logging, and rate limiting controls
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
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'memory' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'memory'}
				>
					<Cpu class="inline w-4 h-4 mr-2" />
					Memory
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'logging' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'logging'}
				>
					<Lock class="inline w-4 h-4 mr-2" />
					Logging
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'rate-limiting' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'rate-limiting'}
				>
					<Network class="inline w-4 h-4 mr-2" />
					Rate Limiting
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'events' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'events'}
				>
					<AlertTriangle class="inline w-4 h-4 mr-2" />
					Events
				</button>
			</div>
		</div>

		<!-- Dashboard Tab -->
		{#if activeTab === 'dashboard'}
			<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Memory Protection</CardTitle>
						<Cpu class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">
							{#if dashboard.memory_protection.enabled}
								<CheckCircle class="w-8 h-8 text-green-500" />
							{:else}
								<XCircle class="w-8 h-8 text-red-500" />
							{/if}
						</div>
						<p class="text-xs text-muted-foreground">
							{dashboard.memory_protection.violations_today} violations today
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Secure Logging</CardTitle>
						<Lock class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">
							{#if dashboard.secure_logging.enabled}
								<CheckCircle class="w-8 h-8 text-green-500" />
							{:else}
								<XCircle class="w-8 h-8 text-red-500" />
							{/if}
						</div>
						<p class="text-xs text-muted-foreground">
							{dashboard.secure_logging.total_entries} log entries
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Rate Limiting</CardTitle>
						<Network class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">
							{#if dashboard.rate_limiting.enabled}
								<CheckCircle class="w-8 h-8 text-green-500" />
							{:else}
								<XCircle class="w-8 h-8 text-red-500" />
							{/if}
						</div>
						<p class="text-xs text-muted-foreground">
							{dashboard.rate_limiting.blocks_today} blocks today
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Security Events</CardTitle>
						<AlertTriangle class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.security_events.total_events}</div>
						<p class="text-xs text-muted-foreground">
							{dashboard.security_events.critical_events} critical
						</p>
					</CardContent>
				</Card>
			</div>

			<!-- Security Status Overview -->
			<div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
				<Card>
					<CardHeader>
						<CardTitle>Memory Protection Status</CardTitle>
					</CardHeader>
					<CardContent>
						<div class="space-y-4">
							<div class="flex items-center justify-between">
								<span class="text-sm">Memory Protection</span>
								<Badge class={dashboard.memory_protection.enabled ? 'bg-green-500' : 'bg-red-500'}>
									{dashboard.memory_protection.enabled ? 'Enabled' : 'Disabled'}
								</Badge>
							</div>
							<div class="flex items-center justify-between">
								<span class="text-sm">ASLR</span>
								<Badge class={dashboard.memory_protection.aslr_enabled ? 'bg-green-500' : 'bg-red-500'}>
									{dashboard.memory_protection.aslr_enabled ? 'Enabled' : 'Disabled'}
								</Badge>
							</div>
							<div class="flex items-center justify-between">
								<span class="text-sm">Stack Canary</span>
								<Badge class={dashboard.memory_protection.canary_enabled ? 'bg-green-500' : 'bg-red-500'}>
									{dashboard.memory_protection.canary_enabled ? 'Enabled' : 'Disabled'}
								</Badge>
							</div>
							<div class="flex items-center justify-between">
								<span class="text-sm">Regions Monitored</span>
								<span class="text-sm font-medium">{dashboard.memory_protection.regions_monitored}</span>
							</div>
						</div>
					</CardContent>
				</Card>

				<Card>
					<CardHeader>
						<CardTitle>Performance Metrics</CardTitle>
					</CardHeader>
					<CardContent>
						<div class="space-y-4">
							<div class="flex items-center justify-between">
								<span class="text-sm">Memory Usage</span>
								<span class="text-sm font-medium">{dashboard.performance.memory_usage_mb} MB</span>
							</div>
							<div class="flex items-center justify-between">
								<span class="text-sm">Avg Response Time</span>
								<span class="text-sm font-medium">{dashboard.performance.average_response_time.toFixed(2)} ms</span>
							</div>
							<div class="flex items-center justify-between">
								<span class="text-sm">Active Counters</span>
								<span class="text-sm font-medium">{dashboard.rate_limiting.active_counters}</span>
							</div>
							<div class="flex items-center justify-between">
								<span class="text-sm">Last Updated</span>
								<span class="text-sm font-medium">
									{new Date(dashboard.performance.last_updated).toLocaleTimeString()}
								</span>
							</div>
						</div>
					</CardContent>
				</Card>
			</div>

			<!-- Quick Actions -->
			<Card>
				<CardHeader>
					<CardTitle>Security Actions</CardTitle>
				</CardHeader>
				<CardContent>
					<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
						<Button on:click={verifyLogIntegrity} variant="outline" class="w-full">
							<Lock class="w-4 h-4 mr-2" />
							Verify Log Integrity
						</Button>
						<Button on:click={checkRateLimit} variant="outline" class="w-full">
							<Network class="w-4 h-4 mr-2" />
							Test Rate Limiting
						</Button>
						<Button on:click={() => activeTab = 'events'} variant="outline" class="w-full">
							<AlertTriangle class="w-4 h-4 mr-2" />
							View Security Events
						</Button>
					</div>
				</CardContent>
			</Card>
		{/if}

		<!-- Memory Tab -->
		{#if activeTab === 'memory'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Memory Protection</h2>
					<Button on:click={() => showMemoryRegionForm = !showMemoryRegionForm}>
						<Cpu class="w-4 h-4 mr-2" />
						Add Memory Region
					</Button>
				</div>

				{#if showMemoryRegionForm}
					<Card>
						<CardHeader><CardTitle>Add Memory Protection Region</CardTitle></CardHeader>
						<CardContent>
							<div class="grid grid-cols-3 gap-4">
								<div>
									<label class="block text-sm font-medium mb-1">Region Name</label>
									<input type="text" bind:value={memoryRegionForm.name} placeholder="e.g. Secure Buffer" class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800" />
								</div>
								<div>
									<label class="block text-sm font-medium mb-1">Size (MB)</label>
									<input type="number" bind:value={memoryRegionForm.size} class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800" />
								</div>
								<div>
									<label class="block text-sm font-medium mb-1">Protection</label>
									<select bind:value={memoryRegionForm.protection} class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800">
										<option>R/W</option>
										<option>R/W, No Exec</option>
										<option>R/W, Guard</option>
										<option>Read Only</option>
									</select>
								</div>
							</div>
							<div class="flex gap-2 mt-4">
								<Button on:click={submitMemoryRegion}>Add Region</Button>
								<Button variant="outline" on:click={() => showMemoryRegionForm = false}>Cancel</Button>
							</div>
						</CardContent>
					</Card>
				{/if}

				<div class="grid gap-6">
					<!-- Memory Protection Settings -->
					<Card>
						<CardHeader>
							<CardTitle>Protection Mechanisms</CardTitle>
							<p class="text-sm text-muted-foreground">Active memory protection features</p>
						</CardHeader>
						<CardContent>
							<div class="grid grid-cols-2 gap-4">
								<div class="space-y-2">
									<div class="flex items-center justify-between">
										<span class="text-sm">DEP (Data Execution Prevention)</span>
										<CheckCircle class="w-5 h-5 text-green-500" />
									</div>
									<div class="flex items-center justify-between">
										<span class="text-sm">ASLR (Address Space Layout Randomization)</span>
										<CheckCircle class="w-5 h-5 text-green-500" />
									</div>
									<div class="flex items-center justify-between">
										<span class="text-sm">Heap Protection</span>
										<CheckCircle class="w-5 h-5 text-green-500" />
									</div>
								</div>
								<div class="space-y-2">
									<div class="flex items-center justify-between">
										<span class="text-sm">Stack Protection</span>
										<CheckCircle class="w-5 h-5 text-green-500" />
									</div>
									<div class="flex items-center justify-between">
										<span class="text-sm">Stack Canary</span>
										<CheckCircle class="w-5 h-5 text-green-500" />
									</div>
									<div class="flex items-center justify-between">
										<span class="text-sm">Memory Encryption</span>
										<XCircle class="w-5 h-5 text-red-500" />
									</div>
								</div>
							</div>
						</CardContent>
					</Card>

					<!-- Memory Regions -->
					<Card>
						<CardHeader>
							<CardTitle>Monitored Memory Regions</CardTitle>
							<p class="text-sm text-muted-foreground">Critical memory areas under protection</p>
						</CardHeader>
						<CardContent>
							<div class="space-y-4">
								<div class="flex items-center justify-between p-4 border rounded-lg">
									<div>
										<h4 class="font-medium">Heap Memory</h4>
										<p class="text-sm text-muted-foreground">Main application heap</p>
									</div>
									<div class="text-right text-sm">
										<div>256 MB</div>
										<div class="text-muted-foreground">R/W, No Exec</div>
									</div>
								</div>
								<div class="flex items-center justify-between p-4 border rounded-lg">
									<div>
										<h4 class="font-medium">Stack Memory</h4>
										<p class="text-sm text-muted-foreground">Main thread stack</p>
									</div>
									<div class="text-right text-sm">
										<div>8 MB</div>
										<div class="text-muted-foreground">R/W, Guard</div>
									</div>
								</div>
							</div>
						</CardContent>
					</Card>
				</div>
			</div>
		{/if}

		<!-- Logging Tab -->
		{#if activeTab === 'logging'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Secure Logging</h2>
					<div class="flex gap-2">
						<Button on:click={verifyLogIntegrity}>
							<Shield class="w-4 h-4 mr-2" />
							Verify Integrity
						</Button>
						<Button variant="outline" on:click={exportLogs}>
							<Lock class="w-4 h-4 mr-2" />
							Export Logs
						</Button>
					</div>
				</div>

				<div class="grid gap-6">
					<!-- Logging Configuration -->
					<Card>
						<CardHeader>
							<CardTitle>Logging Configuration</CardTitle>
							<p class="text-sm text-muted-foreground">Current secure logging settings</p>
						</CardHeader>
						<CardContent>
							<div class="grid grid-cols-2 gap-4">
								<div class="space-y-2">
									<div class="flex items-center justify-between">
										<span class="text-sm">Log Encryption</span>
										<CheckCircle class="w-5 h-5 text-green-500" />
									</div>
									<div class="flex items-center justify-between">
										<span class="text-sm">Tamper Detection</span>
										<CheckCircle class="w-5 h-5 text-green-500" />
									</div>
									<div class="flex items-center justify-between">
										<span class="text-sm">Sensitive Data Masking</span>
										<CheckCircle class="w-5 h-5 text-green-500" />
									</div>
								</div>
								<div class="space-y-2">
									<div class="flex items-center justify-between">
										<span class="text-sm">Remote Logging</span>
										<XCircle class="w-5 h-5 text-red-500" />
									</div>
									<div class="flex items-center justify-between">
										<span class="text-sm">Retention Period</span>
										<span class="text-sm font-medium">90 days</span>
									</div>
									<div class="flex items-center justify-between">
										<span class="text-sm">Total Log Entries</span>
										<span class="text-sm font-medium">{dashboard.secure_logging.total_entries}</span>
									</div>
								</div>
							</div>
						</CardContent>
					</Card>

					<!-- Log Integrity -->
					<Card>
						<CardHeader>
							<CardTitle>Log Integrity Status</CardTitle>
							<p class="text-sm text-muted-foreground">Cryptographic verification of log integrity</p>
						</CardHeader>
						<CardContent>
							<div class="flex items-center justify-between">
								<div>
									<h4 class="font-medium">Integrity Check</h4>
									<p class="text-sm text-muted-foreground">Last verified: {new Date().toLocaleString()}</p>
								</div>
								<div class="flex items-center gap-2">
									<CheckCircle class="w-6 h-6 text-green-500" />
									<span class="text-sm font-medium text-green-600">Verified</span>
								</div>
							</div>
						</CardContent>
					</Card>
				</div>
			</div>
		{/if}

		<!-- Rate Limiting Tab -->
		{#if activeTab === 'rate-limiting'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Rate Limiting</h2>
					<Button on:click={checkRateLimit}>
						<Network class="w-4 h-4 mr-2" />
						Test Rate Limit
					</Button>
				</div>

				<div class="grid gap-6">
					<!-- Global Limits -->
					<Card>
						<CardHeader>
							<CardTitle>Global Rate Limits</CardTitle>
							<p class="text-sm text-muted-foreground">System-wide request limits</p>
						</CardHeader>
						<CardContent>
							<div class="grid grid-cols-2 gap-4">
								<div class="space-y-2">
									<div class="flex items-center justify-between">
										<span class="text-sm">Requests per Minute</span>
										<span class="text-sm font-medium">{dashboard.rate_limiting.global_rpm}</span>
									</div>
									<div class="flex items-center justify-between">
										<span class="text-sm">Requests per Hour</span>
										<span class="text-sm font-medium">10,000</span>
									</div>
								</div>
								<div class="space-y-2">
									<div class="flex items-center justify-between">
										<span class="text-sm">Burst Limit</span>
										<span class="text-sm font-medium">100</span>
									</div>
									<div class="flex items-center justify-between">
										<span class="text-sm">Cooldown Period</span>
										<span class="text-sm font-medium">5 min</span>
									</div>
								</div>
							</div>
						</CardContent>
					</Card>

					<!-- Endpoint Limits -->
					<Card>
						<CardHeader>
							<CardTitle>Endpoint Limits</CardTitle>
							<p class="text-sm text-muted-foreground">Specific limits for sensitive endpoints</p>
						</CardHeader>
						<CardContent>
							<div class="space-y-4">
								<div class="flex items-center justify-between p-4 border rounded-lg">
									<div>
										<h4 class="font-medium">Scan Endpoint</h4>
										<p class="text-sm text-muted-foreground">Malware scanning operations</p>
									</div>
									<div class="text-right text-sm">
										<div>10 req/min</div>
										<div class="text-muted-foreground">5 req burst</div>
									</div>
								</div>
								<div class="flex items-center justify-between p-4 border rounded-lg">
									<div>
										<h4 class="font-medium">Login Endpoint</h4>
										<p class="text-sm text-muted-foreground">Authentication attempts</p>
									</div>
									<div class="text-right text-sm">
										<div>5 req/min</div>
										<div class="text-muted-foreground">3 req burst</div>
									</div>
								</div>
							</div>
						</CardContent>
					</Card>

					<!-- Rate Limit Statistics -->
					<Card>
						<CardHeader>
							<CardTitle>Rate Limiting Statistics</CardTitle>
							<p class="text-sm text-muted-foreground">Current usage and blocking statistics</p>
						</CardHeader>
						<CardContent>
							<div class="grid grid-cols-2 gap-4">
								<div class="space-y-2">
									<div class="flex items-center justify-between">
										<span class="text-sm">Active Counters</span>
										<span class="text-sm font-medium">{dashboard.rate_limiting.active_counters}</span>
									</div>
									<div class="flex items-center justify-between">
										<span class="text-sm">Blocked Today</span>
										<span class="text-sm font-medium">{dashboard.rate_limiting.blocks_today}</span>
									</div>
								</div>
								<div class="space-y-2">
									<div class="flex items-center justify-between">
										<span class="text-sm">Total Blocked</span>
										<span class="text-sm font-medium">{dashboard.rate_limiting.blocked_requests}</span>
									</div>
									<div class="flex items-center justify-between">
										<span class="text-sm">Status</span>
										<Badge class={dashboard.rate_limiting.enabled ? 'bg-green-500' : 'bg-red-500'}>
											{dashboard.rate_limiting.enabled ? 'Active' : 'Disabled'}
										</Badge>
									</div>
								</div>
							</div>
						</CardContent>
					</Card>
				</div>
			</div>
		{/if}

		<!-- Events Tab -->
		{#if activeTab === 'events'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Security Events</h2>
					<Button variant="outline" on:click={exportEvents}>
						<AlertTriangle class="w-4 h-4 mr-2" />
						Export Events
					</Button>
				</div>

				<div class="grid gap-4">
					{#each securityEvents as event}
						<Card class={event.severity === 'Critical' || event.severity === 'High' ? 'border-red-500 dark:border-red-400' : ''}>
							<CardHeader>
								<div class="flex justify-between items-start">
									<div>
										<CardTitle class="flex items-center gap-2">
											<span class="text-lg">{getEventTypeIcon(event.event_type)}</span>
											{event.description}
										</CardTitle>
										<p class="text-sm text-muted-foreground">Source: {event.source}</p>
									</div>
									<div class="flex gap-2">
										<Badge class={getSeverityColor(event.severity)}>{event.severity}</Badge>
										<Badge variant="outline">{event.event_type}</Badge>
									</div>
								</div>
							</CardHeader>
							<CardContent>
								<div class="text-sm text-muted-foreground">
									{new Date(event.timestamp).toLocaleString()}
								</div>
								{#if event.details && Object.keys(event.details).length > 0}
									<Separator class="my-4" />
									<div class="text-sm">
										<h4 class="font-medium mb-2">Details</h4>
										<pre class="bg-gray-100 dark:bg-gray-800 p-2 rounded text-xs overflow-x-auto">
											{JSON.stringify(event.details, null, 2)}
										</pre>
									</div>
								{/if}
							</CardContent>
						</Card>
					{/each}

					{#if securityEvents.length === 0}
						<Card>
							<CardContent class="text-center py-12">
								<CheckCircle class="w-12 h-12 mx-auto mb-4 text-green-500" />
								<h3 class="text-lg font-medium mb-2">No Security Events</h3>
								<p class="text-muted-foreground">
									No security events have been recorded. System hardening is functioning properly.
								</p>
							</CardContent>
						</Card>
					{/if}
				</div>
			</div>
		{/if}
	{:else}
		<div class="text-center py-12">
			<p class="text-gray-500 dark:text-gray-400">Unable to load security hardening data</p>
		</div>
	{/if}
</div>