<script lang="ts">
	import { onMount } from 'svelte';
	import { securityScore, activities, alerts, moduleStatuses } from '$lib/stores/security';
	import SecurityScoreCard from '$lib/components/SecurityScoreCard.svelte';
	import StatusCard from '$lib/components/StatusCard.svelte';
	import ActivityLog from '$lib/components/ActivityLog.svelte';
	import ThreatAlert from '$lib/components/ThreatAlert.svelte';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import {
		Shield,
		Flame,
		Lock,
		RefreshCw,
		Activity,
		Cpu,
		HardDrive,
		Wifi,
		Bot,
		Sparkles,
		Zap,
		ArrowRight,
		Brain,
		Eye,
		Rocket
	} from 'lucide-svelte';
	import * as api from '$lib/api';

	let loading = true;
	let systemInfo: api.SystemInfo | null = null;

	onMount(async () => {
		try {
			systemInfo = await api.getSystemInfo();
		} catch (error) {
			console.error('Failed to load system info:', error);
		} finally {
			loading = false;
		}
	});

	async function refreshData() {
		loading = true;
		try {
			await Promise.all([
				securityScore.fetch(),
				activities.fetch(10),
				alerts.fetch(),
				moduleStatuses.fetch()
			]);
		} finally {
			loading = false;
		}
	}

	function handleResolveAlert(event: CustomEvent<{ id: string }>) {
		alerts.resolve(event.detail.id);
	}

	function handleDismissAlert(event: CustomEvent<{ id: string }>) {
		alerts.remove(event.detail.id);
	}

	$: scannerStatus = $moduleStatuses.find(m => m.name === 'scanner');
	$: firewallStatus = $moduleStatuses.find(m => m.name === 'firewall');
	$: encryptionStatus = $moduleStatuses.find(m => m.name === 'encryption');
	$: networkStatus = $moduleStatuses.find(m => m.name === 'network');
</script>

<svelte:head>
	<title>Dashboard - Cyber Security Prime</title>
</svelte:head>

<div class="space-y-6">
	<!-- Hero Header -->
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold tracking-tight text-foreground flex items-center gap-3">
				Security Dashboard
				<Badge variant="outline" class="text-[10px] font-mono tracking-wider border-orange-500/40 text-orange-400">
					MISTRAL-POWERED
				</Badge>
			</h1>
			<p class="text-muted-foreground mt-1">
				Real-time system protection with AI-driven threat analysis
			</p>
		</div>
		<Button
			variant="outline"
			class="gap-2"
			on:click={refreshData}
			disabled={loading}
		>
			<RefreshCw class="w-4 h-4 {loading ? 'animate-spin' : ''}" />
			Refresh
		</Button>
	</div>

	<!-- System Info Bar -->
	{#if systemInfo}
		<Card variant="glass" class="border-primary/20">
			<CardContent class="py-3">
				<div class="flex items-center justify-between text-sm">
					<div class="flex items-center gap-6">
						<div class="flex items-center gap-2">
							<Cpu class="w-4 h-4 text-primary" />
							<span class="text-muted-foreground">Host:</span>
							<span class="font-medium">{systemInfo.hostname}</span>
						</div>
						<div class="flex items-center gap-2">
							<HardDrive class="w-4 h-4 text-primary" />
							<span class="text-muted-foreground">OS:</span>
							<span class="font-medium">{systemInfo.os_name} {systemInfo.os_version}</span>
						</div>
						<div class="flex items-center gap-2">
							<Activity class="w-4 h-4 text-primary" />
							<span class="text-muted-foreground">Cores:</span>
							<span class="font-medium">{systemInfo.cpu_cores}</span>
						</div>
						<div class="flex items-center gap-2">
							<Wifi class="w-4 h-4 text-neon-green" />
							<span class="font-medium text-neon-green">Connected</span>
						</div>
					</div>
					<Badge variant="success" class="gap-1">
						<div class="w-1.5 h-1.5 rounded-full bg-neon-green animate-pulse" />
						Protection Active
					</Badge>
				</div>
			</CardContent>
		</Card>
	{/if}

	<!-- Main Grid -->
	<div class="grid grid-cols-12 gap-6">
		<!-- Security Score -->
		<div class="col-span-12 lg:col-span-4">
			<SecurityScoreCard score={$securityScore} {loading} />
		</div>

		<!-- Status Cards -->
		<div class="col-span-12 lg:col-span-8">
			<div class="grid grid-cols-2 gap-4">
				<StatusCard
					title="Malware Scanner"
					description="Real-time protection"
					status={scannerStatus?.status === 'active' ? 'active' : 'inactive'}
					icon={Shield}
					value={scannerStatus?.enabled ? 'On' : 'Off'}
					href="/scanner"
				/>
				<StatusCard
					title="Firewall"
					description="Network protection"
					status={firewallStatus?.status === 'active' ? 'active' : 'inactive'}
					icon={Flame}
					value={firewallStatus?.enabled ? 'On' : 'Off'}
					href="/firewall"
				/>
				<StatusCard
					title="Encryption"
					description="Data protection"
					status={encryptionStatus?.status === 'active' ? 'active' : 'inactive'}
					icon={Lock}
					value={encryptionStatus?.enabled ? 'On' : 'Off'}
					href="/encryption"
				/>
				<StatusCard
					title="Network Monitor"
					description="Connection tracking"
					status={networkStatus?.status === 'active' ? 'active' : 'inactive'}
					icon={Wifi}
					value={networkStatus?.enabled ? 'On' : 'Off'}
					href="/network"
				/>
			</div>
		</div>

		<!-- AI Insight Card -->
		<div class="col-span-12">
			<Card variant="glass" class="border-orange-500/20 overflow-hidden relative">
				<div class="absolute inset-0 opacity-[0.03] pointer-events-none"
					style="background: radial-gradient(circle at 20% 50%, #ff7300 0%, transparent 50%), radial-gradient(circle at 80% 50%, #ff9900 0%, transparent 50%);"
				/>
				<CardContent class="py-5">
					<div class="flex items-center gap-6">
						<div class="flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-orange-500 to-amber-500 flex-shrink-0">
							<Brain class="w-7 h-7 text-white" />
						</div>
						<div class="flex-1 min-w-0">
							<div class="flex items-center gap-2 mb-1">
								<h3 class="text-base font-semibold">Mistral Security Copilot</h3>
								<Badge variant="outline" class="text-[9px] border-orange-500/30 text-orange-400 font-mono">AI</Badge>
							</div>
							<p class="text-sm text-muted-foreground">
								Multi-model AI analysis using Mistral Large for deep threat assessment, Ministral for fast triage,
								Devstral for remediation scripting, and Pixtral for visual inspection.
							</p>
						</div>
						<div class="flex items-center gap-3 flex-shrink-0">
							<div class="text-right mr-2">
								<div class="flex items-center gap-2 text-xs text-muted-foreground">
									<div class="flex -space-x-1">
										<div class="w-5 h-5 rounded-full bg-orange-500/20 border border-orange-500/30 flex items-center justify-center"><Brain class="w-2.5 h-2.5 text-orange-400" /></div>
										<div class="w-5 h-5 rounded-full bg-yellow-500/20 border border-yellow-500/30 flex items-center justify-center"><Zap class="w-2.5 h-2.5 text-yellow-400" /></div>
										<div class="w-5 h-5 rounded-full bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center"><Sparkles class="w-2.5 h-2.5 text-emerald-400" /></div>
										<div class="w-5 h-5 rounded-full bg-violet-500/20 border border-violet-500/30 flex items-center justify-center"><Eye class="w-2.5 h-2.5 text-violet-400" /></div>
									</div>
									<span>4 models available</span>
								</div>
							</div>
							<Button variant="cyber" class="gap-2" href="/agent">
								<Bot class="w-4 h-4" />
								Open Copilot
								<ArrowRight class="w-4 h-4" />
							</Button>
						</div>
					</div>
				</CardContent>
			</Card>
		</div>

		<!-- Activity Log -->
		<div class="col-span-12 lg:col-span-6">
			<ActivityLog activities={$activities} maxHeight="350px" />
		</div>

		<!-- Threat Alerts -->
		<div class="col-span-12 lg:col-span-6">
			<ThreatAlert
				alerts={$alerts}
				maxHeight="350px"
				on:resolve={handleResolveAlert}
				on:dismiss={handleDismissAlert}
			/>
		</div>
	</div>

	<!-- Quick Actions -->
	<Card variant="glass">
		<CardHeader class="pb-3">
			<CardTitle class="text-lg">Quick Actions</CardTitle>
		</CardHeader>
		<CardContent>
			<div class="flex flex-wrap gap-3">
				<Button variant="cyber" class="gap-2" href="/scanner">
					<Shield class="w-4 h-4" />
					Run Quick Scan
				</Button>
				<Button variant="outline" class="gap-2" href="/vulnerability">
					Check Vulnerabilities
				</Button>
				<Button variant="outline" class="gap-2" href="/encryption">
					Encrypt Files
				</Button>
				<Button variant="outline" class="gap-2" href="/agent">
					<Bot class="w-4 h-4" />
					AI Security Audit
				</Button>
				<Button variant="outline" class="gap-2" href="/flagship">
					<Rocket class="w-4 h-4" />
					Flagship Program
				</Button>
				<Button variant="outline" class="gap-2" href="/settings">
					Configure Settings
				</Button>
			</div>
		</CardContent>
	</Card>
</div>
