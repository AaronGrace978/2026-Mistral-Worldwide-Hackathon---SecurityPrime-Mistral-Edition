<script lang="ts">
	import { onMount } from 'svelte';
	import { getDashboardSummary, getAlerts, type DashboardSummary, type Alert } from '$lib/api';
	import { 
		Building2, 
		Monitor, 
		AlertTriangle, 
		Shield,
		TrendingUp,
		Activity,
		CheckCircle,
		XCircle
	} from 'lucide-svelte';

	let summary: DashboardSummary | null = null;
	let recentAlerts: Alert[] = [];
	let loading = true;
	let error: string | null = null;

	onMount(async () => {
		try {
			const [summaryData, alertsData] = await Promise.all([
				getDashboardSummary(),
				getAlerts()
			]);
			summary = summaryData;
			recentAlerts = alertsData.slice(0, 5);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load dashboard';
		} finally {
			loading = false;
		}
	});

	function getSeverityColor(severity: string) {
		switch (severity) {
			case 'critical': return 'text-red-500';
			case 'high': return 'text-orange-500';
			case 'medium': return 'text-yellow-500';
			default: return 'text-blue-500';
		}
	}

	function getStatusColor(status: string) {
		switch (status) {
			case 'online': return 'text-green-500';
			case 'offline': return 'text-gray-500';
			case 'warning': return 'text-yellow-500';
			case 'critical': return 'text-red-500';
			default: return 'text-gray-500';
		}
	}
</script>

<svelte:head>
	<title>Dashboard - Security Prime MSP</title>
</svelte:head>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-bold">Dashboard</h1>
		<p class="text-muted-foreground">Overview of your managed security infrastructure</p>
	</div>

	{#if loading}
		<div class="flex items-center justify-center h-64">
			<div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
		</div>
	{:else if error}
		<div class="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
			<p class="text-destructive">{error}</p>
		</div>
	{:else if summary}
		<!-- Stats Grid -->
		<div class="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
			<div class="rounded-lg border border-border bg-card p-6 glass">
				<div class="flex items-center gap-4">
					<div class="rounded-lg bg-primary/10 p-3">
						<Building2 class="h-6 w-6 text-primary" />
					</div>
					<div>
						<p class="text-sm text-muted-foreground">Organizations</p>
						<p class="text-2xl font-bold">{summary.total_organizations}</p>
					</div>
				</div>
			</div>

			<div class="rounded-lg border border-border bg-card p-6 glass">
				<div class="flex items-center gap-4">
					<div class="rounded-lg bg-green-500/10 p-3">
						<Monitor class="h-6 w-6 text-green-500" />
					</div>
					<div>
						<p class="text-sm text-muted-foreground">Endpoints</p>
						<p class="text-2xl font-bold">
							{summary.total_endpoints}
							<span class="text-sm font-normal text-muted-foreground">
								({summary.online_endpoints} online)
							</span>
						</p>
					</div>
				</div>
			</div>

			<div class="rounded-lg border border-border bg-card p-6 glass">
				<div class="flex items-center gap-4">
					<div class="rounded-lg bg-red-500/10 p-3">
						<AlertTriangle class="h-6 w-6 text-red-500" />
					</div>
					<div>
						<p class="text-sm text-muted-foreground">Critical Alerts</p>
						<p class="text-2xl font-bold">{summary.critical_alerts}</p>
					</div>
				</div>
			</div>

			<div class="rounded-lg border border-border bg-card p-6 glass">
				<div class="flex items-center gap-4">
					<div class="rounded-lg bg-blue-500/10 p-3">
						<Shield class="h-6 w-6 text-blue-500" />
					</div>
					<div>
						<p class="text-sm text-muted-foreground">Avg Security Score</p>
						<p class="text-2xl font-bold">{Math.round(summary.average_security_score)}%</p>
					</div>
				</div>
			</div>
		</div>

		<!-- Charts and Recent Activity -->
		<div class="grid gap-6 lg:grid-cols-2">
			<!-- Endpoint Status -->
			<div class="rounded-lg border border-border bg-card glass">
				<div class="border-b border-border p-4">
					<h2 class="font-semibold">Endpoint Status</h2>
				</div>
				<div class="p-6">
					<div class="space-y-4">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-2">
								<CheckCircle class="h-5 w-5 text-green-500" />
								<span>Online</span>
							</div>
							<div class="flex items-center gap-2">
								<span class="font-bold">{summary.online_endpoints}</span>
								<div class="h-2 w-32 rounded-full bg-secondary overflow-hidden">
									<div 
										class="h-full bg-green-500 transition-all"
										style="width: {(summary.online_endpoints / summary.total_endpoints * 100)}%"
									></div>
								</div>
							</div>
						</div>
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-2">
								<XCircle class="h-5 w-5 text-gray-500" />
								<span>Offline</span>
							</div>
							<div class="flex items-center gap-2">
								<span class="font-bold">{summary.offline_endpoints}</span>
								<div class="h-2 w-32 rounded-full bg-secondary overflow-hidden">
									<div 
										class="h-full bg-gray-500 transition-all"
										style="width: {(summary.offline_endpoints / summary.total_endpoints * 100)}%"
									></div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>

			<!-- Recent Alerts -->
			<div class="rounded-lg border border-border bg-card glass">
				<div class="border-b border-border p-4 flex items-center justify-between">
					<h2 class="font-semibold">Recent Alerts</h2>
					<a href="/alerts" class="text-sm text-primary hover:underline">View all</a>
				</div>
				<div class="divide-y divide-border">
					{#if recentAlerts.length === 0}
						<div class="p-6 text-center text-muted-foreground">
							No recent alerts
						</div>
					{:else}
						{#each recentAlerts as alert}
							<div class="p-4 flex items-start gap-3">
								<AlertTriangle class="h-5 w-5 {getSeverityColor(alert.severity)} shrink-0 mt-0.5" />
								<div class="flex-1 min-w-0">
									<p class="font-medium truncate">{alert.title}</p>
									<p class="text-sm text-muted-foreground truncate">{alert.description}</p>
									<p class="text-xs text-muted-foreground mt-1">
										{new Date(alert.created_at).toLocaleString()}
									</p>
								</div>
								<span class="text-xs px-2 py-1 rounded-full bg-secondary {getSeverityColor(alert.severity)}">
									{alert.severity}
								</span>
							</div>
						{/each}
					{/if}
				</div>
			</div>
		</div>
	{/if}
</div>
