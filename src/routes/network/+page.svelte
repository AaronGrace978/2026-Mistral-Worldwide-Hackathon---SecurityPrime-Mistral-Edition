<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { ScrollArea } from '$lib/components/ui/scroll-area';
	import { cn, formatBytes } from '$lib/utils';
	import * as api from '$lib/api';
	import { 
		Network, 
		Activity,
		ArrowUpRight,
		ArrowDownLeft,
		RefreshCw,
		AlertTriangle,
		Globe,
		Wifi,
		Ban,
		CheckCircle
	} from 'lucide-svelte';

	let connections: api.NetworkConnection[] = [];
	let stats: api.NetworkStats | null = null;
	let loading = true;
	let refreshInterval: ReturnType<typeof setInterval>;

	onMount(async () => {
		await loadData();
		// Auto-refresh every 5 seconds
		refreshInterval = setInterval(loadData, 5000);
	});

	onDestroy(() => {
		if (refreshInterval) clearInterval(refreshInterval);
	});

	async function loadData() {
		try {
			[connections, stats] = await Promise.all([
				api.getNetworkConnections(),
				api.getNetworkStats()
			]);
		} catch (error) {
			console.error('Failed to load network data:', error);
		} finally {
			loading = false;
		}
	}

	function isSuspicious(connection: api.NetworkConnection): boolean {
		return connection.process_name === 'unknown.exe' || 
			   connection.remote_port === 8080 ||
			   connection.process_id > 50000;
	}
</script>

<svelte:head>
	<title>Network Monitor - Cyber Security Prime</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-3">
			<div class="flex items-center justify-center w-12 h-12 rounded-xl bg-cyber-blue/10">
				<Network class="w-6 h-6 text-cyber-blue" />
			</div>
			<div>
				<h1 class="text-2xl font-bold tracking-tight text-foreground">
					Network Monitor
				</h1>
				<p class="text-muted-foreground">
					Monitor network connections and traffic in real-time
				</p>
			</div>
		</div>
		<div class="flex items-center gap-2">
			<div class="flex items-center gap-2 text-sm text-neon-green">
				<div class="w-2 h-2 rounded-full bg-neon-green animate-pulse" />
				Live Monitoring
			</div>
			<Button variant="outline" size="sm" on:click={loadData}>
				<RefreshCw class="w-4 h-4 mr-2" />
				Refresh
			</Button>
		</div>
	</div>

	{#if loading}
		<div class="flex items-center justify-center h-64">
			<div class="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
		</div>
	{:else}
		<div class="grid grid-cols-12 gap-6">
			<!-- Stats Row -->
			<div class="col-span-12">
				<div class="grid grid-cols-6 gap-4">
					<Card variant="glass">
						<CardContent class="pt-6">
							<div class="flex items-center gap-2 mb-2">
								<Wifi class="w-4 h-4 text-primary" />
								<span class="text-xs text-muted-foreground">Active</span>
							</div>
							<p class="text-2xl font-bold">{stats?.active_connections ?? 0}</p>
						</CardContent>
					</Card>
					<Card variant="glass">
						<CardContent class="pt-6">
							<div class="flex items-center gap-2 mb-2">
								<Globe class="w-4 h-4 text-primary" />
								<span class="text-xs text-muted-foreground">Total</span>
							</div>
							<p class="text-2xl font-bold">{stats?.total_connections ?? 0}</p>
						</CardContent>
					</Card>
					<Card variant="glass">
						<CardContent class="pt-6">
							<div class="flex items-center gap-2 mb-2">
								<ArrowUpRight class="w-4 h-4 text-neon-green" />
								<span class="text-xs text-muted-foreground">Upload</span>
							</div>
							<p class="text-xl font-bold">{formatBytes(stats?.bytes_sent_per_sec ?? 0)}/s</p>
						</CardContent>
					</Card>
					<Card variant="glass">
						<CardContent class="pt-6">
							<div class="flex items-center gap-2 mb-2">
								<ArrowDownLeft class="w-4 h-4 text-cyber-blue" />
								<span class="text-xs text-muted-foreground">Download</span>
							</div>
							<p class="text-xl font-bold">{formatBytes(stats?.bytes_received_per_sec ?? 0)}/s</p>
						</CardContent>
					</Card>
					<Card variant="glass" class="border-neon-red/30">
						<CardContent class="pt-6">
							<div class="flex items-center gap-2 mb-2">
								<Ban class="w-4 h-4 text-neon-red" />
								<span class="text-xs text-muted-foreground">Blocked</span>
							</div>
							<p class="text-2xl font-bold text-neon-red">{stats?.blocked_connections ?? 0}</p>
						</CardContent>
					</Card>
					<Card variant="glass" class="border-neon-yellow/30">
						<CardContent class="pt-6">
							<div class="flex items-center gap-2 mb-2">
								<AlertTriangle class="w-4 h-4 text-neon-yellow" />
								<span class="text-xs text-muted-foreground">Suspicious</span>
							</div>
							<p class="text-2xl font-bold text-neon-yellow">{stats?.suspicious_connections ?? 0}</p>
						</CardContent>
					</Card>
				</div>
			</div>

			<!-- Connections List -->
			<div class="col-span-12">
				<Card variant="glass">
					<CardHeader>
						<div class="flex items-center justify-between">
							<div>
								<CardTitle>Active Connections</CardTitle>
								<CardDescription>
									Real-time view of all network connections
								</CardDescription>
							</div>
							<Badge variant="outline" class="gap-1">
								<Activity class="w-3 h-3" />
								{connections.length} connections
							</Badge>
						</div>
					</CardHeader>
					<CardContent>
						<ScrollArea class="max-h-[500px]">
							<div class="space-y-2">
								<!-- Header Row -->
								<div class="grid grid-cols-12 gap-4 px-4 py-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">
									<div class="col-span-2">Process</div>
									<div class="col-span-2">Local</div>
									<div class="col-span-2">Remote</div>
									<div class="col-span-1">Protocol</div>
									<div class="col-span-1">State</div>
									<div class="col-span-2">Traffic</div>
									<div class="col-span-2">Status</div>
								</div>

								{#each connections as conn}
									{@const suspicious = isSuspicious(conn)}
									<div class={cn(
										'grid grid-cols-12 gap-4 px-4 py-3 rounded-lg items-center',
										suspicious 
											? 'bg-neon-red/5 border border-neon-red/30' 
											: 'bg-muted/30 hover:bg-muted/50'
									)}>
										<div class="col-span-2">
											<p class="font-medium text-sm truncate">{conn.process_name}</p>
											<p class="text-xs text-muted-foreground">PID: {conn.process_id}</p>
										</div>
										<div class="col-span-2">
											<p class="font-mono text-xs">{conn.local_address}</p>
											<p class="text-xs text-muted-foreground">:{conn.local_port}</p>
										</div>
										<div class="col-span-2">
											<p class="font-mono text-xs">{conn.remote_address}</p>
											<p class="text-xs text-muted-foreground">:{conn.remote_port}</p>
										</div>
										<div class="col-span-1">
											<Badge variant="secondary" class="text-xs">
												{conn.protocol}
											</Badge>
										</div>
										<div class="col-span-1">
											<Badge 
												variant={conn.state === 'ESTABLISHED' ? 'success' : 'outline'} 
												class="text-[10px]"
											>
												{conn.state}
											</Badge>
										</div>
										<div class="col-span-2 text-xs">
											<div class="flex items-center gap-1 text-neon-green">
												<ArrowUpRight class="w-3 h-3" />
												{formatBytes(conn.bytes_sent)}
											</div>
											<div class="flex items-center gap-1 text-cyber-blue">
												<ArrowDownLeft class="w-3 h-3" />
												{formatBytes(conn.bytes_received)}
											</div>
										</div>
										<div class="col-span-2">
											{#if suspicious}
												<Badge variant="danger" class="gap-1">
													<AlertTriangle class="w-3 h-3" />
													Suspicious
												</Badge>
											{:else}
												<Badge variant="success" class="gap-1">
													<CheckCircle class="w-3 h-3" />
													Safe
												</Badge>
											{/if}
										</div>
									</div>
								{/each}
							</div>
						</ScrollArea>
					</CardContent>
				</Card>
			</div>
		</div>
	{/if}
</div>

