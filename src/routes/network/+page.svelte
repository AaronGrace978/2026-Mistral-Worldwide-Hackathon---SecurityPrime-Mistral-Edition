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
		CheckCircle,
		ShieldCheck,
		ExternalLink,
		Download,
		Eye,
		ShieldAlert,
		Lock,
		Unlock,
		List,
		FileDown,
		Search
	} from 'lucide-svelte';

	let connections: api.NetworkConnection[] = [];
	let stats: api.NetworkStats | null = null;
	let littleSnitchStatus: api.LittleSnitchStatus | null = null;
	let lsRules: api.LittleSnitchRule[] = [];
	let domainTrust: api.DomainTrustEntry[] = [];
	let loading = true;
	let refreshInterval: ReturnType<typeof setInterval>;

	let lsTab: 'rules' | 'domains' | 'export' = 'rules';
	let rulesFilter: 'all' | 'allow' | 'deny' = 'all';
	let domainFilter: 'all' | 'trusted' | 'unknown' | 'suspicious' = 'all';
	let exporting = false;
	let exportedProfile: api.LittleSnitchRuleProfile | null = null;
	let copied = false;

	$: filteredRules = rulesFilter === 'all'
		? lsRules
		: lsRules.filter(r => r.action === rulesFilter);

	$: filteredDomains = domainFilter === 'all'
		? domainTrust
		: domainTrust.filter(d => d.trust_level === domainFilter);

	$: trustCounts = {
		trusted: domainTrust.filter(d => d.trust_level === 'trusted').length,
		unknown: domainTrust.filter(d => d.trust_level === 'unknown').length,
		suspicious: domainTrust.filter(d => d.trust_level === 'suspicious').length,
	};

	onMount(async () => {
		await loadData();
		refreshInterval = setInterval(loadData, 5000);
	});

	onDestroy(() => {
		if (refreshInterval) clearInterval(refreshInterval);
	});

	async function loadData() {
		try {
			[connections, stats, littleSnitchStatus, lsRules, domainTrust] = await Promise.all([
				api.getNetworkConnections(),
				api.getNetworkStats(),
				api.getLittleSnitchStatus(),
				api.getLittleSnitchRules().catch(() => []),
				api.getLittleSnitchDomainTrust().catch(() => []),
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

	async function handleExport() {
		exporting = true;
		try {
			exportedProfile = await api.exportLittleSnitchProfile();
		} catch (e) {
			console.error('Export failed:', e);
		} finally {
			exporting = false;
		}
	}

	async function copyProfile() {
		if (!exportedProfile) return;
		await navigator.clipboard.writeText(exportedProfile.rules_json);
		copied = true;
		setTimeout(() => { copied = false; }, 2000);
	}

	function downloadProfile() {
		if (!exportedProfile) return;
		const blob = new Blob([exportedProfile.rules_json], { type: 'application/json' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'SecurityPrime.lsrules';
		a.click();
		URL.revokeObjectURL(url);
	}

	function priorityColor(p: string) {
		if (p === 'critical') return 'text-neon-red';
		if (p === 'recommended') return 'text-neon-yellow';
		return 'text-muted-foreground';
	}

	function trustColor(t: string) {
		if (t === 'trusted') return 'success';
		if (t === 'suspicious') return 'danger';
		return 'warning';
	}

	function categoryLabel(c: string) {
		const map: Record<string, string> = {
			ai_endpoint: 'AI Endpoint',
			telemetry: 'Telemetry',
			update: 'OS Update',
			cdn: 'CDN',
			local: 'Local',
			uncategorized: 'Unknown',
			suspicious: 'Suspicious',
		};
		return map[c] || c;
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

			<!-- Little Snitch Integration -->
			{#if littleSnitchStatus?.supported || lsRules.length > 0 || domainTrust.length > 0}
				<div class="col-span-12">
					<Card variant="glass" class="border-orange-400/40">
						<CardHeader>
							<div class="flex items-center justify-between gap-3">
								<div>
									<CardTitle class="flex items-center gap-2">
										<ShieldCheck class="w-5 h-5 text-orange-400" />
										Little Snitch Companion
									</CardTitle>
									<CardDescription>
										Process-level outbound visibility and consent-driven network control.
									</CardDescription>
								</div>
								<div class="flex items-center gap-2">
									{#if littleSnitchStatus?.supported}
										<Badge variant={littleSnitchStatus.installed ? 'success' : 'warning'}>
											{littleSnitchStatus.installed ? 'Installed' : 'Not Installed'}
										</Badge>
									{/if}
									<a href={littleSnitchStatus?.docs_url ?? 'https://obdev.at/products/littlesnitch/index.html'} target="_blank" rel="noopener noreferrer">
										<Button variant="outline" size="sm" class="gap-2">
											<ExternalLink class="w-4 h-4" />
											Little Snitch
										</Button>
									</a>
								</div>
							</div>
						</CardHeader>
						<CardContent class="space-y-4">
							<!-- Status bar -->
							{#if littleSnitchStatus}
								<div class="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
									<span>{littleSnitchStatus.status_message}</span>
									{#if littleSnitchStatus.app_path}
										<Badge variant="outline">Detected at: {littleSnitchStatus.app_path}</Badge>
									{/if}
								</div>
							{/if}

							<!-- Tab navigation -->
							<div class="flex items-center gap-1 p-1 rounded-lg bg-muted/40 w-fit">
								<button
									class={cn('px-3 py-1.5 rounded-md text-sm font-medium transition-colors', lsTab === 'rules' ? 'bg-orange-500/20 text-orange-400' : 'text-muted-foreground hover:text-foreground')}
									on:click={() => lsTab = 'rules'}
								>
									<span class="flex items-center gap-1.5"><List class="w-3.5 h-3.5" /> Rules ({lsRules.length})</span>
								</button>
								<button
									class={cn('px-3 py-1.5 rounded-md text-sm font-medium transition-colors', lsTab === 'domains' ? 'bg-orange-500/20 text-orange-400' : 'text-muted-foreground hover:text-foreground')}
									on:click={() => lsTab = 'domains'}
								>
									<span class="flex items-center gap-1.5"><Eye class="w-3.5 h-3.5" /> Domain Trust ({domainTrust.length})</span>
								</button>
								<button
									class={cn('px-3 py-1.5 rounded-md text-sm font-medium transition-colors', lsTab === 'export' ? 'bg-orange-500/20 text-orange-400' : 'text-muted-foreground hover:text-foreground')}
									on:click={() => lsTab = 'export'}
								>
									<span class="flex items-center gap-1.5"><FileDown class="w-3.5 h-3.5" /> Export Profile</span>
								</button>
							</div>

							<!-- Tab: Recommended Rules -->
							{#if lsTab === 'rules'}
								<div class="space-y-3">
									<div class="flex items-center justify-between">
										<div class="flex items-center gap-1 text-xs">
											<button class={cn('px-2 py-1 rounded', rulesFilter === 'all' ? 'bg-muted text-foreground' : 'text-muted-foreground hover:text-foreground')} on:click={() => rulesFilter = 'all'}>All</button>
											<button class={cn('px-2 py-1 rounded', rulesFilter === 'allow' ? 'bg-neon-green/20 text-neon-green' : 'text-muted-foreground hover:text-foreground')} on:click={() => rulesFilter = 'allow'}>Allow</button>
											<button class={cn('px-2 py-1 rounded', rulesFilter === 'deny' ? 'bg-neon-red/20 text-neon-red' : 'text-muted-foreground hover:text-foreground')} on:click={() => rulesFilter = 'deny'}>Deny</button>
										</div>
										<span class="text-xs text-muted-foreground">{filteredRules.length} rules</span>
									</div>
									<ScrollArea class="max-h-[340px]">
										<div class="space-y-1">
											<div class="grid grid-cols-12 gap-3 px-3 py-1.5 text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
												<div class="col-span-1">Action</div>
												<div class="col-span-3">Host</div>
												<div class="col-span-2">Process</div>
												<div class="col-span-1">Ports</div>
												<div class="col-span-1">Proto</div>
												<div class="col-span-1">Category</div>
												<div class="col-span-1">Priority</div>
												<div class="col-span-2">Notes</div>
											</div>
											{#each filteredRules as rule}
												<div class={cn(
													'grid grid-cols-12 gap-3 px-3 py-2 rounded-lg items-center text-xs',
													rule.action === 'deny' ? 'bg-neon-red/5 border border-neon-red/20' : 'bg-neon-green/5 border border-neon-green/20'
												)}>
													<div class="col-span-1">
														<Badge variant={rule.action === 'allow' ? 'success' : 'danger'} class="text-[10px] px-1.5">
															{#if rule.action === 'allow'}<Unlock class="w-2.5 h-2.5 mr-0.5 inline" />{:else}<Lock class="w-2.5 h-2.5 mr-0.5 inline" />{/if}
															{rule.action}
														</Badge>
													</div>
													<div class="col-span-3 font-mono text-[11px] truncate" title={rule.remote_host}>{rule.remote_host}</div>
													<div class="col-span-2 truncate text-muted-foreground">{rule.process}</div>
													<div class="col-span-1 font-mono text-muted-foreground">{rule.ports}</div>
													<div class="col-span-1 uppercase text-muted-foreground">{rule.protocol}</div>
													<div class="col-span-1">
														<Badge variant="outline" class="text-[9px] px-1">{categoryLabel(rule.category)}</Badge>
													</div>
													<div class="col-span-1">
														<span class={cn('text-[10px] font-semibold uppercase', priorityColor(rule.priority))}>{rule.priority}</span>
													</div>
													<div class="col-span-2 truncate text-muted-foreground" title={rule.notes}>{rule.notes}</div>
												</div>
											{/each}
										</div>
									</ScrollArea>
								</div>
							{/if}

							<!-- Tab: Domain Trust -->
							{#if lsTab === 'domains'}
								<div class="space-y-3">
									<div class="flex items-center justify-between gap-4">
										<div class="flex items-center gap-1 text-xs">
											<button class={cn('px-2 py-1 rounded', domainFilter === 'all' ? 'bg-muted text-foreground' : 'text-muted-foreground hover:text-foreground')} on:click={() => domainFilter = 'all'}>All</button>
											<button class={cn('px-2 py-1 rounded', domainFilter === 'trusted' ? 'bg-neon-green/20 text-neon-green' : 'text-muted-foreground hover:text-foreground')} on:click={() => domainFilter = 'trusted'}>
												Trusted ({trustCounts.trusted})
											</button>
											<button class={cn('px-2 py-1 rounded', domainFilter === 'unknown' ? 'bg-neon-yellow/20 text-neon-yellow' : 'text-muted-foreground hover:text-foreground')} on:click={() => domainFilter = 'unknown'}>
												Unknown ({trustCounts.unknown})
											</button>
											<button class={cn('px-2 py-1 rounded', domainFilter === 'suspicious' ? 'bg-neon-red/20 text-neon-red' : 'text-muted-foreground hover:text-foreground')} on:click={() => domainFilter = 'suspicious'}>
												Suspicious ({trustCounts.suspicious})
											</button>
										</div>
									</div>

									<!-- Trust summary badges -->
									<div class="flex items-center gap-3">
										<div class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-neon-green/10 border border-neon-green/20">
											<CheckCircle class="w-3.5 h-3.5 text-neon-green" />
											<span class="text-sm font-semibold text-neon-green">{trustCounts.trusted}</span>
											<span class="text-xs text-neon-green/70">trusted</span>
										</div>
										<div class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-neon-yellow/10 border border-neon-yellow/20">
											<AlertTriangle class="w-3.5 h-3.5 text-neon-yellow" />
											<span class="text-sm font-semibold text-neon-yellow">{trustCounts.unknown}</span>
											<span class="text-xs text-neon-yellow/70">unknown</span>
										</div>
										<div class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-neon-red/10 border border-neon-red/20">
											<ShieldAlert class="w-3.5 h-3.5 text-neon-red" />
											<span class="text-sm font-semibold text-neon-red">{trustCounts.suspicious}</span>
											<span class="text-xs text-neon-red/70">suspicious</span>
										</div>
									</div>

									<ScrollArea class="max-h-[300px]">
										<div class="space-y-1">
											<div class="grid grid-cols-12 gap-3 px-3 py-1.5 text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
												<div class="col-span-1">Trust</div>
												<div class="col-span-4">Domain / IP</div>
												<div class="col-span-2">Category</div>
												<div class="col-span-1">Conns</div>
												<div class="col-span-4">Notes</div>
											</div>
											{#each filteredDomains as entry}
												<div class={cn(
													'grid grid-cols-12 gap-3 px-3 py-2 rounded-lg items-center text-xs',
													entry.trust_level === 'suspicious' ? 'bg-neon-red/5 border border-neon-red/20' :
													entry.trust_level === 'unknown' ? 'bg-neon-yellow/5 border border-neon-yellow/20' :
													'bg-muted/30'
												)}>
													<div class="col-span-1">
														<Badge variant={trustColor(entry.trust_level)} class="text-[10px] px-1.5">
															{entry.trust_level}
														</Badge>
													</div>
													<div class="col-span-4 font-mono text-[11px]" title={entry.domain}>{entry.domain}</div>
													<div class="col-span-2">
														<Badge variant="outline" class="text-[9px] px-1">{categoryLabel(entry.category)}</Badge>
													</div>
													<div class="col-span-1 text-center font-semibold">{entry.connection_count}</div>
													<div class="col-span-4 truncate text-muted-foreground" title={entry.notes}>{entry.notes}</div>
												</div>
											{/each}
											{#if filteredDomains.length === 0}
												<div class="text-center py-8 text-muted-foreground text-sm">No domains match this filter.</div>
											{/if}
										</div>
									</ScrollArea>
								</div>
							{/if}

							<!-- Tab: Export Profile -->
							{#if lsTab === 'export'}
								<div class="space-y-4">
									<div class="p-4 rounded-lg bg-muted/30 border border-muted space-y-3">
										<h4 class="text-sm font-semibold">Export .lsrules Profile</h4>
										<p class="text-xs text-muted-foreground">
											Generate a Little Snitch Rule Group file containing all recommended rules.
											Import it via <span class="font-mono">File &rarr; New Rule Group From File</span> in Little Snitch.
										</p>
										<Button variant="outline" size="sm" class="gap-2" on:click={handleExport} disabled={exporting}>
											{#if exporting}
												<div class="w-4 h-4 border-2 border-orange-400 border-t-transparent rounded-full animate-spin" />
												Generating...
											{:else}
												<FileDown class="w-4 h-4" />
												Generate Profile
											{/if}
										</Button>
									</div>

									{#if exportedProfile}
										<div class="p-4 rounded-lg bg-neon-green/5 border border-neon-green/30 space-y-3">
											<div class="flex items-center justify-between">
												<div>
													<h4 class="text-sm font-semibold text-neon-green">{exportedProfile.name}</h4>
													<p class="text-xs text-muted-foreground">{exportedProfile.rule_count} rules &middot; Generated {new Date(exportedProfile.created_at).toLocaleString()}</p>
												</div>
												<div class="flex items-center gap-2">
													<Button variant="outline" size="sm" class="gap-1.5" on:click={copyProfile}>
														{#if copied}
															<CheckCircle class="w-3.5 h-3.5 text-neon-green" />
															Copied
														{:else}
															Copy JSON
														{/if}
													</Button>
													<Button variant="default" size="sm" class="gap-1.5" on:click={downloadProfile}>
														<Download class="w-3.5 h-3.5" />
														Download .lsrules
													</Button>
												</div>
											</div>
											<div class="relative">
												<ScrollArea class="max-h-[200px]">
													<pre class="text-[10px] font-mono text-muted-foreground bg-background/50 p-3 rounded-md overflow-x-auto">{exportedProfile.rules_json}</pre>
												</ScrollArea>
											</div>
										</div>
									{/if}
								</div>
							{/if}
						</CardContent>
					</Card>
				</div>
			{/if}

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

