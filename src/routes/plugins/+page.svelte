<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Switch } from '$lib/components/ui/switch';
	import { 
		Puzzle, 
		RefreshCw,
		ExternalLink,
		Shield,
		Flame,
		Lock,
		Wifi,
		Search,
		Database,
		Key,
		FileText,
		Link,
		MoreVertical,
		Download,
		Trash2,
		Settings,
		CheckCircle,
		XCircle,
		AlertCircle
	} from 'lucide-svelte';
	import * as api from '$lib/api';

	let plugins: api.Plugin[] = [];
	let loading = true;
	let selectedPlugin: api.Plugin | null = null;
	let pluginInfo: api.PluginInfo | null = null;
	let showDetails = false;

	onMount(async () => {
		await loadPlugins();
	});

	async function loadPlugins() {
		loading = true;
		try {
			plugins = await api.getPlugins();
		} catch (e) {
			console.error('Failed to load plugins:', e);
		} finally {
			loading = false;
		}
	}

	async function togglePlugin(plugin: api.Plugin) {
		try {
			const updated = await api.togglePlugin(plugin.id, !plugin.enabled);
			plugins = plugins.map(p => p.id === updated.id ? updated : p);
		} catch (e) {
			console.error('Failed to toggle plugin:', e);
		}
	}

	async function viewDetails(plugin: api.Plugin) {
		selectedPlugin = plugin;
		try {
			pluginInfo = await api.getPluginInfo(plugin.id);
			showDetails = true;
		} catch (e) {
			console.error('Failed to get plugin info:', e);
		}
	}

	async function uninstallPlugin(plugin: api.Plugin) {
		if (!confirm(`Uninstall "${plugin.name}"? This cannot be undone.`)) return;
		
		try {
			await api.uninstallPlugin(plugin.id);
			plugins = plugins.filter(p => p.id !== plugin.id);
			showDetails = false;
		} catch (e) {
			console.error('Failed to uninstall plugin:', e);
		}
	}

	function getCategoryIcon(category: string) {
		switch (category) {
			case 'scanner': return Shield;
			case 'firewall': return Flame;
			case 'encryption': return Lock;
			case 'network_monitor': return Wifi;
			case 'vulnerability_scanner': return Search;
			case 'threat_intelligence': return Database;
			case 'data_protection': return Shield;
			case 'authentication': return Key;
			case 'reporting': return FileText;
			case 'integration': return Link;
			default: return Puzzle;
		}
	}

	function getCategoryColor(category: string): string {
		switch (category) {
			case 'scanner': return 'from-cyber-blue to-cyber-purple';
			case 'firewall': return 'from-orange-500 to-neon-red';
			case 'encryption': return 'from-neon-green to-cyan-500';
			case 'threat_intelligence': return 'from-neon-pink to-cyber-purple';
			case 'authentication': return 'from-neon-yellow to-orange-500';
			default: return 'from-gray-500 to-gray-600';
		}
	}

	function getStatusBadge(status: string) {
		switch (status) {
			case 'active': return { variant: 'success' as const, icon: CheckCircle, text: 'Active' };
			case 'inactive': return { variant: 'secondary' as const, icon: XCircle, text: 'Inactive' };
			case 'error': return { variant: 'destructive' as const, icon: AlertCircle, text: 'Error' };
			default: return { variant: 'outline' as const, icon: AlertCircle, text: status };
		}
	}

	function formatPermission(perm: string): string {
		return perm.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
	}
</script>

<svelte:head>
	<title>Plugins - Cyber Security Prime</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-3">
			<div class="flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-cyber-purple to-neon-pink">
				<Puzzle class="w-6 h-6 text-white" />
			</div>
			<div>
				<h1 class="text-2xl font-bold tracking-tight text-foreground">
					Plugins
				</h1>
				<p class="text-muted-foreground text-sm">
					Extend functionality with third-party security tools
				</p>
			</div>
		</div>
		<div class="flex items-center gap-2">
			<Button variant="outline" on:click={loadPlugins} disabled={loading}>
				<RefreshCw class="w-4 h-4 {loading ? 'animate-spin' : ''}" />
			</Button>
			<Button variant="cyber">
				<Download class="w-4 h-4 mr-2" />
				Browse Marketplace
			</Button>
		</div>
	</div>

	<!-- Stats -->
	<div class="grid grid-cols-3 gap-4">
		<Card variant="glass" class="border-primary/20">
			<CardContent class="py-4">
				<div class="flex items-center justify-between">
					<div>
						<p class="text-sm text-muted-foreground">Installed</p>
						<p class="text-2xl font-bold">{plugins.length}</p>
					</div>
					<Puzzle class="w-8 h-8 text-primary opacity-50" />
				</div>
			</CardContent>
		</Card>
		<Card variant="glass" class="border-neon-green/20">
			<CardContent class="py-4">
				<div class="flex items-center justify-between">
					<div>
						<p class="text-sm text-muted-foreground">Active</p>
						<p class="text-2xl font-bold text-neon-green">{plugins.filter(p => p.enabled).length}</p>
					</div>
					<CheckCircle class="w-8 h-8 text-neon-green opacity-50" />
				</div>
			</CardContent>
		</Card>
		<Card variant="glass" class="border-muted-foreground/20">
			<CardContent class="py-4">
				<div class="flex items-center justify-between">
					<div>
						<p class="text-sm text-muted-foreground">Inactive</p>
						<p class="text-2xl font-bold">{plugins.filter(p => !p.enabled).length}</p>
					</div>
					<XCircle class="w-8 h-8 text-muted-foreground opacity-50" />
				</div>
			</CardContent>
		</Card>
	</div>

	<!-- Plugin Grid -->
	<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
		{#each plugins as plugin}
			{@const CategoryIcon = getCategoryIcon(plugin.category)}
			{@const statusInfo = getStatusBadge(plugin.status)}
			{@const StatusIcon = statusInfo.icon}
			<Card variant="glass" class="hover:border-primary/30 transition-all duration-300">
				<CardContent class="p-5">
					<div class="flex items-start justify-between mb-4">
						<div class="flex items-center gap-3">
							<div class="w-12 h-12 rounded-xl bg-gradient-to-br {getCategoryColor(plugin.category)} flex items-center justify-center">
								<CategoryIcon class="w-6 h-6 text-white" />
							</div>
							<div>
								<h3 class="font-semibold text-foreground">{plugin.name}</h3>
								<p class="text-xs text-muted-foreground">v{plugin.version} • {plugin.author}</p>
							</div>
						</div>
						<Switch 
							checked={plugin.enabled} 
							on:click={() => togglePlugin(plugin)}
						/>
					</div>
					
					<p class="text-sm text-muted-foreground mb-4 line-clamp-2">
						{plugin.description}
					</p>

					<div class="flex items-center justify-between">
						<Badge variant={statusInfo.variant} class="gap-1">
							<StatusIcon class="w-3 h-3" />
							{statusInfo.text}
						</Badge>
						<div class="flex items-center gap-1">
							{#if plugin.homepage}
								<Button variant="ghost" size="sm" class="h-8 w-8 p-0">
									<a href={plugin.homepage} target="_blank" rel="noopener noreferrer">
										<ExternalLink class="w-4 h-4" />
									</a>
								</Button>
							{/if}
							<Button variant="ghost" size="sm" class="h-8 w-8 p-0" on:click={() => viewDetails(plugin)}>
								<Settings class="w-4 h-4" />
							</Button>
						</div>
					</div>

					<!-- Permissions -->
					{#if plugin.permissions.length > 0}
						<div class="mt-4 pt-4 border-t border-border">
							<p class="text-xs text-muted-foreground mb-2">Permissions:</p>
							<div class="flex flex-wrap gap-1">
								{#each plugin.permissions.slice(0, 3) as perm}
									<Badge variant="outline" class="text-[10px] px-1.5 py-0">
										{formatPermission(perm)}
									</Badge>
								{/each}
								{#if plugin.permissions.length > 3}
									<Badge variant="outline" class="text-[10px] px-1.5 py-0">
										+{plugin.permissions.length - 3} more
									</Badge>
								{/if}
							</div>
						</div>
					{/if}
				</CardContent>
			</Card>
		{/each}
	</div>

	<!-- Plugin Details Modal -->
	{#if showDetails && pluginInfo}
		{@const CategoryIcon = getCategoryIcon(pluginInfo.plugin.category)}
		<!-- svelte-ignore a11y-click-events-have-key-events -->
		<!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
		<div 
			class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
			on:click={() => showDetails = false}
			on:keydown={(e) => e.key === 'Escape' && (showDetails = false)}
			role="dialog"
			tabindex="-1"
		>
			<!-- svelte-ignore a11y-click-events-have-key-events -->
			<!-- svelte-ignore a11y-no-static-element-interactions -->
			<div on:click|stopPropagation>
			<Card 
				variant="glass" 
				class="w-full max-w-2xl max-h-[90vh] overflow-y-auto"
			>
				<CardHeader class="border-b border-border">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-3">
							<div class="w-12 h-12 rounded-xl bg-gradient-to-br {getCategoryColor(pluginInfo.plugin.category)} flex items-center justify-center">
								<svelte:component this={CategoryIcon} class="w-6 h-6 text-white" />
							</div>
							<div>
								<CardTitle>{pluginInfo.plugin.name}</CardTitle>
								<p class="text-sm text-muted-foreground">v{pluginInfo.plugin.version}</p>
							</div>
						</div>
						<Button variant="ghost" size="sm" on:click={() => showDetails = false}>
							✕
						</Button>
					</div>
				</CardHeader>
				<CardContent class="p-6 space-y-6">
					<p class="text-muted-foreground">{pluginInfo.plugin.description}</p>

					<!-- Stats -->
					<div class="grid grid-cols-3 gap-4">
						<div class="text-center p-3 bg-muted/30 rounded-lg">
							<p class="text-2xl font-bold text-cyber-blue">{pluginInfo.stats.invocations}</p>
							<p class="text-xs text-muted-foreground">Invocations</p>
						</div>
						<div class="text-center p-3 bg-muted/30 rounded-lg">
							<p class="text-2xl font-bold text-neon-green">{pluginInfo.stats.avg_response_ms.toFixed(0)}ms</p>
							<p class="text-xs text-muted-foreground">Avg Response</p>
						</div>
						<div class="text-center p-3 bg-muted/30 rounded-lg">
							<p class="text-2xl font-bold text-neon-red">{pluginInfo.stats.errors}</p>
							<p class="text-xs text-muted-foreground">Errors</p>
						</div>
					</div>

					<!-- Health Status -->
					<div class="p-4 rounded-lg {pluginInfo.health.healthy ? 'bg-neon-green/10 border border-neon-green/30' : 'bg-neon-red/10 border border-neon-red/30'}">
						<div class="flex items-center gap-2">
							{#if pluginInfo.health.healthy}
								<CheckCircle class="w-5 h-5 text-neon-green" />
								<span class="font-medium text-neon-green">Healthy</span>
							{:else}
								<AlertCircle class="w-5 h-5 text-neon-red" />
								<span class="font-medium text-neon-red">Unhealthy</span>
							{/if}
						</div>
						<p class="text-sm text-muted-foreground mt-1">{pluginInfo.health.message}</p>
					</div>

					<!-- Permissions -->
					<div>
						<h4 class="font-medium mb-2">Required Permissions</h4>
						<div class="flex flex-wrap gap-2">
							{#each pluginInfo.plugin.permissions as perm}
								<Badge variant="outline">
									{formatPermission(perm)}
								</Badge>
							{/each}
						</div>
					</div>

					<!-- Actions -->
					<div class="flex items-center justify-between pt-4 border-t border-border">
						<Button variant="destructive" on:click={() => pluginInfo && uninstallPlugin(pluginInfo.plugin)}>
							<Trash2 class="w-4 h-4 mr-2" />
							Uninstall
						</Button>
						<div class="flex items-center gap-2">
							<span class="text-sm text-muted-foreground">Enabled</span>
							<Switch 
								checked={pluginInfo.plugin.enabled} 
								on:click={() => {
									if (pluginInfo) {
										togglePlugin(pluginInfo.plugin);
										pluginInfo.plugin.enabled = !pluginInfo.plugin.enabled;
									}
								}}
							/>
						</div>
					</div>
				</CardContent>
			</Card>
			</div>
		</div>
	{/if}
</div>

