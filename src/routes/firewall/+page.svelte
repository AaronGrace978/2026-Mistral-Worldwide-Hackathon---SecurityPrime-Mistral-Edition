<script lang="ts">
	import { onMount } from 'svelte';
	import { save, open } from '@tauri-apps/api/dialog';
	import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Switch } from '$lib/components/ui/switch';
	import { ScrollArea } from '$lib/components/ui/scroll-area';
	import { Separator } from '$lib/components/ui/separator';
	import { cn } from '$lib/utils';
	import * as api from '$lib/api';
	import { 
		Flame, 
		Shield, 
		Plus, 
		Trash2,
		ArrowUpRight,
		ArrowDownLeft,
		Ban,
		CheckCircle,
		Globe,
		Activity,
		Download,
		Upload,
		AlertTriangle,
		RefreshCw
	} from 'lucide-svelte';

	let firewallStatus: api.FirewallStatus | null = null;
	let firewallRules: api.FirewallRule[] = [];
	let loading = true;
	let rulesLoading = false;
	let rulesLoaded = false;
	let error: string | null = null;
	let toggling = false;

	onMount(async () => {
		// Load status first (fast), then lazy-load rules
		await loadFirewallStatus();
	});

	async function loadFirewallStatus() {
		loading = true;
		error = null;
		try {
			// Status is fast, load it first for responsive UI
			firewallStatus = await api.getFirewallStatus();
		} catch (err) {
			console.error('Failed to load firewall status:', err);
			error = `Failed to load firewall status: ${err}`;
		} finally {
			loading = false;
		}
	}

	// Lazy load rules only when user wants to see them
	async function loadFirewallRules() {
		if (rulesLoading || rulesLoaded) return;
		
		rulesLoading = true;
		error = null;
		try {
			firewallRules = await api.getFirewallRules();
			rulesLoaded = true;
		} catch (err) {
			console.error('Failed to load firewall rules:', err);
			error = `Failed to load firewall rules: ${err}`;
		} finally {
			rulesLoading = false;
		}
	}

	async function loadFirewallData() {
		loading = true;
		rulesLoading = true;
		error = null;
		try {
			// Load in parallel but handle separately
			const [status, rules] = await Promise.all([
				api.getFirewallStatus(),
				api.getFirewallRules()
			]);
			firewallStatus = status;
			firewallRules = rules;
			rulesLoaded = true;
		} catch (err) {
			console.error('Failed to load firewall data:', err);
			error = `Failed to load firewall data: ${err}`;
		} finally {
			loading = false;
			rulesLoading = false;
		}
	}

	async function toggleFirewall() {
		if (!firewallStatus || toggling) return;
		toggling = true;
		error = null;
		const previousState = firewallStatus.enabled;
		
		try {
			const newState = !firewallStatus.enabled;
			await api.toggleFirewall(newState);
			// Refresh actual status from system
			firewallStatus = await api.getFirewallStatus();
		} catch (err) {
			console.error('Failed to toggle firewall:', err);
			error = `Failed to toggle firewall: ${err}. This operation requires administrator privileges. Try running the app as Administrator.`;
			// Refresh to get actual state
			try {
				firewallStatus = await api.getFirewallStatus();
			} catch {}
		} finally {
			toggling = false;
		}
	}

	async function toggleRule(ruleId: string, currentState: boolean) {
		firewallRules = firewallRules.map(r => 
			r.id === ruleId ? { ...r, enabled: !currentState } : r
		);
	}

	async function deleteRule(ruleId: string) {
		try {
			await api.removeFirewallRule(ruleId);
			firewallRules = firewallRules.filter(r => r.id !== ruleId);
		} catch (error) {
			console.error('Failed to delete rule:', error);
		}
	}

	async function exportRules() {
		try {
			const filePath = await save({
				defaultPath: 'firewall-rules.json',
				filters: [{ name: 'JSON', extensions: ['json'] }]
			});
			if (filePath) {
				const result = await api.exportFirewallRules(filePath);
				alert(`Exported ${result.rules.length} rules successfully!`);
			}
		} catch (error) {
			console.error('Failed to export rules:', error);
			alert('Failed to export rules');
		}
	}

	async function importRules() {
		try {
			const filePath = await open({
				filters: [{ name: 'JSON', extensions: ['json'] }],
				multiple: false
			});
			if (filePath && typeof filePath === 'string') {
				const merge = confirm('Merge with existing rules? Click Cancel to replace all rules.');
				const result = await api.importFirewallRules(filePath, merge);
				alert(result.message);
				firewallRules = await api.getFirewallRules();
			}
		} catch (error) {
			console.error('Failed to import rules:', error);
			alert('Failed to import rules: ' + error);
		}
	}

	let showAddRule = false;
	let newRule = { name: '', direction: 'Inbound', action: 'Block', protocol: 'TCP', local_port: '', remote_address: '' };

	async function addRule() {
		if (!newRule.name) { alert('Rule name is required'); return; }
		try {
			await api.addFirewallRule({
				name: newRule.name,
				enabled: true,
				direction: newRule.direction,
				action: newRule.action,
				protocol: newRule.protocol,
				local_port: newRule.local_port || null,
				remote_port: null,
				remote_address: newRule.remote_address || null,
				application: null,
				description: `Custom rule created via SecurityPrime`
			});
			showAddRule = false;
			newRule = { name: '', direction: 'Inbound', action: 'Block', protocol: 'TCP', local_port: '', remote_address: '' };
			firewallRules = await api.getFirewallRules();
		} catch (err) {
			alert('Failed to add rule: ' + err);
		}
	}
</script>

<svelte:head>
	<title>Firewall - Cyber Security Prime</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-3">
			<div class="flex items-center justify-center w-12 h-12 rounded-xl bg-cyber-orange/10">
				<Flame class="w-6 h-6 text-cyber-orange" />
			</div>
			<div>
				<h1 class="text-2xl font-bold tracking-tight text-foreground">
					Firewall Manager
				</h1>
				<p class="text-muted-foreground">
					Control network traffic and protect your system
				</p>
			</div>
		</div>
		{#if firewallStatus}
			<div class="flex items-center gap-3">
				<span class="text-sm text-muted-foreground">Firewall</span>
				<Switch 
					checked={firewallStatus.enabled} 
					on:change={toggleFirewall}
				/>
				<Badge variant={firewallStatus.enabled ? 'success' : 'danger'}>
					{firewallStatus.enabled ? 'Active' : 'Disabled'}
				</Badge>
			</div>
		{/if}
	</div>

	{#if loading}
		<div class="flex items-center justify-center h-64">
			<div class="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
		</div>
	{:else}
		<div class="grid grid-cols-12 gap-6">
			<!-- Stats -->
			<div class="col-span-12 lg:col-span-8">
				<div class="grid grid-cols-4 gap-4">
					<Card variant="glass">
						<CardContent class="pt-6">
							<div class="flex items-center gap-2 mb-2">
								<ArrowDownLeft class="w-4 h-4 text-neon-green" />
								<span class="text-sm text-muted-foreground">Inbound Blocked</span>
							</div>
							<p class="text-2xl font-bold">{firewallStatus?.inbound_blocked.toLocaleString() ?? 0}</p>
						</CardContent>
					</Card>
					<Card variant="glass">
						<CardContent class="pt-6">
							<div class="flex items-center gap-2 mb-2">
								<ArrowUpRight class="w-4 h-4 text-cyber-blue" />
								<span class="text-sm text-muted-foreground">Outbound Blocked</span>
							</div>
							<p class="text-2xl font-bold">{firewallStatus?.outbound_blocked.toLocaleString() ?? 0}</p>
						</CardContent>
					</Card>
					<Card variant="glass">
						<CardContent class="pt-6">
							<div class="flex items-center gap-2 mb-2">
								<Shield class="w-4 h-4 text-primary" />
								<span class="text-sm text-muted-foreground">Active Rules</span>
							</div>
							<p class="text-2xl font-bold">{firewallStatus?.active_rules ?? 0}</p>
						</CardContent>
					</Card>
					<Card variant="glass">
						<CardContent class="pt-6">
							<div class="flex items-center gap-2 mb-2">
								<Globe class="w-4 h-4 text-primary" />
								<span class="text-sm text-muted-foreground">Profile</span>
							</div>
							<p class="text-2xl font-bold">{firewallStatus?.profile ?? 'Unknown'}</p>
						</CardContent>
					</Card>
				</div>
			</div>

			<!-- Last Blocked -->
			<div class="col-span-12 lg:col-span-4">
				{#if firewallStatus?.last_blocked}
					<Card variant="glass" class="border-neon-red/30">
						<CardContent class="pt-6">
							<div class="flex items-center gap-2 mb-3">
								<Ban class="w-5 h-5 text-neon-red" />
								<span class="font-medium">Last Blocked Connection</span>
							</div>
							<div class="space-y-2 text-sm">
								<div class="flex justify-between">
									<span class="text-muted-foreground">IP Address</span>
									<span class="font-mono">{firewallStatus.last_blocked.ip}</span>
								</div>
								<div class="flex justify-between">
									<span class="text-muted-foreground">Port</span>
									<span class="font-mono">{firewallStatus.last_blocked.port}</span>
								</div>
								<div class="flex justify-between">
									<span class="text-muted-foreground">Direction</span>
									<span class="capitalize">{firewallStatus.last_blocked.direction}</span>
								</div>
								<div class="flex justify-between">
									<span class="text-muted-foreground">Reason</span>
									<Badge variant="danger" class="text-xs">{firewallStatus.last_blocked.reason}</Badge>
								</div>
							</div>
						</CardContent>
					</Card>
				{/if}
			</div>

			<!-- Rules List -->
			<div class="col-span-12">
				<Card variant="glass">
					<CardHeader>
						<div class="flex items-center justify-between">
							<div>
								<CardTitle>Firewall Rules</CardTitle>
								<CardDescription>
									Manage your network access rules
									{#if rulesLoaded}
										<span class="text-muted-foreground ml-2">({firewallRules.length} rules loaded)</span>
									{/if}
								</CardDescription>
							</div>
							<div class="flex items-center gap-2">
								{#if rulesLoaded}
									<Button variant="outline" size="sm" on:click={exportRules}>
										<Download class="w-4 h-4 mr-2" />
										Export
									</Button>
									<Button variant="outline" size="sm" on:click={importRules}>
										<Upload class="w-4 h-4 mr-2" />
										Import
									</Button>
								<Button variant="cyber" size="sm" on:click={() => showAddRule = !showAddRule}>
									<Plus class="w-4 h-4 mr-2" />
									Add Rule
								</Button>
								{/if}
							</div>
						</div>
				</CardHeader>
				<CardContent>
					{#if showAddRule}
						<div class="mb-4 p-4 rounded-lg bg-muted/30 border border-primary/20 space-y-3">
							<h4 class="text-sm font-semibold">New Firewall Rule</h4>
							<div class="grid grid-cols-2 gap-3">
								<div>
									<label class="text-xs text-muted-foreground">Rule Name *</label>
									<input bind:value={newRule.name} class="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded-md" placeholder="Block Telnet" />
								</div>
								<div>
									<label class="text-xs text-muted-foreground">Direction</label>
									<select bind:value={newRule.direction} class="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded-md">
										<option>Inbound</option>
										<option>Outbound</option>
									</select>
								</div>
								<div>
									<label class="text-xs text-muted-foreground">Action</label>
									<select bind:value={newRule.action} class="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded-md">
										<option>Block</option>
										<option>Allow</option>
									</select>
								</div>
								<div>
									<label class="text-xs text-muted-foreground">Protocol</label>
									<select bind:value={newRule.protocol} class="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded-md">
										<option>TCP</option>
										<option>UDP</option>
										<option>Any</option>
									</select>
								</div>
								<div>
									<label class="text-xs text-muted-foreground">Port</label>
									<input bind:value={newRule.local_port} class="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded-md" placeholder="e.g. 23" />
								</div>
								<div>
									<label class="text-xs text-muted-foreground">Remote Address</label>
									<input bind:value={newRule.remote_address} class="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded-md" placeholder="Any" />
								</div>
							</div>
							<div class="flex justify-end gap-2 pt-1">
								<Button variant="outline" size="sm" on:click={() => showAddRule = false}>Cancel</Button>
								<Button variant="cyber" size="sm" on:click={addRule}>Create Rule</Button>
							</div>
						</div>
					{/if}
					{#if !rulesLoaded && !rulesLoading}
							<!-- Lazy load prompt - rules can take several seconds to load -->
							<div class="flex flex-col items-center justify-center py-12 text-center">
								<Shield class="w-12 h-12 text-muted-foreground mb-4 opacity-50" />
								<p class="text-muted-foreground mb-4">
									Loading firewall rules can take a few seconds on systems with many rules.
								</p>
								<Button variant="cyber" on:click={loadFirewallRules}>
									<RefreshCw class="w-4 h-4 mr-2" />
									Load Firewall Rules
								</Button>
							</div>
						{:else if rulesLoading}
							<div class="flex flex-col items-center justify-center py-12">
								<div class="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mb-4" />
								<p class="text-sm text-muted-foreground">Loading firewall rules...</p>
								<p class="text-xs text-muted-foreground mt-1">This may take a few seconds</p>
							</div>
						{:else}
							<ScrollArea class="max-h-[400px]">
								<div class="space-y-2">
									{#each firewallRules as rule}
										<div class="flex items-center justify-between p-4 rounded-lg bg-muted/30 border border-border hover:border-primary/30 transition-colors">
											<div class="flex items-center gap-4">
												<Switch 
													checked={rule.enabled} 
													on:change={() => toggleRule(rule.id, rule.enabled)}
												/>
												<div class={cn(
													'w-10 h-10 rounded-lg flex items-center justify-center',
													rule.action === 'block' 
														? 'bg-neon-red/10 text-neon-red' 
														: 'bg-neon-green/10 text-neon-green'
												)}>
													{#if rule.action === 'block'}
														<Ban class="w-5 h-5" />
													{:else}
														<CheckCircle class="w-5 h-5" />
													{/if}
												</div>
												<div>
													<p class="font-medium">{rule.name}</p>
													<p class="text-sm text-muted-foreground line-clamp-1">{rule.description || 'No description'}</p>
												</div>
											</div>
											<div class="flex items-center gap-3">
												<div class="flex gap-2">
													<Badge variant="outline" class="capitalize">
														{rule.direction}
													</Badge>
													<Badge variant={rule.action === 'block' ? 'danger' : 'success'} class="capitalize">
														{rule.action}
													</Badge>
													<Badge variant="secondary">
														{rule.protocol.toUpperCase()}
													</Badge>
												</div>
												<Button variant="ghost" size="icon" on:click={() => deleteRule(rule.id)}>
													<Trash2 class="w-4 h-4 text-muted-foreground hover:text-destructive" />
												</Button>
											</div>
										</div>
									{/each}
									{#if firewallRules.length === 0}
										<div class="text-center py-8 text-muted-foreground">
											No firewall rules found
										</div>
									{/if}
								</div>
							</ScrollArea>
						{/if}
					</CardContent>
				</Card>
			</div>
		</div>
	{/if}

	{#if error}
		<Card variant="glass" class="border-destructive/30 mt-4">
			<CardContent class="pt-6">
				<div class="flex items-start gap-3">
					<AlertTriangle class="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
					<div>
						<p class="font-medium text-destructive">Error</p>
						<p class="text-sm text-muted-foreground">{error}</p>
					</div>
				</div>
			</CardContent>
		</Card>
	{/if}
</div>

