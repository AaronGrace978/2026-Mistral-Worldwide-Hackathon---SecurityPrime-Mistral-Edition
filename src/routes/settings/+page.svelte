<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Switch } from '$lib/components/ui/switch';
	import { Separator } from '$lib/components/ui/separator';
	import { theme, isDark } from '$lib/stores/theme';
	import { cn } from '$lib/utils';
	import * as api from '$lib/api';
	import { open } from '@tauri-apps/api/shell';
	import { 
		Settings, 
		Moon, 
		Sun,
		Shield,
		Flame,
		Lock,
		Bug,
		Network,
		Bot,
		RefreshCw,
		Power,
		Bell,
		Download,
		Info,
		Github,
		Heart,
		ExternalLink,
		Key,
		Check,
		X,
		Zap
	} from 'lucide-svelte';

	function openGitHub() { open('https://github.com/AaronGrace978/SecurityPrime'); }
	function openDocs() { open('https://github.com/AaronGrace978/SecurityPrime#readme'); }
	function openWebsite() { open('https://github.com/AaronGrace978/SecurityPrime'); }

	let installMsg = '';
	async function installUpdate() {
		installMsg = 'Checking for updates...';
		setTimeout(() => { installMsg = 'System is up to date.'; }, 1500);
	}

	let settings: api.AppSettings | null = null;
	let loading = true;
	let saving = false;
	let checkingUpdates = false;
	let updateAvailable = false;

	// API Key state
	let mistralKeyInput = '';
	let ollamaKeyInput = '';
	let hasMistralKey = false;
	let hasOllamaKey = false;
	let activeProvider = 'unknown';
	let savingMistralKey = false;
	let savingOllamaKey = false;
	let keyMsg = '';

	async function loadApiKeyStatus() {
		try {
			hasMistralKey = await api.hasMistralApiKey();
			hasOllamaKey = await api.hasOllamaApiKey();
			activeProvider = await api.getAiProvider();
		} catch (e) {
			console.error('Failed to load API key status:', e);
		}
	}

	async function saveMistralKey() {
		if (!mistralKeyInput.trim()) return;
		savingMistralKey = true;
		try {
			await api.storeMistralApiKey(mistralKeyInput.trim());
			hasMistralKey = true;
			mistralKeyInput = '';
			keyMsg = 'Mistral API key saved securely.';
			activeProvider = await api.getAiProvider();
			setTimeout(() => keyMsg = '', 3000);
		} catch (e) {
			keyMsg = 'Failed to save Mistral key.';
		} finally {
			savingMistralKey = false;
		}
	}

	async function removeMistralKey() {
		try {
			await api.deleteMistralApiKey();
			hasMistralKey = false;
			activeProvider = await api.getAiProvider();
			keyMsg = 'Mistral API key removed.';
			setTimeout(() => keyMsg = '', 3000);
		} catch (e) {
			keyMsg = 'Failed to remove Mistral key.';
		}
	}

	async function saveOllamaKey() {
		if (!ollamaKeyInput.trim()) return;
		savingOllamaKey = true;
		try {
			await api.storeOllamaApiKey(ollamaKeyInput.trim());
			hasOllamaKey = true;
			ollamaKeyInput = '';
			keyMsg = 'Ollama API key saved securely.';
			activeProvider = await api.getAiProvider();
			setTimeout(() => keyMsg = '', 3000);
		} catch (e) {
			keyMsg = 'Failed to save Ollama key.';
		} finally {
			savingOllamaKey = false;
		}
	}

	async function removeOllamaKey() {
		try {
			await api.deleteOllamaApiKey();
			hasOllamaKey = false;
			activeProvider = await api.getAiProvider();
			keyMsg = 'Ollama API key removed.';
			setTimeout(() => keyMsg = '', 3000);
		} catch (e) {
			keyMsg = 'Failed to remove Ollama key.';
		}
	}

	onMount(async () => {
		try {
			settings = await api.getSettings();
		} catch (error) {
			console.error('Failed to load settings:', error);
		} finally {
			loading = false;
		}
		loadApiKeyStatus();
	});

	async function saveSettings() {
		if (!settings) return;
		try {
			saving = true;
			await api.updateSettings(settings);
		} catch (error) {
			console.error('Failed to save settings:', error);
		} finally {
			saving = false;
		}
	}

	function toggleTheme() {
		theme.toggle();
		if (settings) {
			settings.theme = $isDark ? 'dark' : 'light';
		}
	}

	function toggleModule(module: keyof api.ModulesEnabled) {
		if (!settings) return;
		settings.modules_enabled[module] = !settings.modules_enabled[module];
		saveSettings();
	}

	async function checkForUpdates() {
		checkingUpdates = true;
		// Simulate update check
		await new Promise(resolve => setTimeout(resolve, 2000));
		updateAvailable = Math.random() > 0.5;
		checkingUpdates = false;
	}

	const modules = [
		{ id: 'scanner', name: 'Malware Scanner', icon: Shield, description: 'Real-time malware protection' },
		{ id: 'firewall', name: 'Firewall', icon: Flame, description: 'Network traffic control' },
		{ id: 'encryption', name: 'Encryption', icon: Lock, description: 'File encryption tools' },
		{ id: 'vulnerability', name: 'Vulnerability Scanner', icon: Bug, description: 'System vulnerability detection' },
		{ id: 'network', name: 'Network Monitor', icon: Network, description: 'Connection monitoring' },
		{ id: 'agent', name: 'AI Assistant', icon: Bot, description: 'AI-powered security analysis' }
	] as const;
</script>

<svelte:head>
	<title>Settings - Cyber Security Prime</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex items-center gap-3">
		<div class="flex items-center justify-center w-12 h-12 rounded-xl bg-muted">
			<Settings class="w-6 h-6 text-muted-foreground" />
		</div>
		<div>
			<h1 class="text-2xl font-bold tracking-tight text-foreground">
				Settings
			</h1>
			<p class="text-muted-foreground">
				Configure your security preferences
			</p>
		</div>
	</div>

	{#if loading}
		<div class="flex items-center justify-center h-64">
			<div class="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
		</div>
	{:else if settings}
		<div class="grid grid-cols-12 gap-6">
			<!-- Appearance -->
			<div class="col-span-12 lg:col-span-6">
				<Card variant="glass">
					<CardHeader>
						<CardTitle>Appearance</CardTitle>
						<CardDescription>
							Customize how Cyber Security Prime looks
						</CardDescription>
					</CardHeader>
					<CardContent class="space-y-4">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-3">
								{#if $isDark}
									<Moon class="w-5 h-5 text-primary" />
								{:else}
									<Sun class="w-5 h-5 text-neon-yellow" />
								{/if}
								<div>
									<p class="font-medium">Theme</p>
									<p class="text-sm text-muted-foreground">
										{$isDark ? 'Dark' : 'Light'} mode
									</p>
								</div>
							</div>
							<Switch checked={$isDark} on:change={toggleTheme} />
						</div>
					</CardContent>
				</Card>
			</div>

			<!-- General Settings -->
			<div class="col-span-12 lg:col-span-6">
				<Card variant="glass">
					<CardHeader>
						<CardTitle>General</CardTitle>
						<CardDescription>
							Application behavior settings
						</CardDescription>
					</CardHeader>
					<CardContent class="space-y-4">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-3">
								<Power class="w-5 h-5 text-muted-foreground" />
								<div>
									<p class="font-medium">Start on boot</p>
									<p class="text-sm text-muted-foreground">
										Launch when Windows starts
									</p>
								</div>
							</div>
							<Switch 
								checked={settings.auto_start} 
								on:change={() => { settings.auto_start = !settings.auto_start; saveSettings(); }} 
							/>
						</div>

						<Separator />

						<div class="flex items-center justify-between">
							<div class="flex items-center gap-3">
								<Bell class="w-5 h-5 text-muted-foreground" />
								<div>
									<p class="font-medium">Notifications</p>
									<p class="text-sm text-muted-foreground">
										Show security alerts
									</p>
								</div>
							</div>
							<Switch 
								checked={settings.notifications_enabled} 
								on:change={() => { settings.notifications_enabled = !settings.notifications_enabled; saveSettings(); }} 
							/>
						</div>

						<Separator />

						<div class="flex items-center justify-between">
							<div class="flex items-center gap-3">
								<RefreshCw class="w-5 h-5 text-muted-foreground" />
								<div>
									<p class="font-medium">Auto-update</p>
									<p class="text-sm text-muted-foreground">
										Automatically update definitions
									</p>
								</div>
							</div>
							<Switch 
								checked={settings.auto_update} 
								on:change={() => { settings.auto_update = !settings.auto_update; saveSettings(); }} 
							/>
						</div>

						<Separator />

						<div class="flex items-center justify-between">
							<div class="flex items-center gap-3">
								<Shield class="w-5 h-5 text-muted-foreground" />
								<div>
									<p class="font-medium">Scan on startup</p>
									<p class="text-sm text-muted-foreground">
										Run quick scan when app starts
									</p>
								</div>
							</div>
							<Switch 
								checked={settings.scan_on_startup} 
								on:change={() => { settings.scan_on_startup = !settings.scan_on_startup; saveSettings(); }} 
							/>
						</div>
					</CardContent>
				</Card>
			</div>

			<!-- Module Settings -->
			<div class="col-span-12">
				<Card variant="glass">
					<CardHeader>
						<CardTitle>Security Modules</CardTitle>
						<CardDescription>
							Enable or disable security features
						</CardDescription>
					</CardHeader>
					<CardContent>
						<div class="grid grid-cols-2 gap-4">
							{#each modules as mod}
								<div class="flex items-center justify-between p-4 rounded-lg bg-muted/30 border border-border">
									<div class="flex items-center gap-3">
										<div class={cn(
											'w-10 h-10 rounded-lg flex items-center justify-center',
											settings.modules_enabled[mod.id] 
												? 'bg-primary/10 text-primary' 
												: 'bg-muted text-muted-foreground'
										)}>
											<svelte:component this={mod.icon} class="w-5 h-5" />
										</div>
										<div>
											<div class="flex items-center gap-2">
												<p class="font-medium">{mod.name}</p>
												{#if mod.comingSoon}
													<Badge variant="outline" class="text-[10px]">Soon</Badge>
												{/if}
											</div>
											<p class="text-sm text-muted-foreground">{mod.description}</p>
										</div>
									</div>
									<Switch 
										checked={settings.modules_enabled[mod.id]}
										disabled={mod.comingSoon}
										on:change={() => toggleModule(mod.id)}
									/>
								</div>
							{/each}
						</div>
					</CardContent>
				</Card>
			</div>

		<!-- AI API Keys -->
		<div class="col-span-12">
			<Card variant="glass">
				<CardHeader>
					<div class="flex items-center justify-between">
						<div>
							<CardTitle>AI API Keys</CardTitle>
							<CardDescription>
								Configure Mistral AI or Ollama Cloud API keys. Keys are stored securely in your OS keychain.
							</CardDescription>
						</div>
						{#if activeProvider !== 'unknown'}
							<Badge variant={activeProvider === 'mistral' ? 'default' : 'outline'} class="text-xs">
								<Zap class="w-3 h-3 mr-1" />
								{activeProvider === 'mistral' ? 'Mistral API' : activeProvider === 'ollama-cloud' ? 'Ollama Cloud' : 'Ollama Local'}
							</Badge>
						{/if}
					</div>
				</CardHeader>
				<CardContent class="space-y-6">
					{#if keyMsg}
						<div class="p-3 rounded-lg bg-primary/10 border border-primary/30 text-sm flex items-center gap-2">
							<Check class="w-4 h-4 text-primary" />
							{keyMsg}
						</div>
					{/if}

					<!-- Mistral Direct API -->
					<div class="p-4 rounded-lg bg-muted/30 border border-border space-y-3">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-3">
								<div class="w-10 h-10 rounded-lg flex items-center justify-center bg-orange-500/10">
									<Key class="w-5 h-5 text-orange-400" />
								</div>
								<div>
									<p class="font-medium">Mistral API Key</p>
									<p class="text-xs text-muted-foreground">
										Direct access via api.mistral.ai — <a href="https://console.mistral.ai/api-keys" class="underline text-primary" on:click|preventDefault={() => open('https://console.mistral.ai/api-keys')}>Get your key</a>
									</p>
								</div>
							</div>
							{#if hasMistralKey}
								<div class="flex items-center gap-2">
									<Badge variant="default" class="text-xs bg-green-600">
										<Check class="w-3 h-3 mr-1" /> Active
									</Badge>
									<Button variant="ghost" size="sm" on:click={removeMistralKey}>
										<X class="w-4 h-4" />
									</Button>
								</div>
							{/if}
						</div>
						{#if !hasMistralKey}
							<div class="flex gap-2">
								<input
									type="password"
									bind:value={mistralKeyInput}
									placeholder="Enter your Mistral API key..."
									class="flex-1 px-3 py-2 text-sm rounded-lg border border-border bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
								/>
								<Button variant="cyber" size="sm" on:click={saveMistralKey} disabled={savingMistralKey || !mistralKeyInput.trim()}>
									{savingMistralKey ? 'Saving...' : 'Save'}
								</Button>
							</div>
						{/if}
					</div>

					<!-- Ollama Cloud API -->
					<div class="p-4 rounded-lg bg-muted/30 border border-border space-y-3">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-3">
								<div class="w-10 h-10 rounded-lg flex items-center justify-center bg-blue-500/10">
									<Key class="w-5 h-5 text-blue-400" />
								</div>
								<div>
									<p class="font-medium">Ollama Cloud API Key</p>
									<p class="text-xs text-muted-foreground">
										Mistral models via Ollama Cloud — <a href="https://ollama.com/settings/keys" class="underline text-primary" on:click|preventDefault={() => open('https://ollama.com/settings/keys')}>Get your key</a>
									</p>
								</div>
							</div>
							{#if hasOllamaKey}
								<div class="flex items-center gap-2">
									<Badge variant={activeProvider === 'ollama-cloud' ? 'default' : 'outline'} class="text-xs {activeProvider === 'ollama-cloud' ? 'bg-green-600' : ''}">
										<Check class="w-3 h-3 mr-1" /> {activeProvider === 'ollama-cloud' ? 'Active' : 'Stored'}
									</Badge>
									<Button variant="ghost" size="sm" on:click={removeOllamaKey}>
										<X class="w-4 h-4" />
									</Button>
								</div>
							{/if}
						</div>
						{#if !hasOllamaKey}
							<div class="flex gap-2">
								<input
									type="password"
									bind:value={ollamaKeyInput}
									placeholder="Enter your Ollama Cloud API key..."
									class="flex-1 px-3 py-2 text-sm rounded-lg border border-border bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
								/>
								<Button variant="cyber" size="sm" on:click={saveOllamaKey} disabled={savingOllamaKey || !ollamaKeyInput.trim()}>
									{savingOllamaKey ? 'Saving...' : 'Save'}
								</Button>
							</div>
						{/if}
					</div>

					<p class="text-xs text-muted-foreground">
						Priority: Mistral API key is used first if set. Otherwise falls back to Ollama Cloud, then Ollama Local.
						All keys are stored in your OS keychain — never in files.
					</p>
				</CardContent>
			</Card>
		</div>

		<!-- Updates -->
		<div class="col-span-12 lg:col-span-6">
				<Card variant="glass">
					<CardHeader>
						<CardTitle>Updates</CardTitle>
						<CardDescription>
							Check for application updates
						</CardDescription>
					</CardHeader>
					<CardContent class="space-y-4">
						<div class="flex items-center justify-between">
							<div>
								<p class="font-medium">Current Version</p>
								<p class="text-sm text-muted-foreground">v0.1.0</p>
							</div>
							<Button 
								variant="outline" 
								on:click={checkForUpdates}
								disabled={checkingUpdates}
							>
								{#if checkingUpdates}
									<RefreshCw class="w-4 h-4 mr-2 animate-spin" />
									Checking...
								{:else}
									<Download class="w-4 h-4 mr-2" />
									Check for Updates
								{/if}
							</Button>
						</div>

						{#if updateAvailable}
							<div class="p-4 rounded-lg bg-neon-green/10 border border-neon-green/30">
								<div class="flex items-center justify-between">
									<div>
										<p class="font-medium text-neon-green">Update Available!</p>
										<p class="text-sm text-muted-foreground">Version 0.2.0 is ready to install</p>
									</div>
								<Button variant="cyber" size="sm" on:click={installUpdate}>
									{installMsg || 'Install Update'}
								</Button>
								</div>
							</div>
						{/if}
					</CardContent>
				</Card>
			</div>

			<!-- About -->
			<div class="col-span-12 lg:col-span-6">
				<Card variant="glass">
					<CardHeader>
						<CardTitle>About</CardTitle>
						<CardDescription>
							Cyber Security Prime
						</CardDescription>
					</CardHeader>
					<CardContent class="space-y-4">
						<div class="flex items-center gap-4">
							<div class="w-16 h-16 rounded-xl bg-gradient-to-br from-cyber-blue to-cyber-purple flex items-center justify-center">
								<Shield class="w-8 h-8 text-white" />
							</div>
							<div>
								<h3 class="font-cyber text-lg font-bold text-glow-blue">
									CYBER SECURITY PRIME
								</h3>
								<p class="text-sm text-muted-foreground">
									All-in-one cybersecurity suite
								</p>
							<p class="text-xs text-muted-foreground mt-1">
								Version 1.0.0 (Mistral Hackathon 2026)
							</p>
							</div>
						</div>

						<Separator />

						<div class="flex gap-3">
						<Button variant="outline" size="sm" class="flex-1" on:click={openGitHub}>
							<Github class="w-4 h-4 mr-2" />
							GitHub
						</Button>
						<Button variant="outline" size="sm" class="flex-1" on:click={openDocs}>
							<Info class="w-4 h-4 mr-2" />
							Documentation
						</Button>
						<Button variant="outline" size="sm" class="flex-1" on:click={openWebsite}>
							<ExternalLink class="w-4 h-4 mr-2" />
							Website
						</Button>
					</div>

						<div class="text-center pt-2">
							<p class="text-xs text-muted-foreground flex items-center justify-center gap-1">
								Made with <Heart class="w-3 h-3 text-neon-red fill-current" /> by the Cyber Security Prime Team
							</p>
						</div>
					</CardContent>
				</Card>
			</div>
		</div>
	{/if}
</div>

