<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { invoke } from '@tauri-apps/api/tauri';
	import { listen, type UnlistenFn } from '@tauri-apps/api/event';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Switch } from '$lib/components/ui/switch';
	import { 
		Bot, 
		Send,
		Loader2,
		Server,
		Check,
		X,
		Settings,
		Trash2,
		RefreshCw,
		Sparkles,
		ShieldCheck,
		ChevronDown,
		Zap,
		Key,
		Cloud,
		Eye,
		EyeOff,
		Save
	} from 'lucide-svelte';

	interface ModelInfo {
		name: string;
		size?: number;
		modified_at?: string;
	}

	interface AgentStatus {
		connected: boolean;
		available_models: ModelInfo[];
		current_model: string;
		session_active: boolean;
	}

	interface ChatMessage {
		role: 'user' | 'assistant' | 'system';
		content: string;
		streaming?: boolean;
	}

	interface StreamChunk {
		content: string;
		done: boolean;
		model: string;
	}

	let status: AgentStatus | null = null;
	let messages: ChatMessage[] = [];
	let inputMessage = '';
	let loading = false;
	let configOpen = false;
	let selectedModel = '';
	let ollamaUrl = 'http://127.0.0.1:11434';
	let apiKey = '';
	let hasApiKey = false;
	let savingApiKey = false;
	let showApiKey = false;
	let streamingEnabled = true;
	let unlistenStream: UnlistenFn | null = null;
	let unlistenDone: UnlistenFn | null = null;

	onMount(async () => {
		await checkStatus();
		await checkApiKey();
		await setupStreamListeners();
	});

	async function checkApiKey() {
		try {
			hasApiKey = await invoke<boolean>('has_ollama_api_key');
		} catch (e) {
			console.error('Failed to check API key:', e);
			hasApiKey = false;
		}
	}

	async function saveApiKey() {
		if (!apiKey.trim()) return;
		savingApiKey = true;
		try {
			await invoke('store_ollama_api_key', { apiKey: apiKey.trim() });
			hasApiKey = true;
			apiKey = ''; // Clear from memory
			await checkStatus(); // Reconnect with new key
		} catch (e) {
			console.error('Failed to save API key:', e);
		} finally {
			savingApiKey = false;
		}
	}

	async function deleteApiKey() {
		savingApiKey = true;
		try {
			await invoke('delete_ollama_api_key');
			hasApiKey = false;
			await checkStatus();
		} catch (e) {
			console.error('Failed to delete API key:', e);
		} finally {
			savingApiKey = false;
		}
	}

	onDestroy(() => {
		if (unlistenStream) unlistenStream();
		if (unlistenDone) unlistenDone();
	});

	async function setupStreamListeners() {
		// Listen for streaming chunks
		unlistenStream = await listen<StreamChunk>('agent-stream', (event) => {
			const chunk = event.payload;
			
			// Find the streaming message and append content
			const lastIdx = messages.length - 1;
			if (lastIdx >= 0 && messages[lastIdx].streaming) {
				messages[lastIdx].content += chunk.content;
				messages = [...messages]; // Trigger reactivity
			}
		});

		// Listen for stream completion
		unlistenDone = await listen<StreamChunk>('agent-stream-done', () => {
			// Mark streaming as complete
			const lastIdx = messages.length - 1;
			if (lastIdx >= 0 && messages[lastIdx].streaming) {
				messages[lastIdx].streaming = false;
				messages = [...messages];
			}
			loading = false;
		});
	}

	async function checkStatus() {
		try {
			status = await invoke<AgentStatus>('get_agent_status');
			if (status.connected && status.available_models.length > 0) {
				selectedModel = status.current_model || status.available_models[0].name;
			}
		} catch (e) {
			console.error('Failed to get agent status:', e);
			status = {
				connected: false,
				available_models: [],
				current_model: '',
				session_active: false
			};
		}
	}

	async function sendMessage() {
		if (!inputMessage.trim() || loading) return;

		const userMessage = inputMessage.trim();
		inputMessage = '';
		loading = true;

		// Add user message
		messages = [...messages, { role: 'user', content: userMessage }];

		try {
			if (streamingEnabled) {
				// Add empty assistant message for streaming
				messages = [...messages, { role: 'assistant', content: '', streaming: true }];
				
				// Use streaming endpoint
				await invoke<string>('chat_with_agent_stream', { 
					message: userMessage,
					model: selectedModel || null
				});
				// Response will come via events
			} else {
				// Non-streaming mode
				const response = await invoke<string>('chat_with_agent', { 
					message: userMessage,
					model: selectedModel || null
				});
				messages = [...messages, { role: 'assistant', content: response }];
				loading = false;
			}
		} catch (e: any) {
			// Remove streaming message if exists
			if (messages[messages.length - 1]?.streaming) {
				messages = messages.slice(0, -1);
			}
			messages = [...messages, { 
				role: 'assistant', 
				content: `❌ Error: ${e.toString()}` 
			}];
			loading = false;
		}
	}

	async function clearSession() {
		try {
			await invoke('clear_agent_session');
			messages = [];
		} catch (e) {
			console.error('Failed to clear session:', e);
		}
	}

	async function analyzeSecurityWithAI() {
		loading = true;
		messages = [...messages, {
			role: 'user',
			content: '🔍 Analyze my current security posture and provide recommendations'
		}];

		try {
			const recommendations = await invoke<string[]>('get_security_recommendations');
			const response = recommendations.join('\n\n');
			messages = [...messages, { role: 'assistant', content: response }];
		} catch (e: any) {
			messages = [...messages, {
				role: 'assistant',
				content: `❌ Failed to analyze security: ${e.toString()}`
			}];
		} finally {
			loading = false;
		}
	}

	async function testDirectoryScan() {
		loading = true;
		messages = [...messages, {
			role: 'user',
			content: '🗂️ Can you scan my Documents folder and tell me about its health?'
		}];

		try {
			const response = await invoke<string>('chat_with_agent', {
				message: 'Can you scan my Documents folder and tell me about its health?',
				model: selectedModel || null
			});
			messages = [...messages, { role: 'assistant', content: response }];
		} catch (e: any) {
			messages = [...messages, {
				role: 'assistant',
				content: `❌ Failed to scan directory: ${e.toString()}`
			}];
		} finally {
			loading = false;
		}
	}

	function formatBytes(bytes: number): string {
		if (!bytes) return 'Unknown';
		const gb = bytes / (1024 * 1024 * 1024);
		return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(bytes / (1024 * 1024)).toFixed(0)} MB`;
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			sendMessage();
		}
	}
</script>

<svelte:head>
	<title>AI Security Assistant - Cyber Security Prime</title>
</svelte:head>

<div class="h-full flex flex-col space-y-4">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-3">
			<div class="flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-cyber-purple to-cyber-blue">
				<Bot class="w-6 h-6 text-white" />
			</div>
			<div>
				<h1 class="text-2xl font-bold tracking-tight text-foreground">
					AI Security Assistant
				</h1>
				<p class="text-muted-foreground text-sm">
					Powered by Ollama • Local & Private
				</p>
			</div>
		</div>
		<div class="flex items-center gap-2">
			<Badge variant={status?.connected ? 'success' : 'destructive'} class="gap-1">
				{#if status?.connected}
					<Check class="w-3 h-3" /> Connected
				{:else}
					<X class="w-3 h-3" /> Disconnected
				{/if}
			</Badge>
			<Button variant="outline" size="sm" on:click={checkStatus}>
				<RefreshCw class="w-4 h-4" />
			</Button>
			<Button variant="outline" size="sm" on:click={() => configOpen = !configOpen}>
				<Settings class="w-4 h-4" />
			</Button>
		</div>
	</div>

	<!-- Config Panel -->
	{#if configOpen}
		<Card variant="glass" class="border-cyber-blue/30">
			<CardContent class="py-4 space-y-4">
				<!-- Connection Settings -->
				<div class="grid grid-cols-2 gap-4">
					<div>
						<label for="ollama-url" class="text-sm text-muted-foreground mb-1 block">Ollama URL</label>
						<input 
							id="ollama-url"
							type="text" 
							bind:value={ollamaUrl}
							class="w-full px-3 py-2 bg-muted/50 border border-border rounded-lg text-sm"
							placeholder="http://127.0.0.1:11434"
						/>
					</div>
					<div>
						<label for="model-select" class="text-sm text-muted-foreground mb-1 block">Model</label>
						<div class="relative">
							<select 
								id="model-select"
								bind:value={selectedModel}
								class="w-full px-3 py-2 bg-muted/50 border border-border rounded-lg text-sm appearance-none cursor-pointer"
							>
								{#if status?.available_models}
									{#each status.available_models as model}
										<option value={model.name}>
											{model.name} ({formatBytes(model.size || 0)})
										</option>
									{/each}
								{:else}
									<option value="">No models available</option>
								{/if}
							</select>
							<ChevronDown class="w-4 h-4 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-muted-foreground" />
						</div>
					</div>
				</div>

				<!-- API Key Section -->
				<div class="border-t border-border pt-4">
					<div class="flex items-center gap-2 mb-2">
						<Cloud class="w-4 h-4 text-cyber-purple" />
						<span class="text-sm font-medium">Cloud / API Key</span>
						{#if hasApiKey}
							<Badge variant="success" class="text-[10px]">Configured</Badge>
						{/if}
					</div>
					<p class="text-xs text-muted-foreground mb-3">
						For cloud-hosted Ollama or authenticated endpoints. Key is stored securely in your OS keychain.
					</p>
					
					{#if hasApiKey}
						<div class="flex items-center gap-2">
							<div class="flex-1 px-3 py-2 bg-muted/50 border border-border rounded-lg text-sm text-muted-foreground">
								<span class="flex items-center gap-2">
									<Key class="w-4 h-4" />
									••••••••••••••••
								</span>
							</div>
							<Button 
								variant="destructive" 
								size="sm" 
								on:click={deleteApiKey}
								disabled={savingApiKey}
							>
								{#if savingApiKey}
									<Loader2 class="w-4 h-4 animate-spin" />
								{:else}
									<Trash2 class="w-4 h-4" />
								{/if}
							</Button>
						</div>
					{:else}
						<div class="flex items-center gap-2">
							<div class="relative flex-1">
								<Key class="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
								{#if showApiKey}
									<input 
										type="text"
										bind:value={apiKey}
										class="w-full pl-10 pr-10 py-2 bg-muted/50 border border-border rounded-lg text-sm"
										placeholder="Enter API key for cloud models"
									/>
								{:else}
									<input 
										type="password"
										bind:value={apiKey}
										class="w-full pl-10 pr-10 py-2 bg-muted/50 border border-border rounded-lg text-sm"
										placeholder="Enter API key for cloud models"
									/>
								{/if}
								<button 
									type="button"
									class="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
									on:click={() => showApiKey = !showApiKey}
								>
									{#if showApiKey}
										<EyeOff class="w-4 h-4" />
									{:else}
										<Eye class="w-4 h-4" />
									{/if}
								</button>
							</div>
							<Button 
								variant="cyber" 
								size="sm" 
								on:click={saveApiKey}
								disabled={!apiKey.trim() || savingApiKey}
							>
								{#if savingApiKey}
									<Loader2 class="w-4 h-4 animate-spin" />
								{:else}
									<Save class="w-4 h-4" />
								{/if}
							</Button>
						</div>
					{/if}
				</div>

				<!-- Status Footer -->
				<div class="flex items-center justify-between pt-2 border-t border-border">
					<div class="flex items-center gap-2 text-xs text-muted-foreground">
						<Server class="w-4 h-4" />
						<span>
							{#if status?.connected}
								{status.available_models.length} model(s) available
							{:else}
								Ollama not running. Start with: <code class="px-1 py-0.5 bg-muted rounded">ollama serve</code>
							{/if}
						</span>
					</div>
					<div class="flex items-center gap-2">
						<Zap class="w-4 h-4 text-neon-yellow" />
						<span class="text-xs text-muted-foreground">Streaming</span>
						<Switch bind:checked={streamingEnabled} />
					</div>
				</div>
			</CardContent>
		</Card>
	{/if}

	<!-- Chat Area -->
	<Card variant="glass" class="flex-1 flex flex-col overflow-hidden">
		<CardHeader class="border-b border-border py-3">
			<div class="flex items-center justify-between">
				<CardTitle class="text-lg flex items-center gap-2">
					<Bot class="w-5 h-5 text-cyber-blue" />
					Security Chat
				</CardTitle>
				<div class="flex items-center gap-2">
					<Button variant="ghost" size="sm" on:click={analyzeSecurityWithAI} disabled={!status?.connected || loading}>
						<ShieldCheck class="w-4 h-4 mr-1" />
						Analyze Security
					</Button>
					<Button variant="ghost" size="sm" on:click={testDirectoryScan} disabled={!status?.connected || loading}>
						<Server class="w-4 h-4 mr-1" />
						Scan Documents
					</Button>
					<Button variant="ghost" size="sm" on:click={clearSession}>
						<Trash2 class="w-4 h-4" />
					</Button>
				</div>
			</div>
		</CardHeader>
		
		<CardContent class="flex-1 overflow-y-auto p-4 space-y-4">
			{#if messages.length === 0}
				<div class="h-full flex flex-col items-center justify-center text-center text-muted-foreground">
					<Bot class="w-16 h-16 mb-4 opacity-30" />
					<p class="text-lg font-medium">Start a conversation</p>
					<p class="text-sm mt-1">Ask about security threats, get recommendations, or analyze your system</p>
					<div class="flex flex-wrap gap-2 mt-6 max-w-md justify-center">
						<Button 
							variant="outline" 
							size="sm"
							on:click={() => { inputMessage = 'What are the top security risks I should be aware of?'; sendMessage(); }}
							disabled={!status?.connected}
						>
							<Sparkles class="w-3 h-3 mr-1" />
							Top security risks
						</Button>
						<Button 
							variant="outline" 
							size="sm"
							on:click={() => { inputMessage = 'How can I improve my firewall settings?'; sendMessage(); }}
							disabled={!status?.connected}
						>
							Firewall tips
						</Button>
						<Button 
							variant="outline" 
							size="sm"
							on:click={() => { inputMessage = 'Explain ransomware and how to prevent it'; sendMessage(); }}
							disabled={!status?.connected}
						>
							About ransomware
						</Button>
					</div>
				</div>
			{:else}
				{#each messages as message}
					<div class="flex gap-3 {message.role === 'user' ? 'flex-row-reverse' : ''}">
						<div class="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 {message.role === 'user' ? 'bg-cyber-blue' : 'bg-cyber-purple'}">
							{#if message.role === 'user'}
								<span class="text-sm font-bold text-white">U</span>
							{:else}
								<Bot class="w-4 h-4 text-white" />
							{/if}
						</div>
						<div class="max-w-[80%] rounded-xl px-4 py-3 {message.role === 'user' ? 'bg-cyber-blue/20 text-right' : 'bg-muted/50'}">
							<p class="text-sm whitespace-pre-wrap">{message.content}</p>
						</div>
					</div>
				{/each}
				{#if loading}
					<div class="flex gap-3">
						<div class="w-8 h-8 rounded-lg bg-cyber-purple flex items-center justify-center flex-shrink-0">
							<Bot class="w-4 h-4 text-white" />
						</div>
						<div class="bg-muted/50 rounded-xl px-4 py-3">
							<Loader2 class="w-5 h-5 animate-spin text-cyber-blue" />
						</div>
					</div>
				{/if}
			{/if}
		</CardContent>

		<!-- Input Area -->
		<div class="border-t border-border p-4">
			<div class="flex gap-2">
				<textarea 
					bind:value={inputMessage}
					on:keydown={handleKeydown}
					placeholder={status?.connected ? 'Ask about security, threats, recommendations...' : 'Connect to Ollama to start chatting'}
					disabled={!status?.connected || loading}
					rows="1"
					class="flex-1 px-4 py-3 bg-muted/30 border border-border rounded-xl resize-none focus:outline-none focus:ring-2 focus:ring-cyber-blue/50 disabled:opacity-50"
				/>
				<Button 
					variant="cyber" 
					size="lg"
					on:click={sendMessage}
					disabled={!status?.connected || loading || !inputMessage.trim()}
				>
					{#if loading}
						<Loader2 class="w-5 h-5 animate-spin" />
					{:else}
						<Send class="w-5 h-5" />
					{/if}
				</Button>
			</div>
		</div>
	</Card>
</div>
