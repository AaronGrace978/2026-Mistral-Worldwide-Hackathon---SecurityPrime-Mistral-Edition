<script lang="ts">
	import { onMount, onDestroy, tick } from 'svelte';
	import { invoke } from '@tauri-apps/api/tauri';
	import { listen, type UnlistenFn } from '@tauri-apps/api/event';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Switch } from '$lib/components/ui/switch';
	import { marked } from 'marked';
	import { goto } from '$app/navigation';
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
		Save,
		Brain,
		Cpu,
		ImageIcon,
		Code,
		Shield,
		AlertTriangle,
		FolderSearch,
		Terminal,
		FileSearch,
		Volume2
	} from 'lucide-svelte';
	import MistralCat from '$lib/components/MistralCat.svelte';
	import MistralLogo from '$lib/components/MistralLogo.svelte';
	import MistralPixelCat from '$lib/components/MistralPixelCat.svelte';

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
		model?: string;
		timestamp?: string;
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
	let chatContainer: HTMLElement;
	let activeModel = '';
	let speakingIdx = -1;
	let speakingAudio: HTMLAudioElement | null = null;
	let hasElevenlabsKey = false;

	marked.setOptions({
		breaks: true,
		gfm: true
	});

	const MODEL_META: Record<string, { icon: typeof Brain; label: string; color: string; desc: string }> = {
		'mistral-large': { icon: Brain, label: 'Mistral Large', color: 'text-orange-400', desc: 'Deep security analysis' },
		'ministral': { icon: Zap, label: 'Ministral', color: 'text-yellow-400', desc: 'Fast triage' },
		'devstral': { icon: Code, label: 'Devstral', color: 'text-emerald-400', desc: 'Code & remediation' },
		'pixtral': { icon: ImageIcon, label: 'Pixtral', color: 'text-violet-400', desc: 'Visual analysis' },
		'mixtral': { icon: Cpu, label: 'Mixtral', color: 'text-blue-400', desc: 'MoE reasoning' },
		'codestral': { icon: Terminal, label: 'Codestral', color: 'text-cyan-400', desc: 'Code generation' }
	};

	function getModelMeta(name: string) {
		const lower = name.toLowerCase();
		for (const [key, meta] of Object.entries(MODEL_META)) {
			if (lower.includes(key)) return meta;
		}
		return { icon: Brain, label: name, color: 'text-orange-400', desc: 'Mistral model' };
	}

	$: mistralModels = (status?.available_models ?? []).filter((model) => {
		const n = model.name.toLowerCase();
		return n.includes('mistral') || n.includes('mixtral') || n.includes('ministral') ||
			n.includes('codestral') || n.includes('devstral') || n.includes('pixtral');
	});

	function renderMarkdown(text: string): string {
		try {
			return marked.parse(text) as string;
		} catch {
			return text;
		}
	}

	async function scrollToBottom() {
		await tick();
		if (chatContainer) {
			chatContainer.scrollTop = chatContainer.scrollHeight;
		}
	}

	onMount(async () => {
		await checkStatus();
		await checkApiKey();
		await setupStreamListeners();
		try { hasElevenlabsKey = await invoke<boolean>('has_elevenlabs_api_key'); } catch { /* */ }
	});

	async function checkApiKey() {
		try {
			const hasMistral = await invoke<boolean>('has_mistral_api_key');
			const hasOllama = await invoke<boolean>('has_ollama_api_key');
			hasApiKey = hasMistral || hasOllama;
		} catch (e) {
			console.error('Failed to check API key:', e);
			hasApiKey = false;
		}
	}

	async function saveApiKey() {
		if (!apiKey.trim()) return;
		savingApiKey = true;
		try {
			await invoke('store_mistral_api_key', { apiKey: apiKey.trim() });
			await invoke('store_ollama_api_key', { apiKey: apiKey.trim() });
			hasApiKey = true;
			apiKey = '';
			await invoke('reset_agent_client');
			await checkStatus();
		} catch (e) {
			console.error('Failed to save API key:', e);
		} finally {
			savingApiKey = false;
		}
	}

	async function deleteApiKey() {
		savingApiKey = true;
		try {
			await invoke('delete_mistral_api_key');
			await invoke('delete_ollama_api_key');
			hasApiKey = false;
			await invoke('reset_agent_client');
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
		unlistenStream = await listen<StreamChunk>('agent-stream', (event) => {
			const chunk = event.payload;
			const lastIdx = messages.length - 1;
			if (lastIdx >= 0 && messages[lastIdx].streaming) {
				messages[lastIdx].content += chunk.content;
				if (chunk.model) activeModel = chunk.model;
				messages = [...messages];
				scrollToBottom();
			}
		});

		unlistenDone = await listen<StreamChunk>('agent-stream-done', (event) => {
			const lastIdx = messages.length - 1;
			if (lastIdx >= 0 && messages[lastIdx].streaming) {
				messages[lastIdx].streaming = false;
				messages[lastIdx].model = event.payload.model || activeModel;
				messages = [...messages];
			}
			loading = false;
		});
	}

	async function checkStatus() {
		try {
			status = await invoke<AgentStatus>('get_agent_status');
			const models = status.available_models.filter((model) => {
				const n = model.name.toLowerCase();
				return n.includes('mistral') || n.includes('mixtral') || n.includes('ministral') ||
					n.includes('codestral') || n.includes('devstral') || n.includes('pixtral');
			});
			if (status.connected && models.length > 0) {
				const current = status.current_model || models[0].name;
				selectedModel = models.some((m) => m.name === current) ? current : models[0].name;
			}
		} catch (e) {
			console.error('Failed to get agent status:', e);
			status = { connected: false, available_models: [], current_model: '', session_active: false };
		}
	}

	async function sendMessage() {
		if (!inputMessage.trim() || loading) return;
		const userMessage = inputMessage.trim();
		inputMessage = '';
		loading = true;
		activeModel = selectedModel;

		messages = [...messages, { role: 'user', content: userMessage, timestamp: new Date().toISOString() }];
		scrollToBottom();

		try {
			if (streamingEnabled) {
				messages = [...messages, { role: 'assistant', content: '', streaming: true, model: selectedModel, timestamp: new Date().toISOString() }];
				scrollToBottom();
				await invoke<string>('chat_with_agent_stream', { message: userMessage, model: selectedModel || null });
			} else {
				const response = await invoke<string>('chat_with_agent', { message: userMessage, model: selectedModel || null });
				messages = [...messages, { role: 'assistant', content: response, model: selectedModel, timestamp: new Date().toISOString() }];
				loading = false;
				scrollToBottom();
			}
		} catch (e: any) {
			if (messages[messages.length - 1]?.streaming) {
				messages = messages.slice(0, -1);
			}
			messages = [...messages, { role: 'assistant', content: `Error: ${e.toString()}`, timestamp: new Date().toISOString() }];
			loading = false;
			scrollToBottom();
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

	async function quickAction(prompt: string) {
		inputMessage = prompt;
		await sendMessage();
	}

	function formatBytes(bytes: number): string {
		if (!bytes) return 'Cloud';
		const gb = bytes / (1024 * 1024 * 1024);
		return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(bytes / (1024 * 1024)).toFixed(0)} MB`;
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			sendMessage();
		}
	}

	async function speakMessage(idx: number) {
		const msg = messages[idx];
		if (!msg || msg.role !== 'assistant' || speakingIdx === idx) {
			if (speakingAudio) { speakingAudio.pause(); speakingAudio = null; }
			speakingIdx = -1;
			return;
		}

		speakingIdx = idx;
		try {
			const plain = msg.content.replace(/[#*`_~>\[\]()]/g, '').slice(0, 2000);
			const audioB64 = await invoke<string>('narrate_dossier', { text: plain, voiceId: null });
			const raw = atob(audioB64);
			const arr = new Uint8Array(raw.length);
			for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
			const blob = new Blob([arr], { type: 'audio/mpeg' });
			const url = URL.createObjectURL(blob);
			if (speakingAudio) speakingAudio.pause();
			speakingAudio = new Audio(url);
			speakingAudio.addEventListener('ended', () => { speakingIdx = -1; });
			speakingAudio.play();
		} catch {
			speakingIdx = -1;
		}
	}

	function timeAgo(ts: string | undefined): string {
		if (!ts) return '';
		const diff = Date.now() - new Date(ts).getTime();
		if (diff < 60000) return 'just now';
		if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
		return `${Math.floor(diff / 3600000)}h ago`;
	}
</script>

<svelte:head>
	<title>Mistral Security Copilot - Cyber Security Prime</title>
</svelte:head>

<div class="h-full flex flex-col gap-4">
	<!-- Hero Header -->
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-4">
		<div class="mistral-icon-shell flex items-center justify-center w-14 h-14 rounded-2xl">
			<MistralLogo size={28} className="drop-shadow-md" />
		</div>
			<div>
				<h1 class="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
					<span class="text-mistral-gradient">Le</span> Security Copilot
					<Badge variant="outline" class="text-[10px] font-mono tracking-wider border-[#FF8205]/40 text-[#FF8205]">
						MISTRAL AI
					</Badge>
				</h1>
				<p class="text-muted-foreground text-sm mt-0.5">
					Multi-model AI security analysis — deep reasoning, fast triage, code remediation & visual inspection
				</p>
			</div>
		</div>
		<div class="flex items-center gap-2">
			<Badge variant={status?.connected ? 'success' : 'destructive'} class="gap-1 px-3 py-1">
				{#if status?.connected}
					<Check class="w-3 h-3" /> Online
				{:else}
					<X class="w-3 h-3" /> Offline
				{/if}
			</Badge>
			<Button variant="outline" size="sm" on:click={checkStatus} class="h-9 w-9 p-0">
				<RefreshCw class="w-4 h-4" />
			</Button>
			<Button variant="outline" size="sm" on:click={() => configOpen = !configOpen} class="h-9 w-9 p-0">
				<Settings class="w-4 h-4" />
			</Button>
		</div>
	</div>

	<!-- Model Routing Bar -->
	{#if status?.connected && mistralModels.length > 0}
		<div class="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-card/60 border border-border/50 backdrop-blur-sm">
			<span class="text-xs text-muted-foreground font-medium uppercase tracking-wider">Model Routing</span>
			<div class="h-4 w-px bg-border" />
			{#each mistralModels as model}
				{@const meta = getModelMeta(model.name)}
				<button
					class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all
						{selectedModel === model.name
							? 'bg-orange-500/15 border border-orange-500/30 ' + meta.color
							: 'text-muted-foreground hover:text-foreground hover:bg-muted/50'}"
					on:click={() => selectedModel = model.name}
				>
					<svelte:component this={meta.icon} class="w-3.5 h-3.5" />
					{meta.label}
					<span class="text-[10px] opacity-60">({formatBytes(model.size || 0)})</span>
				</button>
			{/each}
		</div>
	{/if}

	<!-- Config Panel -->
	{#if configOpen}
		<Card variant="glass" class="mistral-panel animate-in">
			<CardContent class="py-4 space-y-4">
				<div class="grid grid-cols-2 gap-4">
					<div>
						<label for="ollama-url" class="text-xs text-muted-foreground mb-1 block font-medium uppercase tracking-wider">Endpoint URL</label>
						<input
							id="ollama-url"
							type="text"
							bind:value={ollamaUrl}
							class="w-full px-3 py-2 bg-muted/50 border border-border rounded-lg text-sm focus:ring-2 focus:ring-orange-500/30 focus:outline-none"
							placeholder="https://ollama.com or http://127.0.0.1:11434"
						/>
					</div>
					<div>
						<label for="model-select" class="text-xs text-muted-foreground mb-1 block font-medium uppercase tracking-wider">Default Model</label>
						<div class="relative">
							<select
								id="model-select"
								bind:value={selectedModel}
								class="w-full px-3 py-2 bg-muted/50 border border-orange-400/30 rounded-lg text-sm appearance-none cursor-pointer focus:ring-2 focus:ring-orange-500/30 focus:outline-none"
							>
								{#if mistralModels.length > 0}
									{#each mistralModels as model}
										{@const meta = getModelMeta(model.name)}
										<option value={model.name}>{meta.label} — {model.name} ({formatBytes(model.size || 0)})</option>
									{/each}
								{:else}
									<option value="">No Mistral models available</option>
								{/if}
							</select>
							<ChevronDown class="w-4 h-4 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-muted-foreground" />
						</div>
					</div>
				</div>

				<!-- API Key Section -->
				<div class="border-t border-border pt-4">
					<div class="flex items-center gap-2 mb-2">
						<Cloud class="w-4 h-4 text-orange-400" />
						<span class="text-sm font-medium">API Key (OS Keychain)</span>
						{#if hasApiKey}
							<Badge variant="success" class="text-[10px]">Stored Securely</Badge>
						{/if}
					</div>
					<p class="text-xs text-muted-foreground mb-3">
						Your API key is encrypted and stored in your operating system's native keychain — never in config files.
					</p>

					{#if hasApiKey}
						<div class="flex items-center gap-2">
							<div class="flex-1 px-3 py-2 bg-muted/50 border border-border rounded-lg text-sm text-muted-foreground">
								<span class="flex items-center gap-2">
									<Key class="w-4 h-4 text-green-500" />
									<span class="font-mono text-xs tracking-widest">••••••••••••••••</span>
								</span>
							</div>
							<Button variant="destructive" size="sm" on:click={deleteApiKey} disabled={savingApiKey}>
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
										class="w-full pl-10 pr-10 py-2 bg-muted/50 border border-border rounded-lg text-sm focus:ring-2 focus:ring-orange-500/30 focus:outline-none"
										placeholder="Enter your Mistral API key"
								/>
							{:else}
								<input
									type="password"
									bind:value={apiKey}
									class="w-full pl-10 pr-10 py-2 bg-muted/50 border border-border rounded-lg text-sm focus:ring-2 focus:ring-orange-500/30 focus:outline-none"
									placeholder="Enter your Mistral API key"
									/>
								{/if}
								<button
									type="button"
									class="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
									on:click={() => showApiKey = !showApiKey}
								>
									{#if showApiKey}<EyeOff class="w-4 h-4" />{:else}<Eye class="w-4 h-4" />{/if}
								</button>
							</div>
							<Button variant="cyber" size="sm" on:click={saveApiKey} disabled={!apiKey.trim() || savingApiKey}>
								{#if savingApiKey}
									<Loader2 class="w-4 h-4 animate-spin" />
								{:else}
									<Save class="w-4 h-4" />
								{/if}
							</Button>
						</div>
					{/if}
				</div>

				<!-- Footer -->
				<div class="flex items-center justify-between pt-2 border-t border-border">
					<div class="flex items-center gap-2 text-xs text-muted-foreground">
						<Server class="w-4 h-4" />
						<span>
							{#if status?.connected}
								{mistralModels.length} Mistral model{mistralModels.length !== 1 ? 's' : ''} available
							{:else}
								Add your Mistral API key above to connect
							{/if}
						</span>
					</div>
					<div class="flex items-center gap-2">
						<Zap class="w-4 h-4 text-yellow-400" />
						<span class="text-xs text-muted-foreground">Streaming</span>
						<Switch bind:checked={streamingEnabled} />
					</div>
				</div>
			</CardContent>
		</Card>
	{/if}

	<!-- Chat Area -->
	<Card variant="glass" class="flex-1 flex flex-col overflow-hidden min-h-0">
		<CardHeader class="border-b border-border py-3 flex-shrink-0">
			<div class="flex items-center justify-between">
				<CardTitle class="text-base flex items-center gap-2">
					<Shield class="w-5 h-5 text-orange-400" />
					Security Analysis Chat
					{#if activeModel && loading}
						<Badge variant="outline" class="text-[10px] font-mono gap-1 animate-pulse border-orange-500/30 text-orange-400">
							<svelte:component this={getModelMeta(activeModel).icon} class="w-3 h-3" />
							{getModelMeta(activeModel).label}
						</Badge>
					{/if}
				</CardTitle>
				<div class="flex items-center gap-1">
					<Button variant="ghost" size="sm" on:click={() => quickAction('Analyze my current security posture and provide recommendations')} disabled={!status?.connected || loading} class="text-xs h-8">
						<ShieldCheck class="w-3.5 h-3.5 mr-1" />
						Security Audit
					</Button>
					<Button variant="ghost" size="sm" on:click={() => quickAction('Scan my Documents folder and analyze its health')} disabled={!status?.connected || loading} class="text-xs h-8">
						<FolderSearch class="w-3.5 h-3.5 mr-1" />
						Scan Folder
					</Button>
					<Button variant="ghost" size="sm" on:click={() => goto('/investigation')} class="text-xs h-8 text-amber-400 hover:text-amber-300">
						<FileSearch class="w-3.5 h-3.5 mr-1" />
						Investigation
					</Button>
					<div class="w-px h-5 bg-border mx-1" />
					<Button variant="ghost" size="sm" on:click={clearSession} class="h-8 w-8 p-0">
						<Trash2 class="w-4 h-4" />
					</Button>
				</div>
			</div>
		</CardHeader>

		<CardContent class="flex-1 overflow-y-auto p-4 space-y-5 min-h-0" bind:this={chatContainer}>
			{#if messages.length === 0}
				<!-- Empty State -->
				<div class="h-full flex flex-col items-center justify-center text-center">
					<div class="mb-6 relative">
						<MistralPixelCat size={120} animated={true} />
						<div class="absolute -bottom-1 left-1/2 -translate-x-1/2 w-20 h-2 bg-primary/10 rounded-full blur-sm" />
					</div>
					<p class="text-xl font-semibold text-foreground mb-1">What can I help you secure?</p>
					<p class="text-sm text-muted-foreground max-w-md">
						Ask me to analyze threats, audit your system, scan directories, review firewall rules, or explain any cybersecurity concept.
					</p>

					<div class="grid grid-cols-2 gap-3 mt-8 max-w-lg w-full">
						<button
							class="quick-action-card group"
							on:click={() => quickAction('What are the top security risks I should be aware of right now?')}
							disabled={!status?.connected}
						>
							<AlertTriangle class="w-5 h-5 text-orange-400 mb-2 group-hover:scale-110 transition-transform" />
							<span class="text-sm font-medium">Current threat landscape</span>
							<span class="text-xs text-muted-foreground">Top risks & mitigations</span>
						</button>
						<button
							class="quick-action-card group"
							on:click={() => quickAction('Analyze my firewall configuration and suggest improvements')}
							disabled={!status?.connected}
						>
							<Shield class="w-5 h-5 text-emerald-400 mb-2 group-hover:scale-110 transition-transform" />
							<span class="text-sm font-medium">Firewall analysis</span>
							<span class="text-xs text-muted-foreground">Review & harden rules</span>
						</button>
						<button
							class="quick-action-card group"
							on:click={() => quickAction('Scan my Downloads folder for suspicious files and malware indicators')}
							disabled={!status?.connected}
						>
							<FolderSearch class="w-5 h-5 text-blue-400 mb-2 group-hover:scale-110 transition-transform" />
							<span class="text-sm font-medium">Scan Downloads</span>
							<span class="text-xs text-muted-foreground">Check for threats</span>
						</button>
						<button
							class="quick-action-card group"
							on:click={() => goto('/investigation')}
						>
							<FileSearch class="w-5 h-5 text-amber-400 mb-2 group-hover:scale-110 transition-transform" />
							<span class="text-sm font-medium">Investigation Dossier</span>
							<span class="text-xs text-muted-foreground">Pixtral vision + voice briefing</span>
						</button>
					</div>
				</div>
			{:else}
				{#each messages as message, i}
					<div class="flex gap-3 {message.role === 'user' ? 'flex-row-reverse' : ''} animate-in">
						<!-- Avatar -->
						<div class="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0
							{message.role === 'user' ? 'bg-gradient-to-br from-blue-500 to-blue-600' : 'mistral-avatar'}">
							{#if message.role === 'user'}
								<span class="text-xs font-bold text-white">U</span>
							{:else}
								<MistralCat size={20} />
							{/if}
						</div>

						<!-- Message Bubble -->
						<div class="max-w-[80%] min-w-0 {message.role === 'user' ? 'ml-auto' : ''}">
							{#if message.role === 'assistant' && message.model}
								{@const meta = getModelMeta(message.model)}
								<div class="flex items-center gap-1.5 mb-1 text-[10px] {meta.color} font-medium">
									<svelte:component this={meta.icon} class="w-3 h-3" />
									{meta.label}
									{#if message.timestamp}
										<span class="text-muted-foreground ml-1">{timeAgo(message.timestamp)}</span>
									{/if}
								</div>
							{/if}

							<div class="rounded-2xl px-4 py-3 {message.role === 'user'
								? 'bg-blue-600/20 border border-blue-500/20'
								: 'bg-muted/40 border border-border/50'}">
								{#if message.role === 'assistant'}
									<div class="prose prose-sm dark:prose-invert max-w-none message-content">
										{#if message.streaming && message.content === ''}
											<div class="flex items-center gap-2 text-sm text-muted-foreground">
												<Loader2 class="w-4 h-4 animate-spin text-orange-400" />
												<span class="animate-pulse">Analyzing...</span>
											</div>
										{:else}
											{@html renderMarkdown(message.content)}
											{#if message.streaming}
												<span class="inline-block w-2 h-4 bg-orange-400 animate-pulse ml-0.5 rounded-sm" />
											{/if}
										{/if}
									</div>
									{#if !message.streaming && message.content && hasElevenlabsKey}
										<div class="flex items-center gap-1 mt-2 pt-2 border-t border-border/30">
											<button
												class="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-amber-400 transition-colors px-1.5 py-0.5 rounded"
												on:click={() => speakMessage(i)}
											>
												{#if speakingIdx === i}
													<Loader2 class="w-3 h-3 animate-spin" />
													<span>Speaking...</span>
												{:else}
													<Volume2 class="w-3 h-3" />
													<span>Speak</span>
												{/if}
											</button>
										</div>
									{/if}
								{:else}
									<p class="text-sm whitespace-pre-wrap text-foreground">{message.content}</p>
								{/if}
							</div>
						</div>
					</div>
				{/each}
			{/if}
		</CardContent>

		<!-- Input Area -->
		<div class="border-t border-border p-4 flex-shrink-0">
			<div class="flex gap-2 items-end">
				<textarea
					bind:value={inputMessage}
					on:keydown={handleKeydown}
					placeholder={status?.connected ? 'Describe a threat, ask for analysis, or request a scan...' : 'Connect to a Mistral endpoint to start'}
					disabled={!status?.connected || loading}
					rows="1"
					class="flex-1 px-4 py-3 bg-muted/30 border border-border rounded-xl resize-none focus:outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-500/30 disabled:opacity-50 transition-all text-sm min-h-[44px] max-h-[120px] text-foreground placeholder:text-muted-foreground"
				/>
				<Button
					variant="cyber"
					size="lg"
					on:click={sendMessage}
					disabled={!status?.connected || loading || !inputMessage.trim()}
					class="h-[44px] w-[44px] p-0 rounded-xl"
				>
					{#if loading}
						<Loader2 class="w-5 h-5 animate-spin" />
					{:else}
						<Send class="w-5 h-5" />
					{/if}
				</Button>
			</div>
			<div class="flex items-center justify-between mt-2 text-[10px] text-muted-foreground">
				<span>
					{#if selectedModel}
						{@const meta = getModelMeta(selectedModel)}
						<span class="inline-flex items-center gap-1 {meta.color}">
							<svelte:component this={meta.icon} class="w-3 h-3" />
							{meta.label}
						</span>
						<span class="mx-1 opacity-40">|</span>
					{/if}
					{streamingEnabled ? 'Streaming enabled' : 'Batch mode'}
				</span>
				<span class="opacity-60">Shift+Enter for new line</span>
			</div>
		</div>
	</Card>
</div>

<style>
	.mistral-icon-shell {
		background: #FFFFFF;
		border: 2px solid rgba(255, 130, 5, 0.25);
		box-shadow: 0 0 12px rgba(255, 130, 5, 0.1);
	}

	.mistral-avatar {
		background: linear-gradient(135deg, #FA5010, #FF8205, #FFB000);
	}

	:global(.mistral-panel) {
		border-color: rgba(255, 130, 5, 0.3);
		background:
			radial-gradient(circle at top right, rgba(250, 80, 16, 0.1), transparent 40%),
			radial-gradient(circle at bottom left, rgba(255, 130, 5, 0.08), transparent 45%);
	}

	.quick-action-card {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		padding: 1rem;
		border-radius: 0.75rem;
		border: 1px solid hsl(var(--border) / 0.5);
		background: hsl(var(--card) / 0.6);
		backdrop-filter: blur(8px);
		cursor: pointer;
		transition: all 0.2s ease;
		text-align: left;
	}

	.quick-action-card:hover:not(:disabled) {
		border-color: rgba(255, 138, 18, 0.4);
		background: hsl(var(--card) / 0.9);
		box-shadow: 0 0 20px rgba(255, 138, 18, 0.1);
		transform: translateY(-1px);
	}

	.quick-action-card:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	:global(.message-content p) {
		margin: 0.25em 0;
	}

	:global(.message-content ul),
	:global(.message-content ol) {
		margin: 0.5em 0;
		padding-left: 1.5em;
	}

	:global(.message-content li) {
		margin: 0.15em 0;
	}

	:global(.message-content) {
		color: hsl(var(--foreground));
	}

	:global(.message-content code) {
		font-size: 0.85em;
		background: hsl(var(--muted));
		color: hsl(var(--foreground));
		padding: 0.15em 0.4em;
		border-radius: 0.25em;
	}

	:global(.message-content pre) {
		background: hsl(var(--muted) / 0.7);
		border: 1px solid hsl(var(--border));
		border-radius: 0.5rem;
		padding: 0.75rem 1rem;
		overflow-x: auto;
		margin: 0.5em 0;
	}

	:global(.message-content pre code) {
		background: none;
		padding: 0;
	}

	:global(.message-content h1),
	:global(.message-content h2),
	:global(.message-content h3) {
		margin-top: 0.75em;
		margin-bottom: 0.25em;
		font-weight: 600;
		color: hsl(var(--foreground));
	}

	:global(.message-content p),
	:global(.message-content li),
	:global(.message-content span) {
		color: hsl(var(--foreground));
	}

	:global(.message-content blockquote) {
		border-left: 3px solid rgba(255, 138, 18, 0.4);
		padding-left: 0.75rem;
		margin: 0.5em 0;
		color: hsl(var(--muted-foreground));
	}

	:global(.message-content table) {
		border-collapse: collapse;
		margin: 0.5em 0;
		font-size: 0.85em;
	}

	:global(.message-content th),
	:global(.message-content td) {
		border: 1px solid hsl(var(--border));
		padding: 0.35em 0.75em;
		color: hsl(var(--foreground));
	}

	:global(.message-content th) {
		background: hsl(var(--muted) / 0.5);
	}

	:global(.message-content strong) {
		color: hsl(var(--foreground));
	}

	.animate-in {
		animation: message-in 0.25s ease-out;
	}

	@keyframes message-in {
		from { opacity: 0; transform: translateY(8px); }
		to { opacity: 1; transform: translateY(0); }
	}
</style>
