<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { invoke } from '@tauri-apps/api/tauri';
	import { listen, type UnlistenFn } from '@tauri-apps/api/event';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { marked } from 'marked';
	import {
		FileSearch,
		Upload,
		Volume2,
		VolumeX,
		Loader2,
		AlertTriangle,
		Shield,
		ShieldAlert,
		ShieldCheck,
		Eye,
		Clock,
		Fingerprint,
		Network,
		Cpu,
		Key,
		Bug,
		Settings,
		Info,
		Camera,
		Clipboard,
		Play,
		Pause,
		Square,
		Mic,
		Sparkles
	} from 'lucide-svelte';
	import type { InvestigationDossier, DossierFinding } from '$lib/api';
	import MistralLogo from '$lib/components/MistralLogo.svelte';

	let dossier: InvestigationDossier | null = null;
	let loading = false;
	let loadingStage = '';
	let loadingMessage = '';
	let error = '';
	let dragOver = false;
	let imagePreview = '';
	let imageBase64 = '';
	let contextInput = '';

	// Audio state
	let narrating = false;
	let audioPlaying = false;
	let audioElement: HTMLAudioElement | null = null;
	let audioProgress = 0;
	let audioDuration = 0;
	let hasElevenlabsKey = false;
	let hasMistralKey = false;

	// ElevenLabs settings
	let showVoiceSettings = false;
	let elevenlabsKey = '';
	let savingKey = false;

	let unlistenProgress: UnlistenFn | null = null;

	const CATEGORY_META: Record<string, { icon: typeof Shield; color: string; label: string }> = {
		network: { icon: Network, color: 'text-blue-400', label: 'Network' },
		process: { icon: Cpu, color: 'text-emerald-400', label: 'Process' },
		credential: { icon: Key, color: 'text-red-400', label: 'Credential' },
		malware: { icon: Bug, color: 'text-rose-500', label: 'Malware' },
		config: { icon: Settings, color: 'text-yellow-400', label: 'Config' },
		anomaly: { icon: AlertTriangle, color: 'text-orange-400', label: 'Anomaly' },
		info: { icon: Info, color: 'text-zinc-400', label: 'Info' },
	};

	const SEVERITY_COLORS: Record<string, string> = {
		critical: 'bg-red-500/20 text-red-400 border-red-500/40',
		high: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
		medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
		low: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
		info: 'bg-zinc-500/20 text-zinc-400 border-zinc-500/40',
	};

	function getCategoryMeta(cat: string) {
		return CATEGORY_META[cat] || CATEGORY_META['info'];
	}

	function getSeverityClass(sev: string) {
		return SEVERITY_COLORS[sev] || SEVERITY_COLORS['info'];
	}

	onMount(async () => {
		unlistenProgress = await listen<{ stage: string; message: string }>('dossier-progress', (e) => {
			loadingStage = e.payload.stage;
			loadingMessage = e.payload.message;
		});

		try {
			hasMistralKey = await invoke<boolean>('has_mistral_api_key');
			hasElevenlabsKey = await invoke<boolean>('has_elevenlabs_api_key');
		} catch { /* ignore */ }
	});

	onDestroy(() => {
		unlistenProgress?.();
		if (audioElement) {
			audioElement.pause();
			audioElement = null;
		}
	});

	function handleDragOver(e: DragEvent) {
		e.preventDefault();
		dragOver = true;
	}

	function handleDragLeave() {
		dragOver = false;
	}

	function handleDrop(e: DragEvent) {
		e.preventDefault();
		dragOver = false;
		const file = e.dataTransfer?.files?.[0];
		if (file && file.type.startsWith('image/')) {
			loadImage(file);
		}
	}

	function handleFileSelect(e: Event) {
		const input = e.target as HTMLInputElement;
		const file = input.files?.[0];
		if (file) loadImage(file);
	}

	function loadImage(file: File) {
		const reader = new FileReader();
		reader.onload = () => {
			const result = reader.result as string;
			imagePreview = result;
			imageBase64 = result.split(',')[1] || result;
		};
		reader.readAsDataURL(file);
	}

	async function handlePaste() {
		try {
			const items = await navigator.clipboard.read();
			for (const item of items) {
				const imageType = item.types.find(t => t.startsWith('image/'));
				if (imageType) {
					const blob = await item.getType(imageType);
					const file = new File([blob], 'clipboard.png', { type: imageType });
					loadImage(file);
					return;
				}
			}
		} catch {
			error = 'No image found on clipboard';
			setTimeout(() => error = '', 3000);
		}
	}

	async function generateDossier() {
		if (!imageBase64 || loading) return;
		loading = true;
		error = '';
		loadingStage = 'starting';
		loadingMessage = 'Initiating investigation...';

		try {
			dossier = await invoke<InvestigationDossier>('generate_investigation_dossier', {
				imageBase64,
				context: contextInput || null,
			});
		} catch (e: any) {
			error = e.toString();
		} finally {
			loading = false;
			loadingStage = '';
		}
	}

	async function narrateDossier() {
		if (!dossier || narrating) return;
		narrating = true;

		try {
			const audioBase64 = await invoke<string>('narrate_dossier', {
				text: dossier.narrative,
				voiceId: null,
			});

			const audioBlob = base64ToBlob(audioBase64, 'audio/mpeg');
			const audioUrl = URL.createObjectURL(audioBlob);

			audioElement = new Audio(audioUrl);
			audioElement.addEventListener('timeupdate', () => {
				if (audioElement) {
					audioProgress = audioElement.currentTime;
					audioDuration = audioElement.duration || 0;
				}
			});
			audioElement.addEventListener('ended', () => {
				audioPlaying = false;
			});
			audioElement.play();
			audioPlaying = true;
		} catch (e: any) {
			error = e.toString();
		} finally {
			narrating = false;
		}
	}

	function togglePlayback() {
		if (!audioElement) return;
		if (audioPlaying) {
			audioElement.pause();
			audioPlaying = false;
		} else {
			audioElement.play();
			audioPlaying = true;
		}
	}

	function stopPlayback() {
		if (audioElement) {
			audioElement.pause();
			audioElement.currentTime = 0;
			audioPlaying = false;
			audioProgress = 0;
		}
	}

	function base64ToBlob(b64: string, mime: string): Blob {
		const raw = atob(b64);
		const arr = new Uint8Array(raw.length);
		for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
		return new Blob([arr], { type: mime });
	}

	async function saveElevenlabsKey() {
		if (!elevenlabsKey.trim()) return;
		savingKey = true;
		try {
			await invoke('store_elevenlabs_api_key', { apiKey: elevenlabsKey.trim() });
			hasElevenlabsKey = true;
			elevenlabsKey = '';
			showVoiceSettings = false;
		} catch (e: any) {
			error = e.toString();
		} finally {
			savingKey = false;
		}
	}

	function formatDuration(s: number): string {
		const m = Math.floor(s / 60);
		const sec = Math.floor(s % 60);
		return `${m}:${sec.toString().padStart(2, '0')}`;
	}

	function clearInvestigation() {
		dossier = null;
		imagePreview = '';
		imageBase64 = '';
		contextInput = '';
		error = '';
		stopPlayback();
	}

	function renderMarkdown(text: string): string {
		try { return marked.parse(text) as string; } catch { return text; }
	}

	$: criticalCount = dossier?.findings.filter(f => f.severity === 'critical').length ?? 0;
	$: highCount = dossier?.findings.filter(f => f.severity === 'high').length ?? 0;
	$: mediumCount = dossier?.findings.filter(f => f.severity === 'medium').length ?? 0;
</script>

<svelte:head>
	<title>Investigation Dossier - Cyber Security Prime</title>
</svelte:head>

<div class="h-full flex flex-col gap-4">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-4">
			<div class="dossier-icon flex items-center justify-center w-14 h-14 rounded-2xl">
				<FileSearch class="w-7 h-7 text-amber-400" />
			</div>
			<div>
				<h1 class="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
					Investigation Dossier
					<Badge variant="outline" class="text-[10px] font-mono tracking-wider border-amber-500/40 text-amber-400">
						PIXTRAL + ELEVENLABS
					</Badge>
				</h1>
				<p class="text-muted-foreground text-sm mt-0.5">
					Upload evidence — Pixtral builds the case file — PRIME narrates the briefing
				</p>
			</div>
		</div>
		<div class="flex items-center gap-2">
			{#if !hasElevenlabsKey}
				<Button variant="outline" size="sm" on:click={() => showVoiceSettings = !showVoiceSettings} class="gap-1.5 text-xs">
					<Mic class="w-3.5 h-3.5" />
					Add Voice Key
				</Button>
			{:else}
				<Badge variant="success" class="text-[10px] gap-1">
					<Volume2 class="w-3 h-3" /> Voice Active
				</Badge>
			{/if}
			{#if dossier}
				<Button variant="outline" size="sm" on:click={clearInvestigation} class="text-xs">
					New Investigation
				</Button>
			{/if}
		</div>
	</div>

	<!-- ElevenLabs Key Setup -->
	{#if showVoiceSettings}
		<Card variant="glass" class="border-amber-500/20">
			<CardContent class="py-4">
				<div class="flex items-center gap-3">
					<Mic class="w-5 h-5 text-amber-400" />
					<div class="flex-1">
						<p class="text-sm font-medium">ElevenLabs API Key</p>
						<p class="text-xs text-muted-foreground">Required for voice narration. Stored in OS keychain.</p>
					</div>
				</div>
				<div class="flex gap-2 mt-3">
					<input
						type="password"
						bind:value={elevenlabsKey}
						placeholder="Enter your ElevenLabs API key"
						class="flex-1 px-3 py-2 bg-muted/50 border border-border rounded-lg text-sm focus:ring-2 focus:ring-amber-500/30 focus:outline-none"
					/>
					<Button variant="cyber" size="sm" on:click={saveElevenlabsKey} disabled={!elevenlabsKey.trim() || savingKey}>
						{#if savingKey}
							<Loader2 class="w-4 h-4 animate-spin" />
						{:else}
							Save
						{/if}
					</Button>
				</div>
			</CardContent>
		</Card>
	{/if}

	{#if !dossier && !loading}
		<!-- Upload State -->
		<div class="flex-1 flex flex-col gap-4">
			<Card variant="glass" class="flex-1 flex flex-col">
				<CardContent class="flex-1 flex flex-col items-center justify-center p-8">
					<!-- Drop Zone -->
					<div
						class="w-full max-w-2xl aspect-[16/10] rounded-2xl border-2 border-dashed transition-all duration-300 flex flex-col items-center justify-center gap-4 cursor-pointer relative overflow-hidden
							{dragOver ? 'border-amber-400 bg-amber-500/10 scale-[1.02]' : 'border-border/60 hover:border-amber-400/50 hover:bg-muted/30'}
							{imagePreview ? 'border-amber-500/40 bg-black/20' : ''}"
						on:dragover={handleDragOver}
						on:dragleave={handleDragLeave}
						on:drop={handleDrop}
						on:click={() => document.getElementById('file-input')?.click()}
						role="button"
						tabindex="0"
					>
						{#if imagePreview}
							<img src={imagePreview} alt="Evidence" class="absolute inset-0 w-full h-full object-contain p-2" />
							<div class="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/80 to-transparent p-4">
								<p class="text-sm text-white font-medium">Evidence loaded — ready for analysis</p>
							</div>
						{:else}
							<div class="flex items-center justify-center w-20 h-20 rounded-full bg-amber-500/10 mb-2">
								<Upload class="w-10 h-10 text-amber-400" />
							</div>
							<p class="text-lg font-semibold text-foreground">Drop screenshot evidence here</p>
							<p class="text-sm text-muted-foreground">or click to browse — PNG, JPG, WebP supported</p>
							<div class="flex gap-2 mt-4">
								<div on:click|stopPropagation={() => {}}>
									<Button variant="outline" size="sm" on:click={handlePaste} class="gap-1.5 text-xs">
										<Clipboard class="w-3.5 h-3.5" />
										Paste from Clipboard
									</Button>
								</div>
							</div>
						{/if}
					</div>

					<input id="file-input" type="file" accept="image/*" class="hidden" on:change={handleFileSelect} />

					{#if imagePreview}
						<div class="w-full max-w-2xl mt-4 space-y-3">
							<div>
								<label for="context" class="text-xs text-muted-foreground font-medium uppercase tracking-wider block mb-1.5">
									Investigation Context (optional)
								</label>
								<input
									id="context"
									type="text"
									bind:value={contextInput}
									placeholder="e.g., Suspicious activity on endpoint DESK-042, potential lateral movement"
									class="w-full px-4 py-2.5 bg-muted/30 border border-border rounded-xl text-sm focus:ring-2 focus:ring-amber-500/30 focus:outline-none"
								/>
							</div>
							<Button
								variant="cyber"
								class="w-full gap-2 h-12 text-base"
								on:click={generateDossier}
								disabled={!hasMistralKey}
							>
								<Eye class="w-5 h-5" />
								Launch Investigation
							</Button>
							{#if !hasMistralKey}
								<p class="text-xs text-red-400 text-center">Mistral API key required — add it in the Copilot settings</p>
							{/if}
						</div>
					{/if}
				</CardContent>
			</Card>
		</div>

	{:else if loading}
		<!-- Loading State -->
		<div class="flex-1 flex flex-col items-center justify-center gap-6">
			<div class="relative">
				<div class="w-32 h-32 rounded-full border-4 border-amber-500/20 flex items-center justify-center">
					<div class="w-24 h-24 rounded-full border-4 border-amber-500/40 border-t-amber-400 animate-spin flex items-center justify-center">
						<Eye class="w-10 h-10 text-amber-400 animate-pulse" />
					</div>
				</div>
				<div class="absolute -bottom-2 left-1/2 -translate-x-1/2 w-24 h-3 bg-amber-500/10 rounded-full blur-md" />
			</div>
			<div class="text-center">
				<p class="text-lg font-semibold text-foreground">{loadingMessage || 'Initializing...'}</p>
				<p class="text-sm text-muted-foreground mt-1">
					{#if loadingStage === 'analyzing'}
						Pixtral is examining every pixel for security-relevant evidence
					{:else if loadingStage === 'narrating'}
						Mistral Large is composing your intelligence briefing
					{:else}
						Preparing forensic analysis pipeline
					{/if}
				</p>
			</div>
		</div>

	{:else if dossier}
		<!-- Dossier Display -->
		<div class="flex-1 flex flex-col gap-4 overflow-y-auto min-h-0 pr-1">
			<!-- Classification Banner -->
			<div class="dossier-banner flex items-center justify-between px-6 py-3 rounded-xl">
				<div class="flex items-center gap-3">
					<Fingerprint class="w-5 h-5 text-amber-400" />
					<span class="font-mono text-sm font-bold tracking-[0.3em] text-amber-400">
						{dossier.classification}
					</span>
				</div>
				<div class="flex items-center gap-4 text-xs text-muted-foreground font-mono">
					<span class="flex items-center gap-1">
						<Clock class="w-3.5 h-3.5" />
						{dossier.created_at}
					</span>
					<span>CASE {dossier.case_id}</span>
				</div>
			</div>

			<div class="grid grid-cols-3 gap-3">
				<!-- Risk Assessment -->
				<Card variant="glass" class="col-span-1 {dossier.risk_assessment.startsWith('CRITICAL') ? 'border-red-500/40' : dossier.risk_assessment.startsWith('HIGH') ? 'border-orange-500/40' : 'border-border/50'}">
					<CardContent class="py-4 text-center">
						{#if dossier.risk_assessment.startsWith('CRITICAL')}
							<ShieldAlert class="w-10 h-10 text-red-400 mx-auto mb-2" />
						{:else if dossier.risk_assessment.startsWith('HIGH')}
							<AlertTriangle class="w-10 h-10 text-orange-400 mx-auto mb-2" />
						{:else}
							<ShieldCheck class="w-10 h-10 text-emerald-400 mx-auto mb-2" />
						{/if}
						<p class="text-xs font-mono font-bold uppercase tracking-wider text-muted-foreground">Risk Level</p>
						<p class="text-sm font-bold mt-1 text-foreground">{dossier.risk_assessment.split(' — ')[0]}</p>
						<p class="text-xs text-muted-foreground mt-0.5">{dossier.risk_assessment.split(' — ')[1] || ''}</p>
					</CardContent>
				</Card>

				<!-- Finding Stats -->
				<Card variant="glass" class="col-span-1">
					<CardContent class="py-4 text-center">
						<p class="text-3xl font-bold text-foreground">{dossier.findings.length}</p>
						<p class="text-xs font-mono font-bold uppercase tracking-wider text-muted-foreground mt-1">Findings</p>
						<div class="flex items-center justify-center gap-3 mt-3">
							{#if criticalCount > 0}
								<span class="text-xs font-bold text-red-400">{criticalCount} CRIT</span>
							{/if}
							{#if highCount > 0}
								<span class="text-xs font-bold text-orange-400">{highCount} HIGH</span>
							{/if}
							{#if mediumCount > 0}
								<span class="text-xs font-bold text-yellow-400">{mediumCount} MED</span>
							{/if}
						</div>
					</CardContent>
				</Card>

				<!-- Brief Me Button -->
				<Card variant="glass" class="col-span-1 flex flex-col">
					<CardContent class="py-4 flex flex-col items-center justify-center flex-1 gap-2">
						{#if audioPlaying}
							<div class="flex items-center gap-2">
								<Button variant="outline" size="sm" on:click={togglePlayback} class="h-10 w-10 p-0 rounded-full border-amber-500/40">
									<Pause class="w-5 h-5 text-amber-400" />
								</Button>
								<Button variant="outline" size="sm" on:click={stopPlayback} class="h-10 w-10 p-0 rounded-full">
									<Square class="w-4 h-4" />
								</Button>
							</div>
							<div class="w-full bg-muted/50 rounded-full h-1.5 mt-1">
								<div
									class="bg-amber-400 h-full rounded-full transition-all"
									style="width: {audioDuration > 0 ? (audioProgress / audioDuration) * 100 : 0}%"
								/>
							</div>
							<p class="text-[10px] text-muted-foreground font-mono">
								{formatDuration(audioProgress)} / {formatDuration(audioDuration)}
							</p>
						{:else if narrating}
							<Loader2 class="w-8 h-8 text-amber-400 animate-spin" />
							<p class="text-xs text-muted-foreground">Generating voice briefing...</p>
						{:else}
							<Button
								variant="cyber"
								class="gap-2 w-full"
								on:click={narrateDossier}
								disabled={!hasElevenlabsKey}
							>
								<Volume2 class="w-5 h-5" />
								Brief Me
							</Button>
							{#if !hasElevenlabsKey}
								<p class="text-[10px] text-muted-foreground text-center">ElevenLabs key needed</p>
							{:else}
								<p class="text-[10px] text-muted-foreground text-center">PRIME narrates the dossier</p>
							{/if}
						{/if}
					</CardContent>
				</Card>
			</div>

			<!-- Evidence Image -->
			{#if imagePreview}
				<Card variant="glass">
					<CardHeader class="py-3">
						<CardTitle class="text-sm flex items-center gap-2">
							<Camera class="w-4 h-4 text-amber-400" />
							<span class="font-mono uppercase tracking-wider text-xs">Exhibit A — Source Evidence</span>
						</CardTitle>
					</CardHeader>
					<CardContent class="py-0 pb-4">
						<div class="rounded-lg overflow-hidden border border-border/50 bg-black/20 max-h-64">
							<img src={imagePreview} alt="Evidence" class="w-full h-full object-contain max-h-64" />
						</div>
					</CardContent>
				</Card>
			{/if}

			<!-- Findings -->
			<Card variant="glass">
				<CardHeader class="py-3 border-b border-border/50">
					<CardTitle class="text-sm flex items-center gap-2">
						<Eye class="w-4 h-4 text-amber-400" />
						<span class="font-mono uppercase tracking-wider text-xs">Forensic Findings</span>
					</CardTitle>
				</CardHeader>
				<CardContent class="py-0">
					{#each dossier.findings as finding, i}
						{@const meta = getCategoryMeta(finding.category)}
						<div class="flex gap-4 py-4 {i < dossier.findings.length - 1 ? 'border-b border-border/30' : ''}">
							<!-- Timeline Indicator -->
							<div class="flex flex-col items-center gap-1 pt-1">
								<div class="w-8 h-8 rounded-lg flex items-center justify-center bg-muted/50 {meta.color}">
									<svelte:component this={meta.icon} class="w-4 h-4" />
								</div>
								{#if i < dossier.findings.length - 1}
									<div class="w-px flex-1 bg-border/30 min-h-[20px]" />
								{/if}
							</div>

							<!-- Finding Content -->
							<div class="flex-1 min-w-0">
								<div class="flex items-center gap-2 mb-1">
									<span class="text-[10px] font-mono text-muted-foreground">{finding.id}</span>
									<Badge class="text-[10px] px-1.5 py-0 border {getSeverityClass(finding.severity)}">
										{finding.severity.toUpperCase()}
									</Badge>
									<Badge variant="outline" class="text-[10px] px-1.5 py-0 {meta.color}">
										{meta.label}
									</Badge>
									<span class="text-[10px] text-muted-foreground ml-auto font-mono">
										{finding.timestamp}
									</span>
								</div>
								<p class="text-sm font-semibold text-foreground">{finding.title}</p>
								<p class="text-xs text-muted-foreground mt-0.5 leading-relaxed">{finding.detail}</p>
								<div class="flex items-center gap-2 mt-1.5">
									<div class="h-1 flex-1 max-w-[100px] bg-muted/50 rounded-full overflow-hidden">
										<div
											class="h-full rounded-full {finding.confidence > 0.8 ? 'bg-red-400' : finding.confidence > 0.5 ? 'bg-yellow-400' : 'bg-blue-400'}"
											style="width: {finding.confidence * 100}%"
										/>
									</div>
									<span class="text-[10px] text-muted-foreground">{Math.round(finding.confidence * 100)}% confidence</span>
								</div>
							</div>
						</div>
					{/each}
				</CardContent>
			</Card>

			<!-- Intelligence Briefing Narrative -->
			<Card variant="glass" class="dossier-narrative">
				<CardHeader class="py-3 border-b border-border/50">
					<div class="flex items-center justify-between">
						<CardTitle class="text-sm flex items-center gap-2">
							<Sparkles class="w-4 h-4 text-amber-400" />
							<span class="font-mono uppercase tracking-wider text-xs">Intelligence Briefing — Agent PRIME</span>
						</CardTitle>
						{#if hasElevenlabsKey && !audioPlaying && !narrating}
							<Button variant="ghost" size="sm" on:click={narrateDossier} class="text-xs gap-1.5 h-7">
								<Volume2 class="w-3.5 h-3.5" />
								Read Aloud
							</Button>
						{/if}
					</div>
				</CardHeader>
				<CardContent class="py-4">
					<div class="prose prose-sm dark:prose-invert max-w-none narrative-text">
						{@html renderMarkdown(dossier.narrative)}
					</div>
				</CardContent>
			</Card>

			<!-- Analyst Notes -->
			<div class="text-xs text-muted-foreground font-mono text-center py-2 opacity-60">
				{dossier.analyst_notes} • Subject: {dossier.subject}
			</div>
		</div>
	{/if}

	<!-- Error -->
	{#if error}
		<div class="fixed bottom-4 right-4 bg-red-500/10 border border-red-500/40 text-red-400 px-4 py-3 rounded-xl text-sm max-w-md z-50">
			<p class="font-medium">Investigation Error</p>
			<p class="text-xs mt-1 opacity-80">{error}</p>
		</div>
	{/if}
</div>

<style>
	.dossier-icon {
		background: linear-gradient(135deg, rgba(245, 158, 11, 0.15), rgba(234, 88, 12, 0.1));
		border: 2px solid rgba(245, 158, 11, 0.25);
		box-shadow: 0 0 20px rgba(245, 158, 11, 0.1);
	}

	.dossier-banner {
		background:
			repeating-linear-gradient(
				-45deg,
				transparent,
				transparent 10px,
				rgba(245, 158, 11, 0.03) 10px,
				rgba(245, 158, 11, 0.03) 20px
			),
			linear-gradient(135deg, rgba(245, 158, 11, 0.08), rgba(234, 88, 12, 0.05));
		border: 1px solid rgba(245, 158, 11, 0.3);
	}

	.dossier-narrative {
		border-color: rgba(245, 158, 11, 0.2);
		background:
			radial-gradient(circle at top right, rgba(245, 158, 11, 0.06), transparent 50%),
			radial-gradient(circle at bottom left, rgba(234, 88, 12, 0.04), transparent 50%);
	}

	:global(.narrative-text p) {
		margin: 0.5em 0;
		line-height: 1.7;
		color: hsl(var(--foreground));
	}

	:global(.narrative-text strong) {
		color: rgb(251 191 36);
	}

	:global(.narrative-text em) {
		color: hsl(var(--muted-foreground));
	}
</style>
