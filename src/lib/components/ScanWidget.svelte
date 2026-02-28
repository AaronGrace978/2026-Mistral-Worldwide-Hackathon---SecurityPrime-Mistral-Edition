<script lang="ts">
	import { scanStore, isScanning } from '$lib/stores/scanner';
	import { goto } from '$app/navigation';
	import { Shield, Square, Loader2, X } from 'lucide-svelte';
	import { fly } from 'svelte/transition';

	let minimized = false;

	$: progress = $scanStore.scanStatus?.progress ?? 0;
	$: threatsFound = $scanStore.scanStatus?.threats_found ?? 0;
	$: scannedFiles = $scanStore.scanStatus?.scanned_files ?? 0;
	$: currentFile = $scanStore.scanStatus?.current_file ?? 'Scanning...';
	const basicNames: Record<string, string> = { quick: 'Quick Scan', full: 'Full Scan', custom: 'Custom Scan' };
	const advancedNames: Record<string, string> = { memory: 'Memory Forensics', behavioral: 'Behavioral Analysis', yara: 'YARA Scan', comprehensive: 'Comprehensive Scan' };
	$: scanLabel = $scanStore.scanMode === 'advanced'
		? advancedNames[$scanStore.advancedScanType] ?? 'Advanced Scan'
		: basicNames[$scanStore.scanType] ?? 'Scan';
</script>

{#if $isScanning}
	<div
		class="fixed bottom-6 right-6 z-50"
		transition:fly={{ y: 100, duration: 300 }}
	>
		{#if minimized}
			<button
				class="flex items-center gap-2 px-4 py-3 rounded-2xl bg-card border border-primary/40 shadow-lg shadow-primary/10 backdrop-blur-xl cursor-pointer hover:border-primary/60 transition-all"
				on:click={() => minimized = false}
			>
				<div class="w-5 h-5 rounded-full border-2 border-primary border-t-transparent animate-spin" />
				<span class="text-sm font-medium">{Math.round(progress)}%</span>
				{#if threatsFound > 0}
					<span class="text-xs text-red-400 font-bold">{threatsFound} threats</span>
				{/if}
			</button>
		{:else}
			<div class="w-80 rounded-2xl bg-card border border-primary/30 shadow-2xl shadow-primary/10 backdrop-blur-xl overflow-hidden">
				<div class="flex items-center justify-between px-4 py-3 border-b border-border/50">
					<div class="flex items-center gap-2">
						<Shield class="w-4 h-4 text-primary" />
						<span class="text-sm font-semibold">{scanLabel}</span>
					</div>
					<div class="flex items-center gap-1">
						<button
							class="p-1 rounded hover:bg-muted/50 text-muted-foreground hover:text-foreground transition-colors"
							on:click={() => minimized = true}
							title="Minimize"
						>
							<div class="w-3 h-0.5 bg-current rounded" />
						</button>
						<button
							class="p-1 rounded hover:bg-red-500/20 text-muted-foreground hover:text-red-400 transition-colors"
							on:click={() => scanStore.stopScan()}
							title="Stop scan"
						>
							<X class="w-3.5 h-3.5" />
						</button>
					</div>
				</div>

				<div class="px-4 py-3 space-y-3">
					<div class="flex items-center justify-between text-sm">
						<span class="text-muted-foreground">Progress</span>
						<span class="font-mono font-bold text-foreground">{Math.round(progress)}%</span>
					</div>

					<div class="w-full h-2 bg-muted rounded-full overflow-hidden">
						<div
							class="h-full bg-gradient-to-r from-primary to-yellow-400 rounded-full transition-all duration-300"
							style="width: {progress}%"
						/>
					</div>

					<div class="flex justify-between text-xs text-muted-foreground">
						<span>{scannedFiles.toLocaleString()} files</span>
						{#if threatsFound > 0}
							<span class="text-red-400 font-semibold">{threatsFound} threats</span>
						{:else}
							<span class="text-green-400">No threats</span>
						{/if}
					</div>

					<p class="text-[11px] text-muted-foreground truncate">{currentFile}</p>

					<button
						class="w-full text-center text-xs text-primary hover:text-primary/80 transition-colors py-1"
						on:click={() => goto('/scanner')}
					>
						View details
					</button>
				</div>
			</div>
		{/if}
	</div>
{/if}
