<script lang="ts">
	import { onMount } from 'svelte';
	import { theme } from '$lib/stores/theme';
	import { initSecurityData } from '$lib/stores/security';
	import Sidebar from '$lib/components/Sidebar.svelte';
	import ScanWidget from '$lib/components/ScanWidget.svelte';
	import MistralPixelCat from '$lib/components/MistralPixelCat.svelte';
	import '../app.css';

	let sidebarCollapsed = false;
	let mounted = false;

	onMount(async () => {
		// Initialize theme
		theme.init();
		
		// Load security data
		await initSecurityData();
		
		mounted = true;
	});
</script>

<div class="flex h-screen overflow-hidden bg-background cyber-bg">
	<!-- Sidebar -->
	<Sidebar bind:collapsed={sidebarCollapsed} />

	<!-- Main Content -->
	<main class="flex-1 overflow-auto">
		<div class="min-h-full p-6">
		{#if mounted}
			<slot />
		{:else}
				<!-- Loading state -->
				<div class="flex items-center justify-center h-full">
					<div class="flex flex-col items-center gap-5">
						<MistralPixelCat size={120} animated={true} />
						<div class="flex flex-col items-center gap-2">
							<span class="text-sm text-foreground font-bold tracking-wider">
								SECURITY PRIME
							</span>
							<div class="flex items-center gap-1">
								{#each ['#E10500', '#FA5010', '#FF8205', '#FFB000', '#FFD800'] as color, i}
									<div
										class="w-2 h-2 rounded-sm animate-pulse"
										style="background: {color}; animation-delay: {i * 150}ms;"
									/>
								{/each}
							</div>
							<span class="text-xs text-muted-foreground font-medium tracking-wider">
								INITIALIZING SYSTEMS...
							</span>
						</div>
					</div>
				</div>
			{/if}
		</div>
	</main>
</div>

<ScanWidget />

<!-- Global scan line effect (optimized: uses will-change for GPU acceleration, reduced opacity) -->
<!-- Note: Animation paused when tab is not visible via CSS media query -->
<div class="fixed inset-0 pointer-events-none overflow-hidden opacity-10 scan-line-container">
	<div class="absolute left-0 right-0 h-px bg-gradient-to-r from-transparent via-primary/30 to-transparent animate-scan-line will-change-transform" />
</div>

<style>
	/* Pause animation when page is not visible to save resources */
	@media (prefers-reduced-motion: reduce) {
		.scan-line-container {
			display: none;
		}
	}
	
	/* Also hide when document is hidden (tab not active) */
	:global(html.hidden) .scan-line-container {
		display: none;
	}
</style>

