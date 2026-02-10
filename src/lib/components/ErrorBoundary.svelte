<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, CardContent } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { AlertTriangle, RefreshCw } from 'lucide-svelte';

	export let error: Error | null = null;
	export let title = 'Something went wrong';
	export let description = 'An error occurred while loading this content.';

	function handleRetry() {
		window.location.reload();
	}
</script>

{#if error}
	<Card variant="glass" class="border-neon-red/30">
		<CardContent class="py-8">
			<div class="flex flex-col items-center text-center space-y-4">
				<div class="w-16 h-16 rounded-full bg-neon-red/10 flex items-center justify-center">
					<AlertTriangle class="w-8 h-8 text-neon-red" />
				</div>
				<div>
					<h3 class="text-lg font-semibold">{title}</h3>
					<p class="text-sm text-muted-foreground mt-1">{description}</p>
				</div>
				{#if error.message}
					<pre class="text-xs bg-muted/50 p-3 rounded-lg max-w-md overflow-auto">
						{error.message}
					</pre>
				{/if}
				<Button variant="outline" on:click={handleRetry}>
					<RefreshCw class="w-4 h-4 mr-2" />
					Try Again
				</Button>
			</div>
		</CardContent>
	</Card>
{:else}
	<slot />
{/if}

