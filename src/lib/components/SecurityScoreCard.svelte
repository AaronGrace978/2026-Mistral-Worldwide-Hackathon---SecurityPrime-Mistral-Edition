<script lang="ts">
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { cn } from '$lib/utils';
	import type { SecurityScore } from '$lib/api';
	import { Shield } from 'lucide-svelte';

	export let score: SecurityScore | null;
	export let loading = false;

	$: displayScore = score?.score ?? 0;
	$: grade = score?.grade ?? '--';
	
	// Calculate circle properties
	const radius = 80;
	const circumference = 2 * Math.PI * radius;
	$: dashOffset = circumference - (displayScore / 100) * circumference;

	// Get color based on score
	$: scoreColor = displayScore >= 80 
		? 'text-neon-green' 
		: displayScore >= 60 
			? 'text-neon-yellow' 
			: displayScore >= 40 
				? 'text-cyber-orange' 
				: 'text-neon-red';

	$: strokeColor = displayScore >= 80 
		? '#00ff88' 
		: displayScore >= 60 
			? '#eab308' 
			: displayScore >= 40 
				? '#ffaa00' 
				: '#ff0044';
</script>

<Card variant="glass" class="relative overflow-hidden">
	<!-- Background glow effect -->
	<div 
		class="absolute inset-0 opacity-20 pointer-events-none"
		style="background: radial-gradient(circle at 50% 50%, {strokeColor}33 0%, transparent 70%);"
	/>

	<CardHeader class="pb-2">
		<CardTitle class="flex items-center gap-2 text-lg">
			<Shield class="w-5 h-5 text-primary" />
			Security Score
		</CardTitle>
	</CardHeader>

	<CardContent class="flex flex-col items-center">
		{#if loading}
			<div class="w-48 h-48 flex items-center justify-center">
				<div class="w-16 h-16 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
			</div>
		{:else}
			<!-- Score Circle -->
			<div class="relative w-48 h-48">
				<svg class="w-full h-full progress-ring" viewBox="0 0 200 200">
					<!-- Background circle -->
					<circle
						cx="100"
						cy="100"
						r={radius}
						fill="none"
						stroke="hsl(var(--muted))"
						stroke-width="12"
					/>
					<!-- Progress circle -->
					<circle
						cx="100"
						cy="100"
						r={radius}
						fill="none"
						stroke={strokeColor}
						stroke-width="12"
						stroke-linecap="round"
						stroke-dasharray={circumference}
						stroke-dashoffset={dashOffset}
						class="progress-ring-circle drop-shadow-[0_0_10px_var(--tw-shadow-color)]"
						style="--tw-shadow-color: {strokeColor};"
					/>
				</svg>
				
				<!-- Score display -->
				<div class="absolute inset-0 flex flex-col items-center justify-center">
					<span class={cn('text-5xl font-cyber font-bold', scoreColor)}>
						{displayScore}
					</span>
					<span class="text-sm text-muted-foreground mt-1">out of 100</span>
					<span class={cn('text-2xl font-bold mt-2', scoreColor)}>
						{grade}
					</span>
				</div>
			</div>

			<!-- Breakdown -->
			{#if score?.breakdown}
				<div class="w-full mt-6 grid grid-cols-2 gap-3">
					{#each Object.entries(score.breakdown) as [key, value]}
						<div class="flex items-center justify-between px-3 py-2 rounded-lg bg-muted/50">
							<span class="text-xs text-muted-foreground capitalize">{key}</span>
							<span class={cn(
								'text-sm font-medium',
								value >= 80 ? 'text-neon-green' : value >= 60 ? 'text-neon-yellow' : 'text-neon-red'
							)}>
								{value}%
							</span>
						</div>
					{/each}
				</div>
			{/if}
		{/if}
	</CardContent>
</Card>

