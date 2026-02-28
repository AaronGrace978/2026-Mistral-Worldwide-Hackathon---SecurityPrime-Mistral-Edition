<script lang="ts">
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { cn } from '$lib/utils';
	import type { SecurityScore, ScoreImprovement } from '$lib/api';
	import { Shield, TrendingUp, ChevronRight } from 'lucide-svelte';
	import { goto } from '$app/navigation';

	export let score: SecurityScore | null;
	export let loading = false;

	$: displayScore = score?.score ?? 0;
	$: grade = score?.grade ?? '--';
	$: improvements = (score?.improvements ?? []).slice(0, 4);
	$: potentialGain = improvements.reduce((sum, i) => sum + i.points, 0);
	
	const radius = 80;
	const circumference = 2 * Math.PI * radius;
	$: dashOffset = circumference - (displayScore / 100) * circumference;

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

	function handleImprovement(imp: ScoreImprovement) {
		if (imp.action === 'navigate') {
			const routes: Record<string, string> = {
				firewall: '/firewall',
				antivirus: '/scanner',
				encryption: '/encryption',
				vulnerabilities: '/vulnerability'
			};
			goto(routes[imp.category] || '/');
		} else if (imp.action === 'toggle_module') {
			goto('/hardening-wizard');
		}
	}
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

		<!-- Actionable Improvements -->
		{#if improvements.length > 0}
			<div class="w-full mt-5 pt-4 border-t border-border/50">
				<div class="flex items-center justify-between mb-3">
					<div class="flex items-center gap-1.5">
						<TrendingUp class="w-3.5 h-3.5 text-primary" />
						<span class="text-xs font-semibold text-foreground">Boost Your Score</span>
					</div>
					{#if potentialGain > 0}
						<span class="text-[10px] font-medium text-green-400">+{potentialGain} pts possible</span>
					{/if}
				</div>
				<div class="space-y-1.5">
					{#each improvements as imp (imp.id)}
						<button
							class="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg bg-muted/30 hover:bg-primary/10 border border-transparent hover:border-primary/30 transition-all text-left group"
							on:click={() => handleImprovement(imp)}
						>
							<span class="text-xs font-bold text-green-400 shrink-0 w-9 text-right">+{imp.points}</span>
							<span class="text-xs text-foreground flex-1 truncate">{imp.title}</span>
							<ChevronRight class="w-3.5 h-3.5 text-muted-foreground group-hover:text-primary transition-colors shrink-0" />
						</button>
					{/each}
				</div>
			</div>
		{/if}
	{/if}
</CardContent>
</Card>

