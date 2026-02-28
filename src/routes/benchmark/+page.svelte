<script lang="ts">
	import { onMount } from 'svelte';
	import * as api from '$lib/api';
	import type { BenchmarkComparison } from '$lib/api';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { cn } from '$lib/utils';
	import { Target, TrendingUp, TrendingDown, Minus, Users, Trophy, BarChart3 } from 'lucide-svelte';

	let benchmark: BenchmarkComparison | null = null;
	let loading = true;

	onMount(async () => {
		try {
			benchmark = await api.getBenchmarkComparison();
		} catch (e) {
			console.error('Failed to load benchmark:', e);
		} finally {
			loading = false;
		}
	});

	function getStatusIcon(status: string) {
		return status === 'above' ? TrendingUp : TrendingDown;
	}

	function getPercentileLabel(p: number): string {
		if (p >= 90) return 'Elite';
		if (p >= 75) return 'Above Average';
		if (p >= 50) return 'Average';
		if (p >= 25) return 'Below Average';
		return 'Needs Work';
	}

	function getPercentileColor(p: number): string {
		if (p >= 90) return 'text-green-400';
		if (p >= 75) return 'text-emerald-400';
		if (p >= 50) return 'text-yellow-400';
		if (p >= 25) return 'text-orange-400';
		return 'text-red-400';
	}
</script>

<div class="flex-1 p-6 space-y-6 max-w-5xl mx-auto">
	<!-- Header -->
	<div class="flex items-center gap-4">
		<div class="p-3 rounded-xl bg-gradient-to-br from-purple-500/20 to-indigo-500/20 border border-purple-500/30">
			<Target class="w-8 h-8 text-purple-400" />
		</div>
		<div>
			<h1 class="text-2xl font-bold text-foreground">Benchmark Mode</h1>
			<p class="text-muted-foreground">Compare your security posture against anonymized baselines</p>
		</div>
	</div>

	{#if loading}
		<div class="flex items-center justify-center py-20">
			<div class="w-10 h-10 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
		</div>
	{:else if benchmark}
		<!-- Top Cards -->
		<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
			<!-- Your Score -->
			<Card variant="glass" class="text-center">
				<CardContent class="pt-6 pb-6 flex flex-col items-center">
					<Trophy class="w-6 h-6 text-primary mb-2" />
					<p class="text-xs text-muted-foreground mb-1">Your Score</p>
					<p class="text-4xl font-bold text-foreground">{benchmark.your_score}</p>
				</CardContent>
			</Card>

			<!-- Average -->
			<Card variant="glass" class="text-center">
				<CardContent class="pt-6 pb-6 flex flex-col items-center">
					<Users class="w-6 h-6 text-muted-foreground mb-2" />
					<p class="text-xs text-muted-foreground mb-1">Community Average</p>
					<p class="text-4xl font-bold text-muted-foreground">{benchmark.average_score}</p>
				</CardContent>
			</Card>

			<!-- Percentile -->
			<Card variant="glass" class="text-center">
				<CardContent class="pt-6 pb-6 flex flex-col items-center">
					<BarChart3 class={cn('w-6 h-6 mb-2', getPercentileColor(benchmark.percentile))} />
					<p class="text-xs text-muted-foreground mb-1">Your Percentile</p>
					<p class={cn('text-4xl font-bold', getPercentileColor(benchmark.percentile))}>
						{benchmark.percentile}<span class="text-lg">th</span>
					</p>
					<Badge variant="outline" class="mt-1 text-[10px]">{getPercentileLabel(benchmark.percentile)}</Badge>
				</CardContent>
			</Card>
		</div>

		<!-- Visual comparison bar -->
		<Card variant="glass">
			<CardHeader class="pb-2">
				<CardTitle class="text-lg">Score Distribution</CardTitle>
			</CardHeader>
			<CardContent>
				<div class="relative h-10 bg-muted/30 rounded-full overflow-hidden">
					<!-- Average marker -->
					<div
						class="absolute top-0 h-full w-0.5 bg-muted-foreground/60 z-10"
						style="left: {benchmark.average_score}%;"
					/>
					<!-- Top 10% marker -->
					<div
						class="absolute top-0 h-full w-0.5 bg-green-500/60 z-10"
						style="left: {benchmark.top_10_percent}%;"
					/>
					<!-- Your score fill -->
					<div
						class="h-full rounded-full transition-all duration-1000"
						style="width: {benchmark.your_score}%; background: linear-gradient(90deg, #FF8205, #FFD800);"
					/>
				</div>
				<div class="flex justify-between mt-2 text-[10px] text-muted-foreground">
					<span>0</span>
					<div class="flex items-center gap-4">
						<span class="flex items-center gap-1"><span class="w-2 h-0.5 bg-muted-foreground/60 inline-block" /> Avg ({benchmark.average_score})</span>
						<span class="flex items-center gap-1"><span class="w-2 h-0.5 bg-green-500/60 inline-block" /> Top 10% ({benchmark.top_10_percent})</span>
					</div>
					<span>100</span>
				</div>
				<p class="text-center text-xs text-muted-foreground mt-3">
					Based on {benchmark.sample_size.toLocaleString()} anonymized SecurityPrime deployments
				</p>
			</CardContent>
		</Card>

		<!-- Category breakdown -->
		<Card variant="glass">
			<CardHeader class="pb-2">
				<CardTitle class="text-lg">Category Comparison</CardTitle>
			</CardHeader>
			<CardContent>
				<div class="space-y-4">
					{#each benchmark.categories as cat (cat.name)}
						{@const diff = cat.your_value - cat.average_value}
						{@const StatusIcon = getStatusIcon(cat.status)}
						<div>
							<div class="flex items-center justify-between mb-1.5">
								<span class="text-sm font-medium text-foreground">{cat.name}</span>
								<div class="flex items-center gap-2">
									<span class={cn(
										'text-xs font-medium flex items-center gap-1',
										cat.status === 'above' ? 'text-green-400' : 'text-red-400'
									)}>
										<StatusIcon class="w-3.5 h-3.5" />
										{diff > 0 ? '+' : ''}{diff} pts
									</span>
								</div>
							</div>
							<div class="relative h-5 bg-muted/30 rounded-full overflow-hidden">
								<!-- Average line -->
								<div
									class="absolute top-0 h-full w-0.5 bg-white/20 z-10"
									style="left: {cat.average_value}%;"
								/>
								<!-- Your value -->
								<div
									class={cn(
										'h-full rounded-full transition-all duration-700',
										cat.status === 'above' ? 'bg-green-500/60' : 'bg-red-500/40'
									)}
									style="width: {cat.your_value}%;"
								/>
							</div>
							<div class="flex justify-between mt-0.5 text-[10px] text-muted-foreground">
								<span>You: {cat.your_value}%</span>
								<span>Avg: {cat.average_value}%</span>
							</div>
						</div>
					{/each}
				</div>
			</CardContent>
		</Card>
	{:else}
		<Card variant="glass">
			<CardContent class="pt-6 text-center text-muted-foreground">
				<p>Failed to load benchmark data. Try again later.</p>
			</CardContent>
		</Card>
	{/if}
</div>
