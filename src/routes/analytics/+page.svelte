<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { 
		BarChart3, 
		TrendingUp, 
		TrendingDown, 
		Minus,
		Shield,
		AlertTriangle,
		CheckCircle,
		Clock,
		RefreshCw,
		Filter,
		Calendar
	} from 'lucide-svelte';
	import * as api from '$lib/api';

	let stats: api.ThreatStats | null = null;
	let history: api.ThreatEvent[] = [];
	let loading = true;
	let selectedDays = 14;

	onMount(async () => {
		await loadData();
	});

	async function loadData() {
		loading = true;
		try {
			[stats, history] = await Promise.all([
				api.getThreatStats(),
				api.getThreatHistory({ days: selectedDays, limit: 50 })
			]);
		} catch (e) {
			console.error('Failed to load analytics:', e);
		} finally {
			loading = false;
		}
	}

	function getSeverityColor(severity: string): string {
		switch (severity.toLowerCase()) {
			case 'critical': return 'text-neon-red';
			case 'high': return 'text-orange-500';
			case 'medium': return 'text-neon-yellow';
			case 'low': return 'text-neon-green';
			default: return 'text-muted-foreground';
		}
	}

	function getSeverityBg(severity: string): string {
		switch (severity.toLowerCase()) {
			case 'critical': return 'bg-neon-red/20';
			case 'high': return 'bg-orange-500/20';
			case 'medium': return 'bg-neon-yellow/20';
			case 'low': return 'bg-neon-green/20';
			default: return 'bg-muted';
		}
	}

	function formatDate(dateStr: string): string {
		return new Date(dateStr).toLocaleDateString('en-US', {
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit'
		});
	}

	// Calculate chart dimensions
	$: maxDailyCount = stats ? Math.max(...stats.daily_counts.map(d => d.count), 1) : 1;
	$: maxHourlyCount = stats ? Math.max(...stats.hourly_distribution.map(h => h.count), 1) : 1;
</script>

<svelte:head>
	<title>Security Analytics - Cyber Security Prime</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-3">
			<div class="flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-cyber-purple to-neon-pink">
				<BarChart3 class="w-6 h-6 text-white" />
			</div>
			<div>
				<h1 class="text-2xl font-bold tracking-tight text-foreground">
					Security Analytics
				</h1>
				<p class="text-muted-foreground text-sm">
					Historical threat analysis and trends
				</p>
			</div>
		</div>
		<div class="flex items-center gap-2">
			<select 
				bind:value={selectedDays}
				on:change={loadData}
				class="px-3 py-2 bg-muted/50 border border-border rounded-lg text-sm"
			>
				<option value={7}>Last 7 days</option>
				<option value={14}>Last 14 days</option>
				<option value={30}>Last 30 days</option>
				<option value={90}>Last 90 days</option>
			</select>
			<Button variant="outline" on:click={loadData} disabled={loading}>
				<RefreshCw class="w-4 h-4 {loading ? 'animate-spin' : ''}" />
			</Button>
		</div>
	</div>

	{#if stats}
		<!-- Stats Overview -->
		<div class="grid grid-cols-2 md:grid-cols-4 gap-4">
			<Card variant="glass" class="border-primary/20">
				<CardContent class="pt-6">
					<div class="flex items-center justify-between">
						<div>
							<p class="text-sm text-muted-foreground">Total Threats</p>
							<p class="text-3xl font-bold text-foreground">{stats.total_threats}</p>
						</div>
						<Shield class="w-10 h-10 text-primary opacity-50" />
					</div>
				</CardContent>
			</Card>
			
			<Card variant="glass" class="border-neon-yellow/20">
				<CardContent class="pt-6">
					<div class="flex items-center justify-between">
						<div>
							<p class="text-sm text-muted-foreground">Today</p>
							<p class="text-3xl font-bold text-neon-yellow">{stats.threats_today}</p>
						</div>
						<Clock class="w-10 h-10 text-neon-yellow opacity-50" />
					</div>
				</CardContent>
			</Card>
			
			<Card variant="glass" class="border-neon-green/20">
				<CardContent class="pt-6">
					<div class="flex items-center justify-between">
						<div>
							<p class="text-sm text-muted-foreground">Resolved</p>
							<p class="text-3xl font-bold text-neon-green">{stats.resolved_threats}</p>
						</div>
						<CheckCircle class="w-10 h-10 text-neon-green opacity-50" />
					</div>
				</CardContent>
			</Card>
			
			<Card variant="glass" class="border-neon-red/20">
				<CardContent class="pt-6">
					<div class="flex items-center justify-between">
						<div>
							<p class="text-sm text-muted-foreground">Unresolved</p>
							<p class="text-3xl font-bold text-neon-red">{stats.unresolved_threats}</p>
						</div>
						<AlertTriangle class="w-10 h-10 text-neon-red opacity-50" />
					</div>
					<div class="mt-2 flex items-center gap-1 text-xs">
						{#if stats.trend.direction === 'up'}
							<TrendingUp class="w-3 h-3 text-neon-red" />
							<span class="text-neon-red">+{stats.trend.percentage_change.toFixed(1)}%</span>
						{:else if stats.trend.direction === 'down'}
							<TrendingDown class="w-3 h-3 text-neon-green" />
							<span class="text-neon-green">{stats.trend.percentage_change.toFixed(1)}%</span>
						{:else}
							<Minus class="w-3 h-3 text-muted-foreground" />
							<span class="text-muted-foreground">Stable</span>
						{/if}
						<span class="text-muted-foreground">{stats.trend.comparison_period}</span>
					</div>
				</CardContent>
			</Card>
		</div>

		<!-- Charts Row -->
		<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
			<!-- Daily Threats Chart -->
			<Card variant="glass">
				<CardHeader>
					<CardTitle class="text-lg flex items-center gap-2">
						<Calendar class="w-5 h-5 text-cyber-blue" />
						Daily Threat Activity
					</CardTitle>
				</CardHeader>
				<CardContent>
					<div class="h-64 flex items-end gap-1">
						{#each stats.daily_counts as day, i}
							<div class="flex-1 flex flex-col items-center gap-1">
								<div class="w-full flex flex-col gap-0.5" style="height: 200px;">
									<!-- Stacked bar -->
									<div 
										class="w-full bg-neon-green/60 rounded-t transition-all duration-300"
										style="height: {(day.resolved / maxDailyCount) * 100}%"
										title="Resolved: {day.resolved}"
									></div>
									<div 
										class="w-full bg-neon-yellow/60 transition-all duration-300"
										style="height: {(day.blocked / maxDailyCount) * 100}%"
										title="Blocked: {day.blocked}"
									></div>
									<div 
										class="w-full bg-cyber-blue/60 rounded-b transition-all duration-300"
										style="height: {((day.count - day.resolved - day.blocked) / maxDailyCount) * 100}%"
										title="Other: {day.count - day.resolved - day.blocked}"
									></div>
								</div>
								<span class="text-[10px] text-muted-foreground rotate-45 origin-left">
									{day.date.split('-').slice(1).join('/')}
								</span>
							</div>
						{/each}
					</div>
					<div class="flex items-center justify-center gap-4 mt-4 text-xs">
						<div class="flex items-center gap-1">
							<div class="w-3 h-3 bg-neon-green/60 rounded"></div>
							<span class="text-muted-foreground">Resolved</span>
						</div>
						<div class="flex items-center gap-1">
							<div class="w-3 h-3 bg-neon-yellow/60 rounded"></div>
							<span class="text-muted-foreground">Blocked</span>
						</div>
						<div class="flex items-center gap-1">
							<div class="w-3 h-3 bg-cyber-blue/60 rounded"></div>
							<span class="text-muted-foreground">Other</span>
						</div>
					</div>
				</CardContent>
			</Card>

			<!-- Severity Breakdown -->
			<Card variant="glass">
				<CardHeader>
					<CardTitle class="text-lg flex items-center gap-2">
						<AlertTriangle class="w-5 h-5 text-neon-yellow" />
						Severity Distribution
					</CardTitle>
				</CardHeader>
				<CardContent>
					<div class="space-y-4">
						{#each [
							{ label: 'Critical', value: stats.by_severity.critical, color: 'bg-neon-red', text: 'text-neon-red' },
							{ label: 'High', value: stats.by_severity.high, color: 'bg-orange-500', text: 'text-orange-500' },
							{ label: 'Medium', value: stats.by_severity.medium, color: 'bg-neon-yellow', text: 'text-neon-yellow' },
							{ label: 'Low', value: stats.by_severity.low, color: 'bg-neon-green', text: 'text-neon-green' }
						] as item}
							{@const total = stats.by_severity.critical + stats.by_severity.high + stats.by_severity.medium + stats.by_severity.low}
							{@const percentage = total > 0 ? (item.value / total) * 100 : 0}
							<div class="space-y-1">
								<div class="flex items-center justify-between text-sm">
									<span class="{item.text} font-medium">{item.label}</span>
									<span class="text-muted-foreground">{item.value} ({percentage.toFixed(1)}%)</span>
								</div>
								<div class="h-2 bg-muted rounded-full overflow-hidden">
									<div 
										class="{item.color} h-full rounded-full transition-all duration-500"
										style="width: {percentage}%"
									></div>
								</div>
							</div>
						{/each}
					</div>

					<!-- Pie chart visualization -->
					<div class="mt-6 flex items-center justify-center">
						<div class="relative w-40 h-40">
							{#if stats}
								{@const total = stats.by_severity.critical + stats.by_severity.high + stats.by_severity.medium + stats.by_severity.low}
								{@const critPct = total > 0 ? (stats.by_severity.critical / total) * 100 : 0}
								{@const highPct = total > 0 ? (stats.by_severity.high / total) * 100 : 0}
								{@const medPct = total > 0 ? (stats.by_severity.medium / total) * 100 : 0}
								{@const lowPct = total > 0 ? (stats.by_severity.low / total) * 100 : 0}
								<svg class="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
									<circle cx="18" cy="18" r="16" fill="none" stroke="currentColor" stroke-width="3" class="text-muted/30"/>
									<circle cx="18" cy="18" r="16" fill="none" stroke="#ff3366" stroke-width="3" 
										stroke-dasharray="{critPct} {100 - critPct}" stroke-dashoffset="0"/>
									<circle cx="18" cy="18" r="16" fill="none" stroke="#f97316" stroke-width="3"
										stroke-dasharray="{highPct} {100 - highPct}" stroke-dashoffset="{-critPct}"/>
									<circle cx="18" cy="18" r="16" fill="none" stroke="#facc15" stroke-width="3"
										stroke-dasharray="{medPct} {100 - medPct}" stroke-dashoffset="{-(critPct + highPct)}"/>
									<circle cx="18" cy="18" r="16" fill="none" stroke="#22c55e" stroke-width="3"
										stroke-dasharray="{lowPct} {100 - lowPct}" stroke-dashoffset="{-(critPct + highPct + medPct)}"/>
								</svg>
								<div class="absolute inset-0 flex items-center justify-center">
									<div class="text-center">
										<div class="text-2xl font-bold">{total}</div>
										<div class="text-xs text-muted-foreground">Total</div>
									</div>
								</div>
							{/if}
						</div>
					</div>
				</CardContent>
			</Card>
		</div>

		<!-- Threat Types & Hourly Distribution -->
		<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
			<!-- Threat Types -->
			<Card variant="glass">
				<CardHeader>
					<CardTitle class="text-lg flex items-center gap-2">
						<Filter class="w-5 h-5 text-cyber-purple" />
						Threat Types
					</CardTitle>
				</CardHeader>
				<CardContent>
					<div class="space-y-3">
						{#each stats.by_type.sort((a, b) => b.count - a.count) as item}
							<div class="flex items-center gap-3">
								<div class="flex-1">
									<div class="flex items-center justify-between mb-1">
										<span class="text-sm font-medium">{item.threat_type.replace(/_/g, ' ')}</span>
										<span class="text-xs text-muted-foreground">{item.count}</span>
									</div>
									<div class="h-1.5 bg-muted rounded-full overflow-hidden">
										<div 
											class="h-full bg-gradient-to-r from-cyber-purple to-cyber-blue rounded-full"
											style="width: {item.percentage}%"
										></div>
									</div>
								</div>
								<Badge variant="outline" class="text-xs">
									{item.percentage.toFixed(1)}%
								</Badge>
							</div>
						{/each}
					</div>
				</CardContent>
			</Card>

			<!-- Hourly Distribution -->
			<Card variant="glass">
				<CardHeader>
					<CardTitle class="text-lg flex items-center gap-2">
						<Clock class="w-5 h-5 text-neon-green" />
						Hourly Distribution
					</CardTitle>
				</CardHeader>
				<CardContent>
					<div class="h-48 flex items-end gap-0.5">
						{#each stats.hourly_distribution as hour}
							<div 
								class="flex-1 bg-gradient-to-t from-cyber-blue to-neon-green rounded-t transition-all duration-300 hover:opacity-80"
								style="height: {maxHourlyCount > 0 ? (hour.count / maxHourlyCount) * 100 : 0}%"
								title="{hour.hour}:00 - {hour.count} events"
							></div>
						{/each}
					</div>
					<div class="flex justify-between mt-2 text-xs text-muted-foreground">
						<span>12 AM</span>
						<span>6 AM</span>
						<span>12 PM</span>
						<span>6 PM</span>
						<span>12 AM</span>
					</div>
					<p class="text-center text-xs text-muted-foreground mt-2">
						Peak activity at {stats.hourly_distribution.reduce((max, h) => h.count > max.count ? h : max, stats.hourly_distribution[0]).hour}:00
					</p>
				</CardContent>
			</Card>
		</div>

		<!-- Recent Threats Table -->
		<Card variant="glass">
			<CardHeader>
				<CardTitle class="text-lg">Recent Threat Events</CardTitle>
			</CardHeader>
			<CardContent>
				<div class="overflow-x-auto">
					<table class="w-full text-sm">
						<thead>
							<tr class="border-b border-border">
								<th class="text-left py-3 px-2 text-muted-foreground font-medium">Time</th>
								<th class="text-left py-3 px-2 text-muted-foreground font-medium">Type</th>
								<th class="text-left py-3 px-2 text-muted-foreground font-medium">Severity</th>
								<th class="text-left py-3 px-2 text-muted-foreground font-medium">Source</th>
								<th class="text-left py-3 px-2 text-muted-foreground font-medium">Description</th>
								<th class="text-left py-3 px-2 text-muted-foreground font-medium">Status</th>
							</tr>
						</thead>
						<tbody>
							{#each history.slice(0, 15) as event}
								<tr class="border-b border-border/50 hover:bg-muted/30 transition-colors">
									<td class="py-3 px-2 text-muted-foreground whitespace-nowrap">
										{formatDate(event.timestamp)}
									</td>
									<td class="py-3 px-2">
										<Badge variant="outline" class="text-xs">
											{event.threat_type.replace(/_/g, ' ')}
										</Badge>
									</td>
									<td class="py-3 px-2">
										<span class="px-2 py-1 rounded text-xs font-medium {getSeverityBg(event.severity)} {getSeverityColor(event.severity)}">
											{event.severity.toUpperCase()}
										</span>
									</td>
									<td class="py-3 px-2">{event.source}</td>
									<td class="py-3 px-2 max-w-xs truncate" title={event.description}>
										{event.description}
									</td>
									<td class="py-3 px-2">
										{#if event.resolved}
											<Badge variant="success" class="gap-1">
												<CheckCircle class="w-3 h-3" />
												Resolved
											</Badge>
										{:else}
											<Badge variant="warning" class="gap-1">
												<AlertTriangle class="w-3 h-3" />
												Open
											</Badge>
										{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</CardContent>
		</Card>
	{:else if loading}
		<div class="flex items-center justify-center h-64">
			<RefreshCw class="w-8 h-8 animate-spin text-primary" />
		</div>
	{:else}
		<Card variant="glass">
			<CardContent class="py-12 text-center">
				<BarChart3 class="w-16 h-16 mx-auto mb-4 text-muted-foreground opacity-50" />
				<p class="text-lg font-medium">No analytics data available</p>
				<p class="text-muted-foreground">Start monitoring to collect threat data</p>
			</CardContent>
		</Card>
	{/if}
</div>

