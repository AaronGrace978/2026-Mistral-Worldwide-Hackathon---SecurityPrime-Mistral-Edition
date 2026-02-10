<script lang="ts">
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import { ScrollArea } from '$lib/components/ui/scroll-area';
	import { cn, formatRelativeTime } from '$lib/utils';
	import type { ThreatAlert } from '$lib/api';
	import { AlertTriangle, X, Shield, CheckCircle } from 'lucide-svelte';
	import { createEventDispatcher } from 'svelte';

	export let alerts: ThreatAlert[] = [];
	export let maxHeight = '400px';

	const dispatch = createEventDispatcher<{
		resolve: { id: string };
		dismiss: { id: string };
	}>();

	function handleResolve(id: string) {
		dispatch('resolve', { id });
	}

	function handleDismiss(id: string) {
		dispatch('dismiss', { id });
	}

	$: unresolvedAlerts = alerts.filter((a) => !a.resolved);

	function getSeverityStyles(severity: string): string {
		switch (severity) {
			case 'critical':
				return 'border-neon-red/50 bg-neon-red/5';
			case 'high':
				return 'border-cyber-orange/50 bg-cyber-orange/5';
			case 'medium':
				return 'border-neon-yellow/50 bg-neon-yellow/5';
			case 'low':
				return 'border-neon-green/50 bg-neon-green/5';
			default:
				return 'border-border';
		}
	}

	function getSeverityIconColor(severity: string): string {
		switch (severity) {
			case 'critical':
				return 'text-neon-red';
			case 'high':
				return 'text-cyber-orange';
			case 'medium':
				return 'text-neon-yellow';
			case 'low':
				return 'text-neon-green';
			default:
				return 'text-muted-foreground';
		}
	}
</script>

<Card variant="glass" class="h-full">
	<CardHeader class="pb-3">
		<div class="flex items-center justify-between">
			<CardTitle class="flex items-center gap-2 text-lg">
				<AlertTriangle class="w-5 h-5 text-neon-red" />
				Threat Alerts
			</CardTitle>
			{#if unresolvedAlerts.length > 0}
				<Badge variant="danger" class="animate-pulse">
					{unresolvedAlerts.length} Active
				</Badge>
			{/if}
		</div>
	</CardHeader>
	<CardContent class="p-0">
		<ScrollArea class="px-6 pb-6" style="max-height: {maxHeight};">
			{#if unresolvedAlerts.length === 0}
				<div class="flex flex-col items-center justify-center py-8 text-muted-foreground">
					<Shield class="w-8 h-8 mb-2 text-neon-green" />
					<span class="text-sm text-neon-green">All clear! No active threats</span>
				</div>
			{:else}
				<div class="space-y-3">
					{#each unresolvedAlerts as alert (alert.id)}
						<div 
							class={cn(
								'relative p-4 rounded-lg border transition-all duration-300 animate-in',
								getSeverityStyles(alert.severity)
							)}
						>
							<!-- Dismiss button -->
							<button
								on:click={() => handleDismiss(alert.id)}
								class="absolute top-2 right-2 p-1 rounded hover:bg-muted/50 text-muted-foreground hover:text-foreground transition-colors"
							>
								<X class="w-4 h-4" />
							</button>

							<div class="flex items-start gap-3 pr-6">
								<div class={cn(
									'flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center',
									alert.severity === 'critical' && 'bg-neon-red/20',
									alert.severity === 'high' && 'bg-cyber-orange/20',
									alert.severity === 'medium' && 'bg-neon-yellow/20',
									alert.severity === 'low' && 'bg-neon-green/20'
								)}>
									<AlertTriangle class={cn('w-5 h-5', getSeverityIconColor(alert.severity))} />
								</div>

								<div class="flex-1 min-w-0">
									<div class="flex items-start justify-between gap-2 mb-1">
										<h4 class="text-sm font-medium text-foreground">
											{alert.title}
										</h4>
										<Badge 
											variant={alert.severity === 'critical' || alert.severity === 'high' ? 'danger' : alert.severity === 'medium' ? 'warning' : 'success'}
											class="text-[10px] uppercase"
										>
											{alert.severity}
										</Badge>
									</div>

									<p class="text-xs text-muted-foreground mb-2">
										{alert.description}
									</p>

									<div class="flex items-center justify-between">
										<div class="flex items-center gap-2 text-[10px] text-muted-foreground">
											<span>{alert.source}</span>
											<span>•</span>
											<span>{formatRelativeTime(alert.timestamp)}</span>
										</div>

										<Button 
											variant="ghost" 
											size="sm" 
											class="h-7 text-xs"
											on:click={() => handleResolve(alert.id)}
										>
											<CheckCircle class="w-3 h-3 mr-1" />
											Resolve
										</Button>
									</div>
								</div>
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</ScrollArea>
	</CardContent>
</Card>

