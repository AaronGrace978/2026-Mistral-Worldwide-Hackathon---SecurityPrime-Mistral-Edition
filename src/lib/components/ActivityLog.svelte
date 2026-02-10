<script lang="ts">
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { ScrollArea } from '$lib/components/ui/scroll-area';
	import { cn, formatRelativeTime, getSeverityColor } from '$lib/utils';
	import type { ActivityEvent } from '$lib/api';
	import { 
		Clock, 
		Shield, 
		Flame, 
		Lock, 
		Bug, 
		Network, 
		Settings,
		AlertTriangle,
		CheckCircle,
		XCircle,
		Info
	} from 'lucide-svelte';

	export let activities: ActivityEvent[] = [];
	export let maxHeight = '400px';

	function getEventIcon(eventType: string) {
		switch (eventType) {
			case 'scan_started':
			case 'scan_completed':
				return Shield;
			case 'threat_detected':
			case 'threat_quarantined':
				return AlertTriangle;
			case 'firewall_blocked':
				return Flame;
			case 'file_encrypted':
			case 'file_decrypted':
				return Lock;
			case 'vulnerability_found':
				return Bug;
			case 'system_update':
				return CheckCircle;
			case 'settings_changed':
				return Settings;
			default:
				return Info;
		}
	}

	function getSeverityVariant(severity: string): 'success' | 'warning' | 'danger' | 'info' {
		switch (severity) {
			case 'critical':
			case 'high':
				return 'danger';
			case 'medium':
				return 'warning';
			case 'low':
				return 'success';
			default:
				return 'info';
		}
	}
</script>

<Card variant="glass" class="h-full">
	<CardHeader class="pb-3">
		<CardTitle class="flex items-center gap-2 text-lg">
			<Clock class="w-5 h-5 text-primary" />
			Recent Activity
		</CardTitle>
	</CardHeader>
	<CardContent class="p-0">
		<ScrollArea class="px-6 pb-6" style="max-height: {maxHeight};">
			{#if activities.length === 0}
				<div class="flex flex-col items-center justify-center py-8 text-muted-foreground">
					<Info class="w-8 h-8 mb-2" />
					<span class="text-sm">No recent activity</span>
				</div>
			{:else}
				<div class="space-y-4">
					{#each activities as activity (activity.id)}
						{@const Icon = getEventIcon(activity.event_type)}
						<div class="flex gap-3 animate-in slide-in-left">
							<div class={cn(
								'flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center',
								activity.severity === 'critical' || activity.severity === 'high' 
									? 'bg-neon-red/10 text-neon-red'
									: activity.severity === 'medium'
										? 'bg-neon-yellow/10 text-neon-yellow'
										: 'bg-primary/10 text-primary'
							)}>
								<Icon class="w-4 h-4" />
							</div>
							
							<div class="flex-1 min-w-0">
								<div class="flex items-start justify-between gap-2">
									<div class="flex-1 min-w-0">
										<p class="text-sm font-medium text-foreground truncate">
											{activity.title}
										</p>
										<p class="text-xs text-muted-foreground mt-0.5 truncate-2">
											{activity.description}
										</p>
									</div>
									<Badge variant={getSeverityVariant(activity.severity)} class="flex-shrink-0 text-[10px]">
										{activity.severity}
									</Badge>
								</div>
								
								<div class="flex items-center gap-2 mt-1.5">
									<span class="text-[10px] text-muted-foreground">
										{formatRelativeTime(activity.timestamp)}
									</span>
									<span class="text-muted-foreground">•</span>
									<span class="text-[10px] text-muted-foreground capitalize">
										{activity.module}
									</span>
								</div>
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</ScrollArea>
	</CardContent>
</Card>

