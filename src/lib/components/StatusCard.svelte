<script lang="ts">
	import { Card, CardContent } from '$lib/components/ui/card';
	import { cn, getStatusColor } from '$lib/utils';
	import type { ComponentType } from 'svelte';

	export let title: string;
	export let description: string;
	export let status: 'active' | 'inactive' | 'warning' | 'error' = 'active';
	export let icon: ComponentType;
	export let value: string | number | null = null;
	export let href: string | undefined = undefined;

	$: statusText = status === 'active' 
		? 'Active' 
		: status === 'warning' 
			? 'Warning' 
			: status === 'error' 
				? 'Error' 
				: 'Inactive';

	$: statusColor = status === 'active' 
		? 'text-neon-green' 
		: status === 'warning' 
			? 'text-neon-yellow' 
			: status === 'error' 
				? 'text-neon-red' 
				: 'text-muted-foreground';

	$: borderColor = status === 'active' 
		? 'border-neon-green/30 hover:border-neon-green/50' 
		: status === 'warning' 
			? 'border-neon-yellow/30 hover:border-neon-yellow/50' 
			: status === 'error' 
				? 'border-neon-red/30 hover:border-neon-red/50' 
				: 'border-border hover:border-primary/30';
</script>

<svelte:element
	this={href ? 'a' : 'div'}
	{href}
	class={cn(
		'block transition-all duration-300',
		href && 'cursor-pointer'
	)}
>
	<Card 
		variant="glass" 
		class={cn(
			'module-card border',
			borderColor
		)}
	>
		<CardContent class="p-4">
			<div class="flex items-start justify-between">
				<div class="flex items-center gap-3">
					<div class={cn(
						'flex items-center justify-center w-10 h-10 rounded-lg',
						status === 'active' && 'bg-neon-green/10 text-neon-green',
						status === 'warning' && 'bg-neon-yellow/10 text-neon-yellow',
						status === 'error' && 'bg-neon-red/10 text-neon-red',
						status === 'inactive' && 'bg-muted text-muted-foreground'
					)}>
						<svelte:component this={icon} class="w-5 h-5" />
					</div>
					<div>
						<h3 class="font-medium text-foreground">{title}</h3>
						<p class="text-xs text-muted-foreground">{description}</p>
					</div>
				</div>
				
				<!-- Status indicator -->
				<div class="flex items-center gap-2">
					{#if value !== null}
						<span class="text-lg font-bold text-foreground">{value}</span>
					{/if}
					<div class={cn('status-indicator', getStatusColor(status))} />
				</div>
			</div>

			{#if status !== 'inactive'}
				<div class="mt-3 pt-3 border-t border-border/50 flex items-center justify-between">
					<span class={cn('text-xs font-medium', statusColor)}>
						{statusText}
					</span>
					{#if href}
						<span class="text-xs text-muted-foreground">
							View details →
						</span>
					{/if}
				</div>
			{/if}
		</CardContent>
	</Card>
</svelte:element>

