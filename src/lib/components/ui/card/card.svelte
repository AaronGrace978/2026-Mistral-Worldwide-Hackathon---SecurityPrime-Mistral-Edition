<script lang="ts">
	import { cn } from '$lib/utils.js';

	let className: string | undefined = undefined;
	export { className as class };
	export let variant: 'default' | 'glass' | 'neon' = 'default';
</script>

<div
	class={cn(
		'rounded-lg border bg-card text-card-foreground',
		variant === 'glass' && 'glass-card',
		variant === 'neon' && 'neon-border glass-card',
		className
	)}
	{...$$restProps}
>
	<slot />
</div>

