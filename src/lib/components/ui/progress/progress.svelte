<script lang="ts">
	import { cn } from '$lib/utils.js';

	export let value = 0;
	export let max = 100;
	let className: string | undefined = undefined;
	export { className as class };
	export let variant: 'default' | 'neon' = 'default';

	$: percentage = Math.min(Math.max((value / max) * 100, 0), 100);
</script>

<div
	class={cn(
		'relative h-2 w-full overflow-hidden rounded-full bg-muted',
		className
	)}
	role="progressbar"
	aria-valuenow={value}
	aria-valuemin={0}
	aria-valuemax={max}
	{...$$restProps}
>
	<div
		class={cn(
			'h-full transition-all duration-500 ease-out',
			variant === 'default' && 'bg-primary',
			variant === 'neon' && 'bg-gradient-to-r from-cyber-blue to-cyber-purple shadow-neon-blue'
		)}
		style="width: {percentage}%"
	/>
</div>

