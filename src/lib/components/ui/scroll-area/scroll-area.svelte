<script lang="ts">
	import { cn } from '$lib/utils.js';

	let className: string | undefined = undefined;
	export { className as class };
	export let orientation: 'vertical' | 'horizontal' | 'both' = 'vertical';
</script>

<div
	class={cn(
		'relative',
		orientation === 'vertical' && 'overflow-y-auto overflow-x-hidden',
		orientation === 'horizontal' && 'overflow-x-auto overflow-y-hidden',
		orientation === 'both' && 'overflow-auto',
		className
	)}
	{...$$restProps}
>
	<slot />
</div>

