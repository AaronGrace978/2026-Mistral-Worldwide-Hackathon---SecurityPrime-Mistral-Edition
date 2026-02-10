<script lang="ts">
	import { cn } from '$lib/utils.js';

	export let orientation: 'horizontal' | 'vertical' = 'horizontal';
	export let decorative = true;
	let className: string | undefined = undefined;
	export { className as class };
</script>

<div
	role={decorative ? 'none' : 'separator'}
	aria-orientation={orientation}
	class={cn(
		'shrink-0 bg-border',
		orientation === 'horizontal' ? 'h-[1px] w-full' : 'h-full w-[1px]',
		className
	)}
	{...$$restProps}
/>

