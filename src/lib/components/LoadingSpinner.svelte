<script lang="ts">
	import { cn } from '$lib/utils';

	export let size: 'sm' | 'md' | 'lg' = 'md';
	let className: string | undefined = undefined;
	export { className as class };

	const sizes = {
		sm: 'w-4 h-4',
		md: 'w-8 h-8',
		lg: 'w-12 h-12'
	};
</script>

<div
	class={cn(
		'relative',
		sizes[size],
		className
	)}
	{...$$restProps}
>
	<div class="absolute inset-0 rounded-full border-2 border-primary/30" />
	<div class="absolute inset-0 rounded-full border-2 border-t-primary border-r-primary border-b-transparent border-l-transparent animate-spin" />
</div>

