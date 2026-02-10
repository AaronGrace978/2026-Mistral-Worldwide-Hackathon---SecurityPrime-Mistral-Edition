<script lang="ts">
	import { cn } from '$lib/utils.js';

	let className: string | undefined = undefined;
	export { className as class };
</script>

<p class={cn('text-sm text-muted-foreground', className)} {...$$restProps}>
	<slot />
</p>

