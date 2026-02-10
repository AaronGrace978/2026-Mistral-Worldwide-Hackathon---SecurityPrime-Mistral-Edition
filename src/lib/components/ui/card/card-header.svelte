<script lang="ts">
	import { cn } from '$lib/utils.js';

	let className: string | undefined = undefined;
	export { className as class };
</script>

<div class={cn('flex flex-col space-y-1.5 p-6', className)} {...$$restProps}>
	<slot />
</div>

