<script lang="ts">
	import { badgeVariants, type Props } from './index.js';
	import { cn } from '$lib/utils.js';

	type $$Props = Props & {
		class?: string;
	};

	export let variant: $$Props['variant'] = 'default';
	let className: string | undefined = undefined;
	export { className as class };
</script>

<div class={cn(badgeVariants({ variant }), className)} {...$$restProps}>
	<slot />
</div>

