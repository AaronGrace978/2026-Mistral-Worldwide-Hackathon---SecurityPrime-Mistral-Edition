<script lang="ts">
	import { buttonVariants, type Props } from './index.js';
	import { cn } from '$lib/utils.js';

	type $$Props = Props & {
		class?: string;
		disabled?: boolean;
		type?: 'button' | 'submit' | 'reset';
	};

	export let variant: $$Props['variant'] = 'default';
	export let size: $$Props['size'] = 'default';
	let className: string | undefined = undefined;
	export { className as class };
	export let disabled = false;
	export let type: $$Props['type'] = 'button';
</script>

<button
	{type}
	{disabled}
	class={cn(buttonVariants({ variant, size }), className)}
	on:click
	on:keydown
	{...$$restProps}
>
	<slot />
</button>

