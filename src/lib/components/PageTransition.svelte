<script lang="ts">
	import { page } from '$app/stores';
	import { fade, fly } from 'svelte/transition';
	import { cubicOut } from 'svelte/easing';

	export let key = '';
</script>

{#key key || $page.url.pathname}
	<div
		in:fly={{ x: 10, duration: 200, delay: 100, easing: cubicOut }}
		out:fade={{ duration: 100 }}
		class="contents"
	>
		<slot />
	</div>
{/key}

