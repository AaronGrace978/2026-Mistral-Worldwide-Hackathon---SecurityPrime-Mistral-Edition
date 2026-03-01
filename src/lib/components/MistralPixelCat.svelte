<script lang="ts">
	import { catBoyGame } from '$lib/stores/catboy';

	export let size = 80;
	export let className = '';
	export let animated = false;
	export let useAnimatedWebp = false;
	export let clickable = false;

	function handleClick() {
		if (clickable) {
			catBoyGame.set(true);
		}
	}
</script>

<button
	type="button"
	class="pixel-cat-wrapper"
	class:clickable
	on:click={handleClick}
	disabled={!clickable}
	title={clickable ? 'Click to play CatBoy Advance!' : undefined}
	aria-label={clickable ? 'Play CatBoy Advance game' : undefined}
>
	<img
		src={useAnimatedWebp ? '/images/animated-sitting-cat.webp' : '/images/pixel-cat.webp'}
		alt="Le Security Copilot mascot"
		width={size}
		height={size}
		class="{className} {animated ? 'pixel-cat-animated' : ''} pixel-cat-img"
		style="image-rendering: pixelated; object-fit: contain;"
		draggable={false}
	/>
</button>

<style>
	.pixel-cat-wrapper {
		background: none;
		border: none;
		padding: 0;
		cursor: default;
		display: inline-block;
	}

	.pixel-cat-wrapper.clickable {
		cursor: pointer;
	}

	.pixel-cat-wrapper.clickable:hover .pixel-cat-img {
		filter: drop-shadow(0 0 12px rgba(255, 130, 5, 0.6));
		transform: scale(1.08);
	}

	.pixel-cat-wrapper.clickable:active .pixel-cat-img {
		transform: scale(0.95);
	}

	.pixel-cat-img {
		image-rendering: pixelated;
		-ms-interpolation-mode: nearest-neighbor;
		transition: transform 0.15s ease, filter 0.15s ease;
	}

	.pixel-cat-animated {
		animation: pixel-bounce 2s ease-in-out infinite;
		filter: drop-shadow(0 2px 8px rgba(255, 130, 5, 0.25));
	}

	.pixel-cat-wrapper.clickable .pixel-cat-animated {
		animation: pixel-bounce 2s ease-in-out infinite;
	}

	@keyframes pixel-bounce {
		0%, 100% { transform: translateY(0); }
		30% { transform: translateY(-4px); }
		50% { transform: translateY(0); }
		70% { transform: translateY(-2px); }
	}
</style>
