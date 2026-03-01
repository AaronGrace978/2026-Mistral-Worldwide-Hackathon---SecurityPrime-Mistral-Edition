<script lang="ts">
	export let size = 80;
	export let className = '';
	export let animated = false;
	export let useAnimatedWebp = false;
</script>

<img
	src={useAnimatedWebp ? '/images/animated-sitting-cat.webp' : '/images/pixel-cat.webp'}
	alt="Le Security Copilot mascot"
	width={size}
	height={size}
	class="{className} {animated ? 'pixel-cat-animated' : ''} pixel-cat-img"
	style="image-rendering: pixelated; object-fit: contain;"
/>

<style>
	.pixel-cat-img {
		image-rendering: pixelated;
		-ms-interpolation-mode: nearest-neighbor;
	}

	.pixel-cat-animated {
		animation: pixel-bounce 2s ease-in-out infinite;
		filter: drop-shadow(0 2px 8px rgba(255, 130, 5, 0.25));
	}

	@keyframes pixel-bounce {
		0%, 100% { transform: translateY(0); }
		30% { transform: translateY(-4px); }
		50% { transform: translateY(0); }
		70% { transform: translateY(-2px); }
	}
</style>
