<script lang="ts">
	export let size = 40;
	export let className = '';
	export let animated = false;
</script>

<svg
	width={size}
	height={size}
	viewBox="0 0 64 64"
	fill="none"
	xmlns="http://www.w3.org/2000/svg"
	class="{className} {animated ? 'mistral-cat-animated' : ''}"
>
	<!-- Cat ears -->
	<path d="M12 24L20 8L28 24" fill="url(#mistral-grad)" opacity="0.9" />
	<path d="M36 24L44 8L52 24" fill="url(#mistral-grad)" opacity="0.9" />
	<!-- Inner ears -->
	<path d="M16 22L20 12L24 22" fill="url(#mistral-inner)" opacity="0.6" />
	<path d="M40 22L44 12L48 22" fill="url(#mistral-inner)" opacity="0.6" />
	<!-- Head -->
	<ellipse cx="32" cy="38" rx="22" ry="20" fill="url(#mistral-grad)" />
	<!-- Eyes -->
	<ellipse cx="24" cy="34" rx="4" ry="4.5" fill="#0a0a0f" />
	<ellipse cx="40" cy="34" rx="4" ry="4.5" fill="#0a0a0f" />
	<!-- Eye shine -->
	<circle cx="25.5" cy="32.5" r="1.5" fill="white" opacity="0.9" />
	<circle cx="41.5" cy="32.5" r="1.5" fill="white" opacity="0.9" />
	<!-- Nose -->
	<ellipse cx="32" cy="41" rx="2.5" ry="2" fill="#E10500" opacity="0.8" />
	<!-- Mouth -->
	<path d="M28 44 Q32 48 36 44" stroke="#0a0a0f" stroke-width="1.5" fill="none" stroke-linecap="round" />
	<!-- Whiskers -->
	<line x1="4" y1="36" x2="18" y2="38" stroke="currentColor" stroke-width="1" opacity="0.3" />
	<line x1="4" y1="40" x2="18" y2="40" stroke="currentColor" stroke-width="1" opacity="0.3" />
	<line x1="46" y1="38" x2="60" y2="36" stroke="currentColor" stroke-width="1" opacity="0.3" />
	<line x1="46" y1="40" x2="60" y2="40" stroke="currentColor" stroke-width="1" opacity="0.3" />
	<defs>
		<linearGradient id="mistral-grad" x1="10" y1="8" x2="54" y2="58" gradientUnits="userSpaceOnUse">
			<stop offset="0%" stop-color="#FF8205" />
			<stop offset="50%" stop-color="#FFB000" />
			<stop offset="100%" stop-color="#FFD800" />
		</linearGradient>
		<linearGradient id="mistral-inner" x1="16" y1="12" x2="48" y2="22" gradientUnits="userSpaceOnUse">
			<stop offset="0%" stop-color="#FA5010" />
			<stop offset="100%" stop-color="#FF8205" />
		</linearGradient>
	</defs>
</svg>

<style>
	.mistral-cat-animated {
		animation: cat-float 3s ease-in-out infinite;
	}

	@keyframes cat-float {
		0%, 100% { transform: translateY(0); }
		50% { transform: translateY(-4px); }
	}
</style>
