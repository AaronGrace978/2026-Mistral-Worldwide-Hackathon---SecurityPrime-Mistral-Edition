<script lang="ts">
	import { onDestroy, tick } from 'svelte';
	import { catBoyGame } from '$lib/stores/catboy';

	let visible = false;
	let running = false;

	async function startGame() {
		if (running) return;
		visible = true;
		running = true;

		await tick();
		await tick();

		await new Promise((r) => setTimeout(r, 60));

		const el = document.getElementById('kitty-game-overlay');
		const cv = document.getElementById('kitty-game-canvas');

		if (!el || !cv) {
			console.error('CatBoy: DOM elements not found after mount');
			running = false;
			visible = false;
			catBoyGame.set(false);
			return;
		}

		const CatBoy = (window as any).CatBoyGame;
		if (!CatBoy?.init) {
			console.error('CatBoy: window.CatBoyGame not found. /catboy.js did not load.');
			running = false;
			visible = false;
			catBoyGame.set(false);
			return;
		}

		CatBoy.init(() => {
			running = false;
			visible = false;
			catBoyGame.set(false);
		});
	}

	function stopGame() {
		if (!running) return;
		const CatBoy = (window as any).CatBoyGame;
		if (CatBoy?.destroy) CatBoy.destroy();
		running = false;
		visible = false;
	}

	const unsub = catBoyGame.subscribe((open) => {
		if (open && !running) {
			startGame();
		}
	});

	onDestroy(() => {
		unsub();
		stopGame();
	});
</script>

{#if visible}
	<div id="kitty-game-overlay" class="catboy-overlay">
		<canvas id="kitty-game-canvas" class="catboy-canvas" width="256" height="224"></canvas>
		<span class="catboy-hint">ESC exit | Arrows move | Z confirm | X cancel</span>
	</div>
{/if}

<style>
	.catboy-overlay {
		position: fixed;
		inset: 0;
		z-index: 99999;
		background: #000;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.catboy-canvas {
		image-rendering: pixelated;
		image-rendering: crisp-edges;
	}

	.catboy-hint {
		position: absolute;
		bottom: 10px;
		left: 50%;
		transform: translateX(-50%);
		color: rgba(255, 255, 255, 0.25);
		font: 11px 'JetBrains Mono', monospace;
		pointer-events: none;
		user-select: none;
	}
</style>
