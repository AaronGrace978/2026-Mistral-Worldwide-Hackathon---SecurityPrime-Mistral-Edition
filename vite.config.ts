import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [sveltekit()],
	
	// Prevent vite from obscuring rust errors
	clearScreen: false,
	
	// Tauri expects a fixed port, fail if that port is not available
	server: {
		port: 5173,
		strictPort: true,
		watch: {
			// Tell vite to ignore watching `src-tauri`
			ignored: ['**/src-tauri/**']
		}
	},
	
	// Tauri uses native module loading
	envPrefix: ['VITE_', 'TAURI_'],
	
	build: {
		// Tauri uses Chromium on Windows and WebKit on macOS and Linux
		target: process.env.TAURI_PLATFORM === 'windows' ? 'chrome105' : 'safari13',
		// Don't minify for debug builds
		minify: !process.env.TAURI_DEBUG ? 'esbuild' : false,
		// Produce sourcemaps for debug builds
		sourcemap: !!process.env.TAURI_DEBUG
	}
});

