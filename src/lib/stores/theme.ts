// Cyber Security Prime - Theme Store
// Manages dark/light mode with persistence

import { writable, derived } from 'svelte/store';
import { browser } from '$app/environment';

type Theme = 'dark' | 'light' | 'system';

// Get initial theme from localStorage or default to dark
function getInitialTheme(): Theme {
	if (!browser) return 'dark';
	const stored = localStorage.getItem('theme') as Theme | null;
	return stored || 'dark';
}

// Create the theme store
function createThemeStore() {
	const { subscribe, set, update } = writable<Theme>(getInitialTheme());

	return {
		subscribe,
		set: (theme: Theme) => {
			if (browser) {
				localStorage.setItem('theme', theme);
				applyTheme(theme);
			}
			set(theme);
		},
		toggle: () => {
			update((current) => {
				const newTheme = current === 'dark' ? 'light' : 'dark';
				if (browser) {
					localStorage.setItem('theme', newTheme);
					applyTheme(newTheme);
				}
				return newTheme;
			});
		},
		init: () => {
			if (browser) {
				const theme = getInitialTheme();
				applyTheme(theme);
			}
		}
	};
}

// Apply theme to document
function applyTheme(theme: Theme) {
	if (!browser) return;

	const root = document.documentElement;
	const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
	const isDark = theme === 'dark' || (theme === 'system' && systemDark);

	if (isDark) {
		root.classList.add('dark');
		root.classList.remove('light');
	} else {
		root.classList.remove('dark');
		root.classList.add('light');
	}

	// Update meta theme color
	const metaTheme = document.querySelector('meta[name="theme-color"]');
	if (metaTheme) {
		metaTheme.setAttribute('content', isDark ? '#0a0a0f' : '#ffffff');
	}
}

export const theme = createThemeStore();

// Derived store for actual dark/light state
export const isDark = derived(theme, ($theme) => {
	if (!browser) return true;
	if ($theme === 'system') {
		return window.matchMedia('(prefers-color-scheme: dark)').matches;
	}
	return $theme === 'dark';
});

