/** @type {import('tailwindcss').Config} */
export default {
	darkMode: ['class'],
	content: ['./src/**/*.{html,js,svelte,ts}'],
	safelist: ['dark'],
	theme: {
		container: {
			center: true,
			padding: '2rem',
			screens: {
				'2xl': '1400px'
			}
		},
		extend: {
			colors: {
				// Cyberpunk 2077 inspired colors
				border: 'hsl(var(--border) / <alpha-value>)',
				input: 'hsl(var(--input) / <alpha-value>)',
				ring: 'hsl(var(--ring) / <alpha-value>)',
				background: 'hsl(var(--background) / <alpha-value>)',
				foreground: 'hsl(var(--foreground) / <alpha-value>)',
				primary: {
					DEFAULT: 'hsl(var(--primary) / <alpha-value>)',
					foreground: 'hsl(var(--primary-foreground) / <alpha-value>)'
				},
				secondary: {
					DEFAULT: 'hsl(var(--secondary) / <alpha-value>)',
					foreground: 'hsl(var(--secondary-foreground) / <alpha-value>)'
				},
				destructive: {
					DEFAULT: 'hsl(var(--destructive) / <alpha-value>)',
					foreground: 'hsl(var(--destructive-foreground) / <alpha-value>)'
				},
				muted: {
					DEFAULT: 'hsl(var(--muted) / <alpha-value>)',
					foreground: 'hsl(var(--muted-foreground) / <alpha-value>)'
				},
				accent: {
					DEFAULT: 'hsl(var(--accent) / <alpha-value>)',
					foreground: 'hsl(var(--accent-foreground) / <alpha-value>)'
				},
				popover: {
					DEFAULT: 'hsl(var(--popover) / <alpha-value>)',
					foreground: 'hsl(var(--popover-foreground) / <alpha-value>)'
				},
				card: {
					DEFAULT: 'hsl(var(--card) / <alpha-value>)',
					foreground: 'hsl(var(--card-foreground) / <alpha-value>)'
				},
				// Cyberpunk specific colors
				cyber: {
					blue: '#00d9ff',
					'blue-dark': '#0099cc',
					purple: '#ff00ff',
					'purple-dark': '#cc00cc',
					pink: '#ff2a6d',
					yellow: '#fcee0a',
					green: '#00ff88',
					red: '#ff0044',
					orange: '#ffaa00'
				},
				neon: {
					blue: '#00d9ff',
					purple: '#a855f7',
					pink: '#ec4899',
					green: '#22c55e',
					yellow: '#eab308',
					red: '#ef4444'
				}
			},
			borderRadius: {
				lg: 'var(--radius)',
				md: 'calc(var(--radius) - 2px)',
				sm: 'calc(var(--radius) - 4px)'
			},
			fontFamily: {
				sans: ['Rajdhani', 'Inter', 'system-ui', 'sans-serif'],
				mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
				cyber: ['Orbitron', 'sans-serif']
			},
			boxShadow: {
				'neon-blue': '0 0 5px #00d9ff, 0 0 20px rgba(0, 217, 255, 0.3)',
				'neon-purple': '0 0 5px #ff00ff, 0 0 20px rgba(255, 0, 255, 0.3)',
				'neon-green': '0 0 5px #00ff88, 0 0 20px rgba(0, 255, 136, 0.3)',
				'neon-red': '0 0 5px #ff0044, 0 0 20px rgba(255, 0, 68, 0.3)',
				'neon-yellow': '0 0 5px #ffaa00, 0 0 20px rgba(255, 170, 0, 0.3)',
				glow: '0 0 15px rgba(0, 217, 255, 0.5)',
				'glow-lg': '0 0 30px rgba(0, 217, 255, 0.4)',
				glass: '0 8px 32px 0 rgba(0, 0, 0, 0.37)'
			},
			animation: {
				'accordion-down': 'accordion-down 0.2s ease-out',
				'accordion-up': 'accordion-up 0.2s ease-out',
				'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
				'scan-line': 'scan-line 3s linear infinite',
				'flicker': 'flicker 0.15s infinite',
				'slide-in': 'slide-in 0.3s ease-out',
				'fade-in': 'fade-in 0.3s ease-out',
				'glow-pulse': 'glow-pulse 2s ease-in-out infinite'
			},
			keyframes: {
				'accordion-down': {
					from: { height: '0' },
					to: { height: 'var(--radix-accordion-content-height)' }
				},
				'accordion-up': {
					from: { height: 'var(--radix-accordion-content-height)' },
					to: { height: '0' }
				},
				'pulse-glow': {
					'0%, 100%': { 
						boxShadow: '0 0 5px #00d9ff, 0 0 10px rgba(0, 217, 255, 0.3)'
					},
					'50%': { 
						boxShadow: '0 0 10px #00d9ff, 0 0 30px rgba(0, 217, 255, 0.5)'
					}
				},
				'scan-line': {
					'0%': { transform: 'translateY(-100%)' },
					'100%': { transform: 'translateY(100%)' }
				},
				'flicker': {
					'0%, 19.999%, 22%, 62.999%, 64%, 64.999%, 70%, 100%': { opacity: '1' },
					'20%, 21.999%, 63%, 63.999%, 65%, 69.999%': { opacity: '0.4' }
				},
				'slide-in': {
					from: { transform: 'translateX(-10px)', opacity: '0' },
					to: { transform: 'translateX(0)', opacity: '1' }
				},
				'fade-in': {
					from: { opacity: '0' },
					to: { opacity: '1' }
				},
				'glow-pulse': {
					'0%, 100%': { opacity: '1' },
					'50%': { opacity: '0.5' }
				}
			},
			backgroundImage: {
				'cyber-grid': `
					linear-gradient(rgba(0, 217, 255, 0.03) 1px, transparent 1px),
					linear-gradient(90deg, rgba(0, 217, 255, 0.03) 1px, transparent 1px)
				`,
				'cyber-gradient': 'linear-gradient(135deg, rgba(0, 217, 255, 0.1) 0%, rgba(255, 0, 255, 0.1) 100%)',
				'dark-gradient': 'linear-gradient(180deg, #0a0a0f 0%, #1a1a2e 100%)'
			},
			backgroundSize: {
				'grid': '50px 50px'
			}
		}
	},
	plugins: [require('@tailwindcss/typography')]
};

