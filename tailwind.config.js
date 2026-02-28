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
				// Mistral brand colors (2025 rebrand)
				mistral: {
					red: '#E10500',
					'orange-dark': '#FA5010',
					orange: '#FF8205',
					'orange-light': '#FFB000',
					yellow: '#FFD800',
					beige: '#FFFAEB',
					'beige-mid': '#FFF0C3',
					'beige-dark': '#E9E2CB',
					black: '#0A0A0F'
				},
				cyber: {
					blue: '#FF8205',
					'blue-dark': '#FA5010',
					purple: '#FFB000',
					'purple-dark': '#d97706',
					pink: '#FA5010',
					yellow: '#FFD800',
					green: '#22c55e',
					red: '#E10500',
					orange: '#FF8205'
				},
				neon: {
					blue: '#FF8205',
					purple: '#FFB000',
					pink: '#FA5010',
					green: '#22c55e',
					yellow: '#FFD800',
					red: '#E10500'
				}
			},
			borderRadius: {
				lg: 'var(--radius)',
				md: 'calc(var(--radius) - 2px)',
				sm: 'calc(var(--radius) - 4px)'
			},
			fontFamily: {
				sans: ['Space Grotesk', 'Rajdhani', 'Inter', 'system-ui', 'sans-serif'],
				mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
				cyber: ['Orbitron', 'sans-serif']
			},
			boxShadow: {
				'neon-blue': '0 0 5px #ff8a12, 0 0 20px rgba(255, 138, 18, 0.35)',
				'neon-purple': '0 0 5px #ff9f43, 0 0 20px rgba(255, 159, 67, 0.3)',
				'neon-green': '0 0 5px #00ff88, 0 0 20px rgba(0, 255, 136, 0.3)',
				'neon-red': '0 0 5px #ff0044, 0 0 20px rgba(255, 0, 68, 0.3)',
				'neon-yellow': '0 0 5px #ff8a12, 0 0 20px rgba(255, 138, 18, 0.35)',
				glow: '0 0 15px rgba(255, 138, 18, 0.45)',
				'glow-lg': '0 0 30px rgba(255, 138, 18, 0.35)',
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
						boxShadow: '0 0 5px #ff8a12, 0 0 10px rgba(255, 138, 18, 0.3)'
					},
					'50%': { 
						boxShadow: '0 0 10px #ff8a12, 0 0 30px rgba(255, 138, 18, 0.5)'
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
					linear-gradient(rgba(255, 138, 18, 0.03) 1px, transparent 1px),
					linear-gradient(90deg, rgba(255, 138, 18, 0.03) 1px, transparent 1px)
				`,
				'cyber-gradient': 'linear-gradient(135deg, rgba(255, 138, 18, 0.12) 0%, rgba(255, 107, 53, 0.12) 100%)',
				'dark-gradient': 'linear-gradient(180deg, #0a0a0f 0%, #1a1a2e 100%)'
			},
			backgroundSize: {
				'grid': '50px 50px'
			}
		}
	},
	plugins: [require('@tailwindcss/typography')]
};

