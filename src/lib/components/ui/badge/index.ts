import Root from './badge.svelte';
import { tv, type VariantProps } from 'tailwind-variants';

const badgeVariants = tv({
	base: 'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2',
	variants: {
		variant: {
			default: 'border-transparent bg-primary text-primary-foreground',
			secondary: 'border-transparent bg-secondary text-secondary-foreground',
			destructive: 'border-transparent bg-destructive text-destructive-foreground',
			outline: 'text-foreground',
			success: 'border-neon-green/30 bg-neon-green/20 text-neon-green',
			warning: 'border-neon-yellow/30 bg-neon-yellow/20 text-neon-yellow',
			danger: 'border-neon-red/30 bg-neon-red/20 text-neon-red',
			info: 'border-cyber-blue/30 bg-cyber-blue/20 text-cyber-blue'
		}
	},
	defaultVariants: {
		variant: 'default'
	}
});

type Variant = VariantProps<typeof badgeVariants>['variant'];

type Props = {
	variant?: Variant;
};

export { Root, type Props, Root as Badge, badgeVariants, type Variant as BadgeVariant };

