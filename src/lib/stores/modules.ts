// Cyber Security Prime - Module Registry Store
// Manages available modules and their configuration

import { writable, derived } from 'svelte/store';
import type { ComponentType } from 'svelte';
import {
	Shield,
	Flame,
	Lock,
	Bug,
	Network,
	Bot,
	Settings,
	LayoutDashboard,
	Globe,
	BarChart3,
	Puzzle,
	MonitorSpeaker,
	Scale,
	Box,
	AlertTriangle,
	Zap,
	Rocket,
	Wand2,
	Target
} from 'lucide-svelte';

export interface ModuleInfo {
	id: string;
	name: string;
	description: string;
	icon: ComponentType;
	route: string;
	category: 'protection' | 'tools' | 'monitoring' | 'ai' | 'system';
	color: string;
	comingSoon?: boolean;
}

// Define all available modules
export const allModules: ModuleInfo[] = [
	{
		id: 'dashboard',
		name: 'Dashboard',
		description: 'Security overview and system status',
		icon: LayoutDashboard,
		route: '/',
		category: 'system',
		color: 'cyber-blue'
	},
	{
		id: 'hardening-wizard',
		name: 'Hardening Wizard',
		description: 'Guided 10-minute setup to harden your system',
		icon: Wand2,
		route: '/hardening-wizard',
		category: 'system',
		color: 'cyber-orange'
	},
	{
		id: 'benchmark',
		name: 'Benchmark',
		description: 'Compare your security posture against baselines',
		icon: Target,
		route: '/benchmark',
		category: 'monitoring',
		color: 'cyber-purple'
	},
	{
		id: 'flagship',
		name: 'Flagship',
		description: 'Flagship enhancement control center',
		icon: Rocket,
		route: '/flagship',
		category: 'system',
		color: 'neon-pink'
	},
	{
		id: 'scanner',
		name: 'Malware Scanner',
		description: 'Real-time and on-demand malware scanning',
		icon: Shield,
		route: '/scanner',
		category: 'protection',
		color: 'neon-green'
	},
	{
		id: 'firewall',
		name: 'Firewall',
		description: 'Advanced network firewall management',
		icon: Flame,
		route: '/firewall',
		category: 'protection',
		color: 'cyber-orange'
	},
	{
		id: 'encryption',
		name: 'Encryption',
		description: 'File and folder encryption tools',
		icon: Lock,
		route: '/encryption',
		category: 'tools',
		color: 'cyber-purple'
	},
	{
		id: 'vulnerability',
		name: 'Vulnerabilities',
		description: 'System vulnerability scanner',
		icon: Bug,
		route: '/vulnerability',
		category: 'monitoring',
		color: 'neon-yellow'
	},
	{
		id: 'network',
		name: 'Network Monitor',
		description: 'Network traffic and connection monitoring',
		icon: Network,
		route: '/network',
		category: 'monitoring',
		color: 'cyber-blue'
	},
	{
		id: 'vpn',
		name: 'VPN',
		description: 'Free VPN protection powered by WireGuard',
		icon: Globe,
		route: '/vpn',
		category: 'protection',
		color: 'neon-green'
	},
	{
		id: 'agent',
		name: 'Mistral Copilot',
		description: 'Multi-model AI security analysis powered by Mistral',
		icon: Bot,
		route: '/agent',
		category: 'ai',
		color: 'cyber-orange'
	},
	{
		id: 'analytics',
		name: 'Analytics',
		description: 'Historical threat analysis and security trends',
		icon: BarChart3,
		route: '/analytics',
		category: 'monitoring',
		color: 'neon-pink'
	},
	{
		id: 'management',
		name: 'Management',
		description: 'Enterprise management console and multi-instance control',
		icon: MonitorSpeaker,
		route: '/management',
		category: 'system',
		color: 'cyber-blue'
	},
	{
		id: 'compliance',
		name: 'Compliance',
		description: 'GDPR, HIPAA, and regulatory compliance reporting',
		icon: Scale,
		route: '/compliance',
		category: 'system',
		color: 'cyber-green'
	},
	{
		id: 'isolation',
		name: 'Isolation',
		description: 'Process sandboxing and containerization',
		icon: Box,
		route: '/isolation',
		category: 'protection',
		color: 'cyber-orange'
	},
	{
		id: 'tamper-detection',
		name: 'Tamper Detection',
		description: 'Integrity checking, anomaly detection, and secure boot',
		icon: AlertTriangle,
		route: '/tamper-detection',
		category: 'protection',
		color: 'cyber-red'
	},
	{
		id: 'security-hardening',
		name: 'Security Hardening',
		description: 'Memory protection, secure logging, and rate limiting',
		icon: Zap,
		route: '/security-hardening',
		category: 'protection',
		color: 'cyber-yellow'
	},
	{
		id: 'plugins',
		name: 'Plugins',
		description: 'Third-party security tool integrations',
		icon: Puzzle,
		route: '/plugins',
		category: 'tools',
		color: 'cyber-purple'
	},
	{
		id: 'settings',
		name: 'Settings',
		description: 'Application settings and preferences',
		icon: Settings,
		route: '/settings',
		category: 'system',
		color: 'muted-foreground'
	}
];

// Create modules store
function createModulesStore() {
	const { subscribe, set, update } = writable<ModuleInfo[]>(allModules);

	return {
		subscribe,
		getModule: (id: string) => allModules.find((m) => m.id === id),
		getModulesByCategory: (category: ModuleInfo['category']) =>
			allModules.filter((m) => m.category === category),
		getNavigationModules: () =>
			allModules.filter((m) => m.category !== 'system' || m.id === 'dashboard')
	};
}

export const modules = createModulesStore();

// Derived stores for navigation
export const navigationModules = derived(modules, () => 
	allModules.filter((m) => m.id !== 'settings')
);

export const protectionModules = derived(modules, () =>
	allModules.filter((m) => m.category === 'protection')
);

export const monitoringModules = derived(modules, () =>
	allModules.filter((m) => m.category === 'monitoring')
);

export const toolModules = derived(modules, () =>
	allModules.filter((m) => m.category === 'tools')
);

