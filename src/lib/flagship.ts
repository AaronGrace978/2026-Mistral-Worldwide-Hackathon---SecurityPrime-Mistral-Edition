export type FlagshipPillar = 'autonomous-defense' | 'enterprise-trust' | 'premium-experience';

export interface FlagshipEnhancement {
	id: string;
	title: string;
	description: string;
	pillar: FlagshipPillar;
	route: string;
	ownerModule: string;
}

export const flagshipEnhancements: FlagshipEnhancement[] = [
	{
		id: 'autonomous-response-playbooks',
		title: 'Autonomous Response Playbooks',
		description: 'Automated containment workflows based on threat score thresholds.',
		pillar: 'autonomous-defense',
		route: '/flagship/autonomous-response-playbooks',
		ownerModule: 'protection'
	},
	{
		id: 'attack-surface-dashboard',
		title: 'Attack Surface Dashboard',
		description: 'Unified exposure map across vulnerabilities, ports, services, and firewall posture.',
		pillar: 'autonomous-defense',
		route: '/flagship/attack-surface-dashboard',
		ownerModule: 'monitoring'
	},
	{
		id: 'behavior-detection-engine',
		title: 'Behavior-Based Detection Engine',
		description: 'Detect suspicious behavior chains beyond signature-only matching.',
		pillar: 'autonomous-defense',
		route: '/flagship/behavior-detection-engine',
		ownerModule: 'protection'
	},
	{
		id: 'threat-timeline',
		title: 'Threat Timeline (EDR-lite)',
		description: 'Investigation-ready timeline to trace incident progression and response.',
		pillar: 'autonomous-defense',
		route: '/analytics',
		ownerModule: 'analytics'
	},
	{
		id: 'zero-trust-app-control',
		title: 'Zero-Trust App Control',
		description: 'Policy controls by hash, signer reputation, and process lineage.',
		pillar: 'autonomous-defense',
		route: '/flagship/zero-trust-app-control',
		ownerModule: 'protection'
	},
	{
		id: 'rollback-remediation',
		title: 'Rollback and Remediation Mode',
		description: 'Guided cleanup and rollback workflow after threat containment.',
		pillar: 'autonomous-defense',
		route: '/flagship/rollback-remediation',
		ownerModule: 'protection'
	},
	{
		id: 'tamper-protection',
		title: 'Tamper Protection Controls',
		description: 'Protect critical settings and monitor unauthorized changes.',
		pillar: 'enterprise-trust',
		route: '/tamper-detection',
		ownerModule: 'hardening'
	},
	{
		id: 'signed-rule-packs',
		title: 'Signed Rule Pack Updates',
		description: 'Verify cryptographic signatures before detection/rule updates apply.',
		pillar: 'enterprise-trust',
		route: '/flagship/signed-rule-packs',
		ownerModule: 'hardening'
	},
	{
		id: 'local-first-ai-copilot',
		title: 'Local-First AI Security Copilot',
		description: 'On-device AI triage with optional cloud assistance.',
		pillar: 'enterprise-trust',
		route: '/agent',
		ownerModule: 'ai'
	},
	{
		id: 'audit-ready-reporting',
		title: 'Audit-Ready PDF and JSON Reporting',
		description: 'Export incident and posture reports for internal and external audits.',
		pillar: 'enterprise-trust',
		route: '/flagship/audit-ready-reporting',
		ownerModule: 'compliance'
	},
	{
		id: 'compliance-profiles',
		title: 'Compliance Profiles (CIS/NIST-lite)',
		description: 'Prebuilt hardening baselines mapped to common security standards.',
		pillar: 'enterprise-trust',
		route: '/compliance',
		ownerModule: 'compliance'
	},
	{
		id: 'encryption-key-recovery',
		title: 'Secure Encryption Key Backup and Recovery',
		description: 'Protected key export/import and recovery flow for encrypted assets.',
		pillar: 'enterprise-trust',
		route: '/flagship/encryption-key-recovery',
		ownerModule: 'encryption'
	},
	{
		id: 'hardening-wizard',
		title: 'First 10 Minutes Hardening Wizard',
		description: 'Step-by-step onboarding workflow to secure systems quickly.',
		pillar: 'premium-experience',
		route: '/flagship/hardening-wizard',
		ownerModule: 'ux'
	},
	{
		id: 'security-score-deltas',
		title: 'Actionable Security Score Deltas',
		description: 'Show projected score impact before applying recommended actions.',
		pillar: 'premium-experience',
		route: '/flagship/security-score-deltas',
		ownerModule: 'dashboard'
	},
	{
		id: 'alert-confidence-dedup',
		title: 'Alert Confidence and Deduplication',
		description: 'Reduce alert fatigue by merging duplicates and confidence-ranking findings.',
		pillar: 'premium-experience',
		route: '/flagship/alert-confidence-dedup',
		ownerModule: 'monitoring'
	},
	{
		id: 'benchmark-posture-mode',
		title: 'Benchmark Posture Mode',
		description: 'Compare local posture against anonymized baseline benchmarks.',
		pillar: 'premium-experience',
		route: '/flagship/benchmark-posture-mode',
		ownerModule: 'analytics'
	}
];

export const flagshipById = Object.fromEntries(flagshipEnhancements.map((item) => [item.id, item]));

export function getPillarLabel(pillar: FlagshipPillar): string {
	switch (pillar) {
		case 'autonomous-defense':
			return 'Autonomous Defense';
		case 'enterprise-trust':
			return 'Enterprise Trust';
		case 'premium-experience':
			return 'Premium Experience';
	}
}

