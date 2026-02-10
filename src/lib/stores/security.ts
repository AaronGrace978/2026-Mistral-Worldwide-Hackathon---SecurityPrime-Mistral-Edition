// Cyber Security Prime - Security State Store
// Manages security score, alerts, and activity
// Optimized with debouncing and caching to prevent rapid API calls

import { writable, derived, get } from 'svelte/store';
import * as api from '$lib/api';
import type { 
	SecurityScore, 
	ActivityEvent, 
	ThreatAlert, 
	ModuleStatus 
} from '$lib/api';

// ============================================================================
// Debounce/Throttle Utilities
// ============================================================================

// Cache for preventing rapid successive calls
const fetchCache = new Map<string, { data: unknown; timestamp: number }>();
const CACHE_TTL_MS = 2000; // 2 seconds cache

// In-flight requests to prevent duplicate calls
const inFlightRequests = new Map<string, Promise<unknown>>();

/**
 * Cached fetch - prevents rapid successive API calls
 * Returns cached data if within TTL, otherwise makes a new request
 */
async function cachedFetch<T>(
	key: string, 
	fetcher: () => Promise<T>,
	ttlMs: number = CACHE_TTL_MS
): Promise<T> {
	const now = Date.now();
	const cached = fetchCache.get(key);
	
	// Return cached data if still fresh
	if (cached && (now - cached.timestamp) < ttlMs) {
		return cached.data as T;
	}
	
	// Check if there's already an in-flight request for this key
	const inFlight = inFlightRequests.get(key);
	if (inFlight) {
		return inFlight as Promise<T>;
	}
	
	// Make new request
	const request = fetcher().then(data => {
		fetchCache.set(key, { data, timestamp: Date.now() });
		inFlightRequests.delete(key);
		return data;
	}).catch(error => {
		inFlightRequests.delete(key);
		throw error;
	});
	
	inFlightRequests.set(key, request);
	return request;
}

/**
 * Clear cache for a specific key or all keys
 */
function clearCache(key?: string) {
	if (key) {
		fetchCache.delete(key);
	} else {
		fetchCache.clear();
	}
}

// ============================================================================
// Security Score Store (with caching)
// ============================================================================

function createSecurityScoreStore() {
	const { subscribe, set, update } = writable<SecurityScore | null>(null);

	return {
		subscribe,
		fetch: async () => {
			try {
				const score = await cachedFetch('security_score', api.getSecurityScore);
				set(score);
				return score;
			} catch (error) {
				console.error('Failed to fetch security score:', error);
				return null;
			}
		},
		// Force refresh bypasses cache
		forceRefresh: async () => {
			clearCache('security_score');
			try {
				const score = await api.getSecurityScore();
				set(score);
				fetchCache.set('security_score', { data: score, timestamp: Date.now() });
				return score;
			} catch (error) {
				console.error('Failed to fetch security score:', error);
				return null;
			}
		},
		reset: () => set(null)
	};
}

// ============================================================================
// Activity Store (with caching)
// ============================================================================

function createActivityStore() {
	const { subscribe, set, update } = writable<ActivityEvent[]>([]);

	return {
		subscribe,
		fetch: async (limit?: number) => {
			try {
				const cacheKey = `activities_${limit ?? 'all'}`;
				const activities = await cachedFetch(cacheKey, () => api.getRecentActivity(limit));
				set(activities);
				return activities;
			} catch (error) {
				console.error('Failed to fetch activities:', error);
				return [];
			}
		},
		add: (event: ActivityEvent) => {
			update((events) => [event, ...events].slice(0, 50));
			// Invalidate cache when adding locally
			clearCache('activities_10');
			clearCache('activities_all');
		},
		clear: () => set([])
	};
}

// ============================================================================
// Threat Alerts Store (with caching)
// ============================================================================

function createAlertsStore() {
	const { subscribe, set, update } = writable<ThreatAlert[]>([]);

	return {
		subscribe,
		fetch: async () => {
			try {
				const alerts = await cachedFetch('threat_alerts', api.getThreatAlerts);
				set(alerts);
				return alerts;
			} catch (error) {
				console.error('Failed to fetch threat alerts:', error);
				return [];
			}
		},
		add: (alert: ThreatAlert) => {
			update((alerts) => [alert, ...alerts]);
			clearCache('threat_alerts');
		},
		resolve: (id: string) => {
			update((alerts) =>
				alerts.map((a) => (a.id === id ? { ...a, resolved: true } : a))
			);
			clearCache('threat_alerts');
		},
		remove: (id: string) => {
			update((alerts) => alerts.filter((a) => a.id !== id));
			clearCache('threat_alerts');
		},
		clear: () => set([])
	};
}

// ============================================================================
// Module Status Store (with caching)
// ============================================================================

function createModuleStatusStore() {
	const { subscribe, set, update } = writable<ModuleStatus[]>([]);

	return {
		subscribe,
		fetch: async () => {
			try {
				const statuses = await cachedFetch('module_statuses', api.getModuleStatus);
				set(statuses);
				return statuses;
			} catch (error) {
				console.error('Failed to fetch module statuses:', error);
				return [];
			}
		},
		toggle: async (moduleName: string, enabled: boolean) => {
			try {
				await api.toggleModule(moduleName, enabled);
				update((modules) =>
					modules.map((m) =>
						m.name === moduleName
							? { ...m, enabled, status: enabled ? 'active' : 'inactive' }
							: m
					)
				);
				// Invalidate cache after toggle
				clearCache('module_statuses');
				clearCache('security_score'); // Score depends on module status
				return true;
			} catch (error) {
				console.error('Failed to toggle module:', error);
				return false;
			}
		},
		updateStatus: (moduleName: string, status: ModuleStatus['status']) => {
			update((modules) =>
				modules.map((m) => (m.name === moduleName ? { ...m, status } : m))
			);
		}
	};
}

// ============================================================================
// Export Stores
// ============================================================================

export const securityScore = createSecurityScoreStore();
export const activities = createActivityStore();
export const alerts = createAlertsStore();
export const moduleStatuses = createModuleStatusStore();

// ============================================================================
// Derived Stores (computed from base stores)
// ============================================================================

export const unresolvedAlerts = derived(alerts, ($alerts) =>
	$alerts.filter((a) => !a.resolved)
);

export const criticalAlerts = derived(alerts, ($alerts) =>
	$alerts.filter((a) => !a.resolved && (a.severity === 'critical' || a.severity === 'high'))
);

export const activeModules = derived(moduleStatuses, ($modules) =>
	$modules.filter((m) => m.enabled && m.status === 'active')
);

// ============================================================================
// Initialization & Refresh Functions
// ============================================================================

// Throttle for initSecurityData to prevent multiple rapid calls
let lastInitTime = 0;
const INIT_THROTTLE_MS = 1000;

/**
 * Initialize all security data
 * Throttled to prevent rapid successive calls (e.g., from multiple components mounting)
 */
export async function initSecurityData() {
	const now = Date.now();
	if (now - lastInitTime < INIT_THROTTLE_MS) {
		// Skip if called too recently
		return;
	}
	lastInitTime = now;

	await Promise.all([
		securityScore.fetch(),
		activities.fetch(10),
		alerts.fetch(),
		moduleStatuses.fetch()
	]);
}

/**
 * Force refresh all security data (bypasses cache)
 */
export async function refreshSecurityData() {
	// Clear all caches before refresh
	clearCache();
	
	await Promise.all([
		securityScore.fetch(),
		activities.fetch(10),
		alerts.fetch(),
		moduleStatuses.fetch()
	]);
}

