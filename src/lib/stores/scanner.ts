import { writable, derived } from 'svelte/store';
import * as api from '$lib/api';

export interface ScanState {
	isScanning: boolean;
	scanMode: 'basic' | 'advanced';
	scanType: string;
	advancedScanType: api.ScanType;
	customPaths: string[];
	scanSession: api.ScanSession | null;
	scanStatus: api.ScanStatus | null;
	scanResults: api.ScanResults | null;
	advancedScanResults: api.AdvancedScanResults | null;
	memoryResults: api.MemoryScanResult[];
	behavioralResults: api.BehavioralAnalysis[];
	yaraResults: api.YaraScanResult[];
}

const initialState: ScanState = {
	isScanning: false,
	scanMode: 'basic',
	scanType: 'quick',
	advancedScanType: 'comprehensive',
	customPaths: [],
	scanSession: null,
	scanStatus: null,
	scanResults: null,
	advancedScanResults: null,
	memoryResults: [],
	behavioralResults: [],
	yaraResults: []
};

function createScanStore() {
	const { subscribe, set, update } = writable<ScanState>(initialState);
	let pollInterval: ReturnType<typeof setInterval> | null = null;

	function clearPoll() {
		if (pollInterval) {
			clearInterval(pollInterval);
			pollInterval = null;
		}
	}

	function getState(): ScanState {
		let state: ScanState = initialState;
		const unsub = subscribe(s => state = s);
		unsub();
		return state;
	}

	function startBasicPolling() {
		pollInterval = setInterval(async () => {
			const current = getState();
			if (!current.scanSession) { clearPoll(); return; }
			try {
				const status = await api.getScanStatus(current.scanSession.id);
				update(s => ({ ...s, scanStatus: status }));
				if (status.status === 'completed' || status.status === 'stopped') {
					clearPoll();
					const results = await api.getScanResults(current.scanSession.id);
					update(s => ({ ...s, scanResults: results, isScanning: false }));
				}
			} catch {
				clearPoll();
				update(s => ({ ...s, isScanning: false }));
			}
		}, 600);
	}

	return {
		subscribe,
		update,

		setScanMode(mode: 'basic' | 'advanced') {
			update(s => ({ ...s, scanMode: mode }));
		},

		setScanType(type: string) {
			update(s => ({ ...s, scanType: type }));
		},

		setAdvancedScanType(type: api.ScanType) {
			update(s => ({ ...s, advancedScanType: type }));
		},

		setCustomPaths(paths: string[]) {
			update(s => ({ ...s, customPaths: paths }));
		},

		addCustomPath(path: string) {
			update(s => {
				if (s.customPaths.includes(path)) return s;
				return { ...s, customPaths: [...s.customPaths, path] };
			});
		},

		removeCustomPath(path: string) {
			update(s => ({ ...s, customPaths: s.customPaths.filter(p => p !== path) }));
		},

		async startScan() {
			const state = getState();
			update(s => ({ ...s, isScanning: true, scanResults: null, advancedScanResults: null }));

			try {
				if (state.scanMode === 'basic') {
					let session: api.ScanSession;
					if (state.scanType === 'custom') {
						if (state.customPaths.length === 0) {
							update(s => ({ ...s, isScanning: false }));
							return;
						}
						session = await api.startCustomScan(state.customPaths);
					} else {
						session = await api.startScan(state.scanType);
					}
					update(s => ({ ...s, scanSession: session }));
					startBasicPolling();
				} else {
					const fakeSession: api.ScanSession = { id: `adv-${Date.now()}`, scan_type: state.advancedScanType, status: 'running', started_at: new Date().toISOString(), total_files: 0, scanned_files: 0, threats_found: 0 };
					const initStatus: api.ScanStatus = { id: fakeSession.id, status: 'running', progress: 10, scanned_files: 0, threats_found: 0, current_file: 'Initializing advanced scan...', estimated_time_remaining: 'Calculating...' };
					update(s => ({ ...s, scanSession: fakeSession, scanStatus: initStatus }));

					let tick = 0;
					pollInterval = setInterval(() => {
						tick++;
						const pct = Math.min(90, tick * 8);
						const labels = ['Scanning process memory...', 'Analyzing behavioral patterns...', 'Running YARA rules...', 'Computing risk assessment...'];
						update(s => ({ ...s, scanStatus: { ...s.scanStatus!, progress: pct, scanned_files: tick * 12, current_file: labels[tick % labels.length] } }));
					}, 800);

					try {
						const adv = await api.performAdvancedScan(state.advancedScanType);
						clearPoll();
						update(s => ({
							...s,
							scanStatus: { ...s.scanStatus!, progress: 100, current_file: 'Complete' },
							advancedScanResults: adv,
							memoryResults: adv.memory_results || [],
							behavioralResults: adv.behavioral_results || [],
							yaraResults: adv.yara_results || [],
							isScanning: false
						}));
					} catch (err) {
						clearPoll();
						console.error('Advanced scan failed:', err);
						update(s => ({ ...s, isScanning: false }));
					}
				}
			} catch (error) {
				console.error('Failed to start scan:', error);
				update(s => ({ ...s, isScanning: false }));
			}
		},

		async stopScan() {
			const current = getState();
			if (current.scanSession) {
				try { await api.stopScan(current.scanSession.id); } catch {}
			}
			clearPoll();
			update(s => ({
				...s,
				isScanning: false,
				scanSession: null,
				scanStatus: null,
				advancedScanResults: null,
				memoryResults: [],
				behavioralResults: [],
				yaraResults: []
			}));
		},

		async loadLastResults() {
			if (getState().isScanning) return;
			try {
				const results = await api.getScanResults('last');
				update(s => {
					if (s.isScanning) return s;
					return { ...s, scanResults: results };
				});
			} catch {}
		}
	};
}

export const scanStore = createScanStore();
export const isScanning = derived(scanStore, $s => $s.isScanning);
export const scanProgress = derived(scanStore, $s => $s.scanStatus?.progress ?? 0);
