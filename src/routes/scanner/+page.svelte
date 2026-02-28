<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Progress } from '$lib/components/ui/progress';
	import { ScrollArea } from '$lib/components/ui/scroll-area';
	import { cn, formatBytes, formatRelativeTime, getSeverityColor } from '$lib/utils';
	import * as api from '$lib/api';
	import {
		Shield,
		Play,
		Square,
		Folder,
		HardDrive,
		Zap,
		AlertTriangle,
		CheckCircle,
		Clock,
		FileSearch,
		Trash2,
		Brain,
		MemoryStick,
		Activity,
		Search,
		Target,
		Cpu,
		Database
	} from 'lucide-svelte';

	let scanSession: api.ScanSession | null = null;
	let scanStatus: api.ScanStatus | null = null;
	let scanResults: api.ScanResults | null = null;
	let advancedScanResults: api.AdvancedScanResults | null = null;
	let isScanning = false;
	let selectedScanType = 'quick';
	let scanMode = 'basic'; // 'basic' or 'advanced'
	let selectedAdvancedScanType: api.ScanType = 'comprehensive';
	let memoryResults: api.MemoryScanResult[] = [];
	let behavioralResults: api.BehavioralAnalysis[] = [];
	let yaraResults: api.YaraScanResult[] = [];

	const scanTypes = [
		{ id: 'quick', name: 'Quick Scan', description: 'Scan common threat locations', icon: Zap, duration: '~5 min' },
		{ id: 'full', name: 'Full Scan', description: 'Comprehensive system scan', icon: HardDrive, duration: '~30 min' },
		{ id: 'custom', name: 'Custom Scan', description: 'Scan selected locations', icon: Folder, duration: 'Varies' }
	];

	const advancedScanTypes = [
		{
			id: 'memory' as api.ScanType,
			name: 'Memory Forensics',
			description: 'Scan process memory for malware signatures',
			icon: MemoryStick,
			duration: '~10 min',
			color: 'text-blue-500'
		},
		{
			id: 'behavioral' as api.ScanType,
			name: 'Behavioral Analysis',
			description: 'Analyze process behavior patterns',
			icon: Activity,
			duration: '~15 min',
			color: 'text-purple-500'
		},
		{
			id: 'yara' as api.ScanType,
			name: 'YARA Rule Scan',
			description: 'Scan files with custom YARA rules',
			icon: Search,
			duration: '~20 min',
			color: 'text-green-500'
		},
		{
			id: 'comprehensive' as api.ScanType,
			name: 'Comprehensive Scan',
			description: 'Complete advanced security analysis',
			icon: Target,
			duration: '~45 min',
			color: 'text-red-500'
		}
	];

	let pollInterval: ReturnType<typeof setInterval> | null = null;

	async function startScan() {
		try {
			isScanning = true;
			scanResults = null;

			if (scanMode === 'basic') {
				scanSession = await api.startScan(selectedScanType);

				pollInterval = setInterval(async () => {
					if (!scanSession) { clearPoll(); return; }
					try {
						scanStatus = await api.getScanStatus(scanSession.id);
						if (scanStatus.status === 'completed' || scanStatus.status === 'stopped') {
							clearPoll();
							scanResults = await api.getScanResults(scanSession.id);
							isScanning = false;
						}
					} catch {
						clearPoll();
						isScanning = false;
					}
				}, 600);
			} else {
				advancedScanResults = null;

				scanSession = await api.startScan('full');

				pollInterval = setInterval(async () => {
					if (!scanSession) { clearPoll(); return; }
					try {
						scanStatus = await api.getScanStatus(scanSession.id);
						if (scanStatus.status === 'completed' || scanStatus.status === 'stopped') {
							clearPoll();

							try {
								advancedScanResults = await api.performAdvancedScan(selectedAdvancedScanType);
								if (advancedScanResults.memory_results) memoryResults = advancedScanResults.memory_results;
								if (advancedScanResults.behavioral_results) behavioralResults = advancedScanResults.behavioral_results;
								if (advancedScanResults.yara_results) yaraResults = advancedScanResults.yara_results;
							} catch (error) {
								console.error('Failed to get advanced scan results:', error);
							}

							isScanning = false;
						}
					} catch {
						clearPoll();
						isScanning = false;
					}
				}, 800);
			}
		} catch (error) {
			console.error('Failed to start scan:', error);
			isScanning = false;
		}
	}

	function clearPoll() {
		if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
	}

	async function stopScan() {
		if (scanSession) {
			try { await api.stopScan(scanSession.id); } catch {}
		}
		clearPoll();
		isScanning = false;
		scanSession = null;
		scanStatus = null;
		advancedScanResults = null;
		memoryResults = [];
		behavioralResults = [];
		yaraResults = [];
	}

	async function quarantineAll() {
		try {
			await api.quarantineThreats([]);
			if (scanSession) {
				scanResults = await api.getScanResults(scanSession.id);
			}
		} catch (error) {
			console.error('Quarantine failed:', error);
		}
	}

	onMount(async () => {
		// Load last scan results
		try {
			scanResults = await api.getScanResults('last');
		} catch (error) {
			console.log('No previous scan results');
		}
	});
</script>

<svelte:head>
	<title>Malware Scanner - Cyber Security Prime</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-3">
			<div class="flex items-center justify-center w-12 h-12 rounded-xl bg-neon-green/10">
				<Shield class="w-6 h-6 text-neon-green" />
			</div>
			<div>
				<h1 class="text-2xl font-bold tracking-tight text-foreground">
					Malware Scanner
				</h1>
				<p class="text-muted-foreground">
					Scan your system for malware, viruses, and other threats
				</p>
			</div>
		</div>
		<Badge variant="success" class="gap-1">
			<div class="w-1.5 h-1.5 rounded-full bg-neon-green animate-pulse" />
			Real-time Protection Active
		</Badge>
	</div>

	<div class="grid grid-cols-12 gap-6">
		<!-- Scan Controls -->
		<div class="col-span-12 lg:col-span-8">
			<Card variant="glass">
				<CardHeader>
					<div class="flex items-center justify-between">
						<div>
							<CardTitle>Security Scanner</CardTitle>
							<CardDescription>
								Choose scan mode and type to protect your system
							</CardDescription>
						</div>
						<div class="flex gap-2">
							<Button
								variant={scanMode === 'basic' ? 'default' : 'outline'}
								size="sm"
								on:click={() => scanMode = 'basic'}
							>
								<FileSearch class="w-4 h-4 mr-2" />
								Basic Scan
							</Button>
							<Button
								variant={scanMode === 'advanced' ? 'default' : 'outline'}
								size="sm"
								on:click={() => scanMode = 'advanced'}
							>
								<Brain class="w-4 h-4 mr-2" />
								Advanced Scan
							</Button>
						</div>
					</div>
				</CardHeader>
				<CardContent class="space-y-6">
					{#if isScanning && scanStatus}
						<!-- Scan Progress -->
						<div class="space-y-4">
							<div class="flex items-center justify-between">
								<div class="flex items-center gap-3">
									<div class="w-10 h-10 rounded-full border-2 border-primary border-t-transparent animate-spin" />
									<div>
										<p class="font-medium">
											{scanMode === 'advanced' ? 'Advanced' : 'Basic'} Scanning in progress...
										</p>
										<p class="text-sm text-muted-foreground">
											{scanStatus.current_file || 'Preparing...'}
										</p>
									</div>
								</div>
								<Button variant="destructive" size="sm" on:click={stopScan}>
									<Square class="w-4 h-4 mr-2" />
									Stop Scan
								</Button>
							</div>

							<div class="space-y-2">
								<div class="flex justify-between text-sm">
									<span class="text-muted-foreground">Progress</span>
									<span class="font-medium">{Math.round(scanStatus.progress)}%</span>
								</div>
								<Progress value={scanStatus.progress} variant="neon" />
							</div>

							<div class="grid grid-cols-3 gap-4">
								<div class="p-3 rounded-lg bg-muted/50">
									<p class="text-2xl font-bold text-foreground">{scanStatus.scanned_files.toLocaleString()}</p>
									<p class="text-xs text-muted-foreground">
										{scanMode === 'advanced' ? 'Items Analyzed' : 'Files Scanned'}
									</p>
								</div>
								<div class="p-3 rounded-lg bg-muted/50">
									<p class="text-2xl font-bold text-neon-red">{scanStatus.threats_found}</p>
									<p class="text-xs text-muted-foreground">Threats Found</p>
								</div>
								<div class="p-3 rounded-lg bg-muted/50">
									<p class="text-2xl font-bold text-foreground">{scanStatus.estimated_time_remaining || '--'}</p>
									<p class="text-xs text-muted-foreground">Time Remaining</p>
								</div>
							</div>
						</div>
					{:else}
						<!-- Scan Type Selection -->
						{#if scanMode === 'basic'}
							<div class="grid grid-cols-3 gap-4">
								{#each scanTypes as scanType}
									<button
										class={cn(
											'p-4 rounded-lg border-2 text-left transition-all',
											selectedScanType === scanType.id
												? 'border-primary bg-primary/5'
												: 'border-border hover:border-primary/50'
										)}
										on:click={() => (selectedScanType = scanType.id)}
									>
										<svelte:component this={scanType.icon} class={cn(
											'w-8 h-8 mb-3',
											selectedScanType === scanType.id ? 'text-primary' : 'text-muted-foreground'
										)} />
										<h3 class="font-medium">{scanType.name}</h3>
										<p class="text-sm text-muted-foreground mt-1">{scanType.description}</p>
										<p class="text-xs text-primary mt-2">{scanType.duration}</p>
									</button>
								{/each}
							</div>
						{:else}
							<div class="grid grid-cols-2 gap-4">
								{#each advancedScanTypes as scanType}
									<button
										class={cn(
											'p-4 rounded-lg border-2 text-left transition-all',
											selectedAdvancedScanType === scanType.id
												? 'border-primary bg-primary/5'
												: 'border-border hover:border-primary/50'
										)}
										on:click={() => (selectedAdvancedScanType = scanType.id)}
									>
										<svelte:component this={scanType.icon} class={cn(
											'w-8 h-8 mb-3',
											selectedAdvancedScanType === scanType.id ? scanType.color : 'text-muted-foreground'
										)} />
										<h3 class="font-medium">{scanType.name}</h3>
										<p class="text-sm text-muted-foreground mt-1">{scanType.description}</p>
										<p class="text-xs text-primary mt-2">{scanType.duration}</p>
									</button>
								{/each}
							</div>
						{/if}

						<Button variant="cyber" size="lg" class="w-full" on:click={startScan}>
							<Play class="w-5 h-5 mr-2" />
							Start {scanMode === 'basic'
								? scanTypes.find(t => t.id === selectedScanType)?.name
								: advancedScanTypes.find(t => t.id === selectedAdvancedScanType)?.name}
						</Button>
					{/if}
				</CardContent>
			</Card>
		</div>

		<!-- Quick Stats -->
		<div class="col-span-12 lg:col-span-4 space-y-4">
			<Card variant="glass">
				<CardContent class="pt-6">
					<div class="flex items-center gap-3 mb-4">
						<Clock class="w-5 h-5 text-primary" />
						<span class="font-medium">Last Scan</span>
					</div>
					<p class="text-2xl font-bold">Today, 2:30 PM</p>
					<p class="text-sm text-muted-foreground mt-1">Quick Scan - No threats found</p>
				</CardContent>
			</Card>

			<Card variant="glass">
				<CardContent class="pt-6">
					<div class="flex items-center gap-3 mb-4">
						<FileSearch class="w-5 h-5 text-primary" />
						<span class="font-medium">Total Scanned</span>
					</div>
					<p class="text-2xl font-bold">1,247,893</p>
					<p class="text-sm text-muted-foreground mt-1">Files scanned this month</p>
				</CardContent>
			</Card>

			<Card variant="glass">
				<CardContent class="pt-6">
					<div class="flex items-center gap-3 mb-4">
						<AlertTriangle class="w-5 h-5 text-neon-yellow" />
						<span class="font-medium">Threats Blocked</span>
					</div>
					<p class="text-2xl font-bold text-neon-yellow">12</p>
					<p class="text-sm text-muted-foreground mt-1">This month</p>
				</CardContent>
			</Card>
		</div>

		<!-- Scan Results / Threat List -->
		{#if (scanResults && scanResults.threats.length > 0) || advancedScanResults}
			<div class="col-span-12 space-y-6">
				<!-- Basic Scan Results -->
				{#if scanResults && scanResults.threats.length > 0}
					<Card variant="glass">
						<CardHeader>
							<div class="flex items-center justify-between">
								<div>
									<CardTitle>Detected Threats</CardTitle>
									<CardDescription>
										{scanResults.threats.length} threats found during the last scan
									</CardDescription>
								</div>
							<Button variant="destructive" size="sm" on:click={quarantineAll}>
								<Trash2 class="w-4 h-4 mr-2" />
								Quarantine All
							</Button>
							</div>
						</CardHeader>
						<CardContent>
							<ScrollArea class="max-h-[300px]">
								<div class="space-y-3">
									{#each scanResults.threats as threat}
										<div class="flex items-center justify-between p-4 rounded-lg bg-muted/50 border border-border">
											<div class="flex items-center gap-4">
												<div class={cn(
													'w-10 h-10 rounded-lg flex items-center justify-center',
													threat.severity === 'critical' || threat.severity === 'high'
														? 'bg-neon-red/20 text-neon-red'
														: 'bg-neon-yellow/20 text-neon-yellow'
												)}>
													<AlertTriangle class="w-5 h-5" />
												</div>
												<div>
													<p class="font-medium">{threat.name}</p>
													<p class="text-sm text-muted-foreground">{threat.file_path}</p>
												</div>
											</div>
											<div class="flex items-center gap-3">
												<Badge variant={threat.severity === 'high' || threat.severity === 'critical' ? 'danger' : 'warning'}>
													{threat.severity}
												</Badge>
												<Badge variant={threat.status === 'quarantined' ? 'success' : 'outline'}>
													{threat.status}
												</Badge>
											</div>
										</div>
									{/each}
								</div>
							</ScrollArea>
						</CardContent>
					</Card>
				{/if}

				<!-- Advanced Scan Results -->
				{#if advancedScanResults}
					<!-- Comprehensive Score -->
					<Card variant="glass">
						<CardHeader>
							<CardTitle>Advanced Scan Results</CardTitle>
							<CardDescription>
								Comprehensive security analysis completed
							</CardDescription>
						</CardHeader>
						<CardContent>
							<div class="grid grid-cols-2 gap-6">
								<div class="text-center">
									<div class="text-4xl font-bold mb-2">{advancedScanResults.comprehensive_score}/100</div>
									<div class="text-sm text-muted-foreground">Security Score</div>
									<Badge variant={advancedScanResults.comprehensive_score >= 80 ? 'success' : advancedScanResults.comprehensive_score >= 60 ? 'warning' : 'danger'} class="mt-2">
										{advancedScanResults.overall_risk_assessment}
									</Badge>
								</div>
								<div class="space-y-3">
									{#if advancedScanResults.memory_results && advancedScanResults.memory_results.length > 0}
										<div class="flex justify-between">
											<span class="text-sm">Memory Scans</span>
											<Badge variant="outline">{advancedScanResults.memory_results.length} processes</Badge>
										</div>
									{/if}
									{#if advancedScanResults.behavioral_results && advancedScanResults.behavioral_results.length > 0}
										<div class="flex justify-between">
											<span class="text-sm">Behavioral Analysis</span>
											<Badge variant="outline">{advancedScanResults.behavioral_results.length} processes</Badge>
										</div>
									{/if}
									{#if advancedScanResults.yara_results && advancedScanResults.yara_results.length > 0}
										<div class="flex justify-between">
											<span class="text-sm">YARA Matches</span>
											<Badge variant="outline">{advancedScanResults.yara_results.reduce((sum, r) => sum + r.matches.length, 0)} matches</Badge>
										</div>
									{/if}
								</div>
							</div>
						</CardContent>
					</Card>

					<!-- Memory Forensics Results -->
					{#if memoryResults.length > 0}
						<Card variant="glass">
							<CardHeader>
								<CardTitle class="flex items-center gap-2">
									<MemoryStick class="w-5 h-5 text-blue-500" />
									Memory Forensics Analysis
								</CardTitle>
								<CardDescription>
									Process memory analysis results
								</CardDescription>
							</CardHeader>
							<CardContent>
								<ScrollArea class="max-h-[400px]">
									<div class="space-y-4">
										{#each memoryResults as process}
											<div class="border border-border rounded-lg p-4">
												<div class="flex items-center justify-between mb-3">
													<h4 class="font-medium">{process.process_name}</h4>
													<Badge variant="outline">PID: {process.process_id}</Badge>
												</div>

												{#if process.detected_signatures.length > 0}
													<div class="mb-3">
														<p class="text-sm font-medium text-neon-red mb-2">Detected Signatures:</p>
														<div class="space-y-1">
															{#each process.detected_signatures as sig}
																<div class="flex items-center gap-2 text-sm">
																	<AlertTriangle class="w-4 h-4 text-neon-red" />
																	<span class="font-medium">{sig.name}</span>
																	<Badge variant="danger" class="text-xs">{sig.severity}</Badge>
																</div>
															{/each}
														</div>
													</div>
												{/if}

												{#if process.suspicious_patterns.length > 0}
													<div class="mb-3">
														<p class="text-sm font-medium text-neon-yellow mb-2">Suspicious Patterns:</p>
														<ul class="text-sm text-muted-foreground space-y-1">
															{#each process.suspicious_patterns as pattern}
																<li>• {pattern}</li>
															{/each}
														</ul>
													</div>
												{/if}

												<div class="text-xs text-muted-foreground">
													Scan duration: {process.scan_duration_ms}ms
												</div>
											</div>
										{/each}
									</div>
								</ScrollArea>
							</CardContent>
						</Card>
					{/if}

					<!-- Behavioral Analysis Results -->
					{#if behavioralResults.length > 0}
						<Card variant="glass">
							<CardHeader>
								<CardTitle class="flex items-center gap-2">
									<Activity class="w-5 h-5 text-purple-500" />
									Behavioral Analysis
								</CardTitle>
								<CardDescription>
									Process behavior pattern analysis
								</CardDescription>
							</CardHeader>
							<CardContent>
								<ScrollArea class="max-h-[400px]">
									<div class="space-y-4">
										{#each behavioralResults as analysis}
											<div class="border border-border rounded-lg p-4">
												<div class="flex items-center justify-between mb-3">
													<h4 class="font-medium">{analysis.process_name}</h4>
													<div class="flex gap-2">
														<Badge variant={analysis.risk_level.includes('HIGH') ? 'danger' : analysis.risk_level.includes('MEDIUM') ? 'warning' : 'success'}>
															{analysis.risk_level}
														</Badge>
														<Badge variant="outline">{Math.round(analysis.behavior_score)}/100</Badge>
													</div>
												</div>

												{#if analysis.anomalies.length > 0}
													<div class="mb-3">
														<p class="text-sm font-medium mb-2">Detected Anomalies:</p>
														<div class="space-y-2">
															{#each analysis.anomalies as anomaly}
																<div class="flex items-center gap-2 p-2 bg-muted/50 rounded text-sm">
																	<AlertTriangle class={cn(
																		'w-4 h-4',
																		anomaly.severity === 'high' || anomaly.severity === 'critical'
																			? 'text-neon-red'
																			: 'text-neon-yellow'
																	)} />
																	<div class="flex-1">
																		<p class="font-medium">{anomaly.anomaly_type}</p>
																		<p class="text-muted-foreground text-xs">{anomaly.description}</p>
																	</div>
																	<Badge variant={anomaly.severity === 'high' || anomaly.severity === 'critical' ? 'danger' : 'warning'} class="text-xs">
																		{Math.round(anomaly.confidence * 100)}%
																	</Badge>
																</div>
															{/each}
														</div>
													</div>
												{/if}

												{#if analysis.recommendations.length > 0}
													<div>
														<p class="text-sm font-medium mb-2">Recommendations:</p>
														<ul class="text-sm text-muted-foreground space-y-1">
															{#each analysis.recommendations as rec}
																<li>• {rec}</li>
															{/each}
														</ul>
													</div>
												{/if}
											</div>
										{/each}
									</div>
								</ScrollArea>
							</CardContent>
						</Card>
					{/if}

					<!-- YARA Scan Results -->
					{#if yaraResults.length > 0}
						<Card variant="glass">
							<CardHeader>
								<CardTitle class="flex items-center gap-2">
									<Search class="w-5 h-5 text-green-500" />
									YARA Rule Matches
								</CardTitle>
								<CardDescription>
									Custom rule-based detection results
								</CardDescription>
							</CardHeader>
							<CardContent>
								<ScrollArea class="max-h-[400px]">
									<div class="space-y-4">
										{#each yaraResults as result}
											<div class="border border-border rounded-lg p-4">
												<div class="flex items-center justify-between mb-3">
													<h4 class="font-medium">{result.rule_name}</h4>
													<Badge variant={result.severity === 'high' || result.severity === 'critical' ? 'danger' : 'warning'}>
														{result.severity}
													</Badge>
												</div>

												<div class="space-y-2">
													{#each result.matches as match}
														<div class="p-3 bg-muted/50 rounded text-sm">
															<div class="flex items-center justify-between mb-1">
																<code class="text-xs">{match.file_path}</code>
																<span class="text-xs text-muted-foreground">Offset: 0x{match.offset.toString(16)}</span>
															</div>
															<div class="text-xs text-muted-foreground">
																String: {match.string_identifier} = "{match.string_data}"
															</div>
														</div>
													{/each}
												</div>
											</div>
										{/each}
									</div>
								</ScrollArea>
							</CardContent>
						</Card>
					{/if}
				{/if}
			</div>
		{/if}
	</div>
</div>

