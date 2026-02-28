<script lang="ts">
	import { page } from '$app/stores';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import { flagshipById, getPillarLabel } from '$lib/flagship';
	import {
		ArrowLeft,
		CheckCircle2,
		ListChecks,
		Route,
		RefreshCw,
		Shield,
		KeyRound
	} from 'lucide-svelte';
	import * as api from '$lib/api';

	let loading = false;
	let loadError: string | null = null;
	let lastLoadedId = '';

	let playbooks: api.AutonomousResponsePlaybook[] = [];
	let dryRunResult: api.PlaybookDryRunResult | null = null;

	let attackSurface: api.AttackSurfaceSnapshot | null = null;

	let rulePackStatus: api.SignedRulePackStatus | null = null;
	let verificationResult: api.RulePackVerificationResult | null = null;

	$: enhancementId = $page.params.id;
	$: enhancement = enhancementId ? flagshipById[enhancementId] : undefined;
	$: supportsDynamicData =
		enhancementId === 'autonomous-response-playbooks' ||
		enhancementId === 'attack-surface-dashboard' ||
		enhancementId === 'signed-rule-packs';

	$: if (enhancementId && enhancementId !== lastLoadedId) {
		lastLoadedId = enhancementId;
		loadError = null;
		dryRunResult = null;
		verificationResult = null;
		void loadFlagshipData();
	}

	async function loadFlagshipData() {
		if (!supportsDynamicData) return;

		loading = true;
		loadError = null;

		try {
			if (enhancementId === 'autonomous-response-playbooks') {
				playbooks = await api.getAutonomousResponsePlaybooks();
			} else if (enhancementId === 'attack-surface-dashboard') {
				attackSurface = await api.getAttackSurfaceSnapshot();
			} else if (enhancementId === 'signed-rule-packs') {
				rulePackStatus = await api.getSignedRulePackStatus();
			}
		} catch (error) {
			loadError = error instanceof Error ? error.message : 'Failed to load enhancement data';
		} finally {
			loading = false;
		}
	}

	async function runDryRun(playbookId: string) {
		dryRunResult = await api.runAutonomousResponseDryRun(playbookId, 'local-workstation');
	}

	async function refreshAttackSurface() {
		attackSurface = await api.refreshAttackSurfaceSnapshot();
	}

	async function verifyRulePack(packId: string) {
		verificationResult = await api.verifyRulePackSignature(packId);
		rulePackStatus = await api.getSignedRulePackStatus();
	}
</script>

<svelte:head>
	<title>
		{enhancement ? `${enhancement.title} - Flagship` : 'Flagship Item Not Found'} - Cyber Security Prime
	</title>
</svelte:head>

{#if enhancement}
	<div class="space-y-6">
		<div class="flex items-center gap-2">
			<a href="/flagship">
				<Button variant="ghost" size="sm">
					<ArrowLeft class="w-4 h-4 mr-1" />
					Back to Flagship
				</Button>
			</a>
			<Badge variant="outline">{getPillarLabel(enhancement.pillar)}</Badge>
			<Badge variant="success">Wired</Badge>
		</div>

		<Card variant="glass" class="border-primary/30">
			<CardHeader>
				<CardTitle class="text-2xl">{enhancement.title}</CardTitle>
				<p class="text-sm text-muted-foreground">{enhancement.description}</p>
			</CardHeader>
		</Card>

		{#if supportsDynamicData}
			<Card variant="glass">
				<CardHeader>
					<div class="flex items-center justify-between">
						<CardTitle class="text-lg">Live Flagship Data</CardTitle>
						<Button variant="outline" size="sm" on:click={loadFlagshipData} disabled={loading}>
							<RefreshCw class="w-4 h-4 mr-1 {loading ? 'animate-spin' : ''}" />
							Refresh
						</Button>
					</div>
				</CardHeader>
				<CardContent>
					{#if loadError}
						<div class="text-sm text-red-500">{loadError}</div>
					{/if}

					{#if enhancementId === 'autonomous-response-playbooks'}
						<div class="space-y-3">
							{#each playbooks as playbook}
								<div class="rounded-lg border border-border/60 p-3 space-y-2">
									<div class="flex items-center justify-between">
										<div>
											<p class="font-medium">{playbook.name}</p>
											<p class="text-xs text-muted-foreground">{playbook.description}</p>
										</div>
										<Badge variant={playbook.enabled ? 'success' : 'outline'}>
											{playbook.enabled ? 'Enabled' : 'Disabled'}
										</Badge>
									</div>
									<div class="flex flex-wrap gap-2 text-xs text-muted-foreground">
										<span>Trigger score: {playbook.trigger_score}</span>
										<span>Severity: {playbook.severity_threshold}</span>
									</div>
									<div class="flex items-center justify-between">
										<div class="text-xs text-muted-foreground">
											Actions: {playbook.actions.join(', ')}
										</div>
										<Button size="sm" variant="outline" on:click={() => runDryRun(playbook.id)}>
											Dry Run
										</Button>
									</div>
								</div>
							{/each}
						</div>

						{#if dryRunResult}
							<div class="mt-4 rounded-lg border border-neon-green/30 p-3 text-sm">
								<p class="font-medium text-neon-green">Dry run completed</p>
								<p class="text-muted-foreground mt-1">{dryRunResult.recommendation}</p>
							</div>
						{/if}
					{:else if enhancementId === 'attack-surface-dashboard' && attackSurface}
						<div class="space-y-4">
							<div class="grid grid-cols-3 gap-3">
								<div class="rounded-lg border border-border/60 p-3">
									<p class="text-xs text-muted-foreground">Exposure score</p>
									<p class="text-lg font-semibold">{attackSurface.overall_exposure_score}</p>
								</div>
								<div class="rounded-lg border border-border/60 p-3">
									<p class="text-xs text-muted-foreground">Open exposures</p>
									<p class="text-lg font-semibold">{attackSurface.open_exposures}</p>
								</div>
								<div class="rounded-lg border border-border/60 p-3">
									<p class="text-xs text-muted-foreground">Critical</p>
									<p class="text-lg font-semibold text-neon-red">{attackSurface.critical_exposures}</p>
								</div>
							</div>
							<Button variant="outline" size="sm" on:click={refreshAttackSurface}>
								Refresh Snapshot
							</Button>
							<div class="space-y-2">
								{#each attackSurface.items as item}
									<div class="rounded-lg border border-border/60 p-3">
										<div class="flex items-center justify-between">
											<p class="font-medium">{item.asset}</p>
											<Badge variant="outline">{item.severity}</Badge>
										</div>
										<p class="text-xs text-muted-foreground mt-1">{item.recommended_action}</p>
									</div>
								{/each}
							</div>
						</div>
					{:else if enhancementId === 'signed-rule-packs' && rulePackStatus}
						<div class="space-y-3">
							<div class="flex items-center gap-2">
								<Shield class="w-4 h-4 text-cyber-blue" />
								<span class="text-sm">
									Enforcement: {rulePackStatus.enforcement_enabled ? 'Enabled' : 'Disabled'}
								</span>
							</div>
							{#each rulePackStatus.packs as pack}
								<div class="rounded-lg border border-border/60 p-3">
									<div class="flex items-center justify-between">
										<div>
											<p class="font-medium">{pack.name}</p>
											<p class="text-xs text-muted-foreground">
												{pack.version} • {pack.publisher}
											</p>
										</div>
										<Button size="sm" variant="outline" on:click={() => verifyRulePack(pack.id)}>
											<KeyRound class="w-3 h-3 mr-1" />
											Verify
										</Button>
									</div>
								</div>
							{/each}
							{#if verificationResult}
								<div class="rounded-lg border border-neon-green/30 p-3 text-sm">
									{verificationResult.details}
								</div>
							{/if}
						</div>
					{/if}
				</CardContent>
			</Card>
		{/if}

		<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
			<Card variant="glass">
				<CardHeader>
					<CardTitle class="text-lg flex items-center gap-2">
						<ListChecks class="w-5 h-5 text-cyber-blue" />
						Execution Checklist
					</CardTitle>
				</CardHeader>
				<CardContent class="space-y-3 text-sm">
					<div class="flex items-start gap-2">
						<CheckCircle2 class="w-4 h-4 text-neon-green mt-0.5" />
						<span>Product scope locked and linked to official flagship roadmap.</span>
					</div>
					<div class="flex items-start gap-2">
						<CheckCircle2 class="w-4 h-4 text-neon-green mt-0.5" />
						<span>Navigation and route wiring complete for this enhancement track.</span>
					</div>
					<div class="flex items-start gap-2">
						<CheckCircle2 class="w-4 h-4 text-neon-green mt-0.5" />
						<span>Ready for backend capability implementation and test automation.</span>
					</div>
				</CardContent>
			</Card>

			<Card variant="glass">
				<CardHeader>
					<CardTitle class="text-lg flex items-center gap-2">
						<Route class="w-5 h-5 text-cyber-purple" />
						Linked Surface
					</CardTitle>
				</CardHeader>
				<CardContent class="space-y-3">
					<p class="text-sm text-muted-foreground">
						This flagship item can be opened directly through the route below.
					</p>
					<div class="rounded-lg border border-border/60 p-3 font-mono text-xs text-foreground bg-muted/20">
						{enhancement.route}
					</div>
					<div>
						<a href={enhancement.route}>
							<Button variant="outline">Open Enhancement Surface</Button>
						</a>
					</div>
				</CardContent>
			</Card>
		</div>
	</div>
{:else}
	<Card variant="glass">
		<CardHeader>
			<CardTitle>Flagship item not found</CardTitle>
		</CardHeader>
		<CardContent>
			<a href="/flagship">
				<Button variant="outline">Return to Flagship Program</Button>
			</a>
		</CardContent>
	</Card>
{/if}

