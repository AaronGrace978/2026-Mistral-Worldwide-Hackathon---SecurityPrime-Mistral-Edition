<script lang="ts">
	import { onMount } from 'svelte';
	import { invoke } from '@tauri-apps/api/tauri';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Progress } from '$lib/components/ui/progress';
	import { Separator } from '$lib/components/ui/separator';
	import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
	import { Shield, FileText, AlertTriangle, Users, Database, CheckCircle, XCircle, Clock } from 'lucide-svelte';

	interface ComplianceDashboard {
		gdpr_score: number;
		hipaa_score: number;
		total_data_assets: number;
		active_consents: number;
		pending_subject_requests: number;
		open_breaches: number;
		phi_assets: number;
		active_baas: number;
	}

	interface DataAsset {
		id: string;
		name: string;
		category: 'Personal' | 'Sensitive' | 'Health' | 'Financial' | 'Contact' | 'Behavioral' | 'Technical';
		sensitivity: 'Public' | 'Internal' | 'Confidential' | 'Restricted';
		location: string;
		owner: string;
		retention_period: string;
		legal_basis: string;
		data_subjects: string[];
		created_at: string;
		last_updated: string;
	}

	interface BreachIncident {
		id: string;
		title: string;
		description: string;
		affected_subjects: number;
		data_categories: string[];
		breach_date: string;
		discovery_date: string;
		reported_date: string | null;
		severity: 'Low' | 'Medium' | 'High' | 'Critical';
		status: 'Investigating' | 'Contained' | 'Resolved' | 'Closed';
		mitigating_actions: string[];
		regulatory_notifications: any[];
	}

	let loading = true;
	let dashboard: ComplianceDashboard | null = null;
	let dataAssets: DataAsset[] = [];
	let breachIncidents: BreachIncident[] = [];
	let activeTab = 'dashboard';

	async function loadDashboardData() {
		try {
			dashboard = await invoke('get_compliance_dashboard');
			dataAssets = await invoke('get_data_inventory');
			breachIncidents = await invoke('get_breach_incidents');
		} catch (error) {
			console.error('Failed to load compliance data:', error);
		} finally {
			loading = false;
		}
	}

	async function generateReport(framework: 'GDPR' | 'HIPAA') {
		try {
			const report = await invoke('generate_compliance_report', {
				framework: framework.toLowerCase()
			});
			// In a real implementation, this would download the report
			console.log('Generated report:', report);
			alert(`${framework} compliance report generated successfully!`);
		} catch (error) {
			console.error('Failed to generate report:', error);
			alert('Failed to generate compliance report');
		}
	}

	function getSeverityColor(severity: string) {
		switch (severity) {
			case 'Low':
				return 'bg-green-500';
			case 'Medium':
				return 'bg-yellow-500';
			case 'High':
				return 'bg-orange-500';
			case 'Critical':
				return 'bg-red-500';
			default:
				return 'bg-gray-500';
		}
	}

	function getStatusColor(status: string) {
		switch (status) {
			case 'Investigating':
				return 'bg-yellow-500';
			case 'Contained':
				return 'bg-blue-500';
			case 'Resolved':
				return 'bg-green-500';
			case 'Closed':
				return 'bg-gray-500';
			default:
				return 'bg-gray-500';
		}
	}

	function getSensitivityColor(sensitivity: string) {
		switch (sensitivity) {
			case 'Public':
				return 'bg-green-500';
			case 'Internal':
				return 'bg-blue-500';
			case 'Confidential':
				return 'bg-yellow-500';
			case 'Restricted':
				return 'bg-red-500';
			default:
				return 'bg-gray-500';
		}
	}

	onMount(() => {
		loadDashboardData();
	});
</script>

<svelte:head>
	<title>Compliance - Cyber Security Prime</title>
</svelte:head>

<div class="container mx-auto p-6">
	<div class="mb-8">
		<h1 class="text-3xl font-bold mb-2">Compliance Management</h1>
		<p class="text-gray-600 dark:text-gray-400">
			GDPR, HIPAA, and regulatory compliance monitoring and reporting
		</p>
	</div>

	{#if loading}
		<LoadingSpinner />
	{:else if dashboard}
		<!-- Navigation Tabs -->
		<div class="mb-6">
			<div class="flex space-x-1 bg-gray-100 dark:bg-gray-800 p-1 rounded-lg">
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'dashboard' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'dashboard'}
				>
					<Shield class="inline w-4 h-4 mr-2" />
					Dashboard
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'gdpr' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'gdpr'}
				>
					<FileText class="inline w-4 h-4 mr-2" />
					GDPR
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'hipaa' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'hipaa'}
				>
					<Database class="inline w-4 h-4 mr-2" />
					HIPAA
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'breaches' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'breaches'}
				>
					<AlertTriangle class="inline w-4 h-4 mr-2" />
					Breaches
				</button>
			</div>
		</div>

		<!-- Dashboard Tab -->
		{#if activeTab === 'dashboard'}
			<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">GDPR Compliance</CardTitle>
						<Shield class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.gdpr_score.toFixed(1)}%</div>
						<Progress value={dashboard.gdpr_score} class="mt-2" />
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">HIPAA Compliance</CardTitle>
						<Database class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.hipaa_score.toFixed(1)}%</div>
						<Progress value={dashboard.hipaa_score} class="mt-2" />
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Data Assets</CardTitle>
						<FileText class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.total_data_assets}</div>
						<p class="text-xs text-muted-foreground">
							Tracked in inventory
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Active Consents</CardTitle>
						<CheckCircle class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.active_consents}</div>
						<p class="text-xs text-muted-foreground">
							User consents granted
						</p>
					</CardContent>
				</Card>
			</div>

			<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">PHI Assets</CardTitle>
						<Database class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.phi_assets}</div>
						<p class="text-xs text-muted-foreground">
							Protected health info
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Active BAAs</CardTitle>
						<FileText class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.active_baas}</div>
						<p class="text-xs text-muted-foreground">
							Business associate agreements
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Pending Requests</CardTitle>
						<Clock class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.pending_subject_requests}</div>
						<p class="text-xs text-muted-foreground">
							Subject rights requests
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Open Breaches</CardTitle>
						<AlertTriangle class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.open_breaches}</div>
						<p class="text-xs text-muted-foreground">
							Require attention
						</p>
					</CardContent>
				</Card>
			</div>

			<!-- Quick Actions -->
			<Card>
				<CardHeader>
					<CardTitle>Compliance Actions</CardTitle>
				</CardHeader>
				<CardContent>
					<div class="flex gap-4">
						<Button on:click={() => generateReport('GDPR')}>
							<FileText class="w-4 h-4 mr-2" />
							Generate GDPR Report
						</Button>
						<Button on:click={() => generateReport('HIPAA')}>
							<Database class="w-4 h-4 mr-2" />
							Generate HIPAA Report
						</Button>
						<Button variant="outline">
							<AlertTriangle class="w-4 h-4 mr-2" />
							Report Breach
						</Button>
						<Button variant="outline">
							<Users class="w-4 h-4 mr-2" />
							Manage Consents
						</Button>
					</div>
				</CardContent>
			</Card>
		{/if}

		<!-- GDPR Tab -->
		{#if activeTab === 'gdpr'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">GDPR Compliance</h2>
					<Button on:click={() => generateReport('GDPR')}>
						<FileText class="w-4 h-4 mr-2" />
						Generate Report
					</Button>
				</div>

				<!-- Data Inventory -->
				<Card>
					<CardHeader>
						<CardTitle>Data Inventory</CardTitle>
						<p class="text-sm text-muted-foreground">Personal data assets and their classification</p>
					</CardHeader>
					<CardContent>
						<div class="space-y-4">
							{#each dataAssets as asset}
								<div class="flex items-center justify-between p-4 border rounded-lg">
									<div class="flex-1">
										<div class="flex items-center gap-2 mb-1">
											<h4 class="font-medium">{asset.name}</h4>
											<Badge class={getSensitivityColor(asset.sensitivity)}>{asset.sensitivity}</Badge>
											<Badge variant="outline">{asset.category}</Badge>
										</div>
										<p class="text-sm text-muted-foreground">
											Owner: {asset.owner} | Location: {asset.location} | Retention: {asset.retention_period}
										</p>
									</div>
									<Button variant="outline" size="sm">View Details</Button>
								</div>
							{/each}
						</div>
					</CardContent>
				</Card>

				<!-- Subject Rights Requests -->
				<Card>
					<CardHeader>
						<CardTitle>Subject Rights Requests</CardTitle>
						<p class="text-sm text-muted-foreground">GDPR subject rights requests management</p>
					</CardHeader>
					<CardContent>
						<div class="text-center py-8 text-muted-foreground">
							<Users class="w-12 h-12 mx-auto mb-4 opacity-50" />
							<p>No subject rights requests at this time</p>
							<Button class="mt-4" variant="outline">
								<Users class="w-4 h-4 mr-2" />
								Manage Requests
							</Button>
						</div>
					</CardContent>
				</Card>
			</div>
		{/if}

		<!-- HIPAA Tab -->
		{#if activeTab === 'hipaa'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">HIPAA Compliance</h2>
					<Button on:click={() => generateReport('HIPAA')}>
						<Database class="w-4 h-4 mr-2" />
						Generate Report
					</Button>
				</div>

				<Card>
					<CardHeader>
						<CardTitle>Protected Health Information (PHI)</CardTitle>
						<p class="text-sm text-muted-foreground">PHI assets and security controls</p>
					</CardHeader>
					<CardContent>
						<div class="text-center py-8 text-muted-foreground">
							<Database class="w-12 h-12 mx-auto mb-4 opacity-50" />
							<p>No PHI assets registered</p>
							<Button class="mt-4" variant="outline">
								<Database class="w-4 h-4 mr-2" />
								Register PHI Asset
							</Button>
						</div>
					</CardContent>
				</Card>

				<Card>
					<CardHeader>
						<CardTitle>Business Associate Agreements</CardTitle>
						<p class="text-sm text-muted-foreground">BAAs with third-party service providers</p>
					</CardHeader>
					<CardContent>
						<div class="text-center py-8 text-muted-foreground">
							<FileText class="w-12 h-12 mx-auto mb-4 opacity-50" />
							<p>No business associate agreements</p>
							<Button class="mt-4" variant="outline">
								<FileText class="w-4 h-4 mr-2" />
								Add BAA
							</Button>
						</div>
					</CardContent>
				</Card>
			</div>
		{/if}

		<!-- Breaches Tab -->
		{#if activeTab === 'breaches'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Breach Incidents</h2>
					<Button>
						<AlertTriangle class="w-4 h-4 mr-2" />
						Report New Breach
					</Button>
				</div>

				<div class="grid gap-4">
					{#each breachIncidents as breach}
						<Card>
							<CardHeader>
								<div class="flex justify-between items-start">
									<div>
										<CardTitle class="flex items-center gap-2">
											{breach.title}
											<div class="w-2 h-2 rounded-full {getSeverityColor(breach.severity)}"></div>
										</CardTitle>
										<p class="text-sm text-muted-foreground">{breach.description}</p>
									</div>
									<div class="flex gap-2">
										<Badge class={getSeverityColor(breach.severity)}>{breach.severity}</Badge>
										<Badge class={getStatusColor(breach.status)}>{breach.status}</Badge>
									</div>
								</div>
							</CardHeader>
							<CardContent>
								<div class="grid grid-cols-2 gap-4 text-sm">
									<div>
										<span class="font-medium">Affected Subjects:</span> {breach.affected_subjects}
									</div>
									<div>
										<span class="font-medium">Breach Date:</span>
										{new Date(breach.breach_date).toLocaleDateString()}
									</div>
									<div>
										<span class="font-medium">Discovery Date:</span>
										{new Date(breach.discovery_date).toLocaleDateString()}
									</div>
									<div>
										<span class="font-medium">Reported:</span>
										{breach.reported_date ? new Date(breach.reported_date).toLocaleDateString() : 'Not yet'}
									</div>
								</div>
								<Separator class="my-4" />
								<div class="flex gap-2">
									<Button variant="outline" size="sm">View Details</Button>
									<Button variant="outline" size="sm">Update Status</Button>
									<Button variant="outline" size="sm" class="text-red-600">Escalate</Button>
								</div>
							</CardContent>
						</Card>
					{/each}

					{#if breachIncidents.length === 0}
						<Card>
							<CardContent class="text-center py-12">
								<CheckCircle class="w-12 h-12 mx-auto mb-4 text-green-500" />
								<h3 class="text-lg font-medium mb-2">No Breach Incidents</h3>
								<p class="text-muted-foreground">
									No security breaches have been reported. Your organization is in good standing.
								</p>
							</CardContent>
						</Card>
					{/if}
				</div>
			</div>
		{/if}
	{:else}
		<div class="text-center py-12">
			<p class="text-gray-500 dark:text-gray-400">Unable to load compliance data</p>
		</div>
	{/if}
</div>