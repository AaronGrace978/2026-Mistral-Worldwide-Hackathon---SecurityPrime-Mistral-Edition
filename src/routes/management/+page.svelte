<script lang="ts">
	import { onMount } from 'svelte';
	import { invoke } from '@tauri-apps/api/tauri';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Separator } from '$lib/components/ui/separator';
	import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
	import { Users, Shield, Activity, AlertTriangle, Server, Settings } from 'lucide-svelte';

	interface ManagedInstance {
		id: string;
		name: string;
		endpoint: string;
		status: 'Online' | 'Offline' | 'Maintenance' | 'Error';
		last_heartbeat: string;
		version: string;
		modules: string[];
		config: {
			auto_update: boolean;
			monitoring_enabled: boolean;
			alert_thresholds: {
				cpu_usage: number;
				memory_usage: number;
				disk_usage: number;
				threat_score: number;
			};
			compliance_settings: {
				gdpr_enabled: boolean;
				hipaa_enabled: boolean;
				pci_dss_enabled: boolean;
				auto_reporting: boolean;
			};
		};
	}

	interface User {
		id: string;
		username: string;
		email: string;
		role: 'Admin' | 'Manager' | 'Analyst' | 'Auditor' | 'ReadOnly';
		permissions: string[];
		last_login: string | null;
		created_at: string;
	}

	interface DashboardData {
		total_instances: number;
		online_instances: number;
		total_users: number;
		active_alerts: number;
		recent_audit_entries: number;
		policies_count: number;
	}

	let loading = true;
	let dashboardData: DashboardData | null = null;
	let instances: ManagedInstance[] = [];
	let users: User[] = [];
	let activeTab = 'dashboard';

	async function loadDashboardData() {
		try {
			dashboardData = await invoke('get_management_dashboard_data');
			instances = await invoke('get_managed_instances');
			users = await invoke('get_users');
		} catch (error) {
			console.error('Failed to load dashboard data:', error);
		} finally {
			loading = false;
		}
	}

	function getStatusColor(status: string) {
		switch (status) {
			case 'Online':
				return 'bg-green-500';
			case 'Offline':
				return 'bg-red-500';
			case 'Maintenance':
				return 'bg-yellow-500';
			case 'Error':
				return 'bg-red-600';
			default:
				return 'bg-gray-500';
		}
	}

	function getRoleColor(role: string) {
		switch (role) {
			case 'Admin':
				return 'bg-red-500';
			case 'Manager':
				return 'bg-blue-500';
			case 'Analyst':
				return 'bg-green-500';
			case 'Auditor':
				return 'bg-purple-500';
			case 'ReadOnly':
				return 'bg-gray-500';
			default:
				return 'bg-gray-500';
		}
	}

	onMount(() => {
		loadDashboardData();
	});
</script>

<svelte:head>
	<title>Management Console - Cyber Security Prime</title>
</svelte:head>

<div class="container mx-auto p-6">
	<div class="mb-8">
		<h1 class="text-3xl font-bold mb-2">Enterprise Management Console</h1>
		<p class="text-gray-600 dark:text-gray-400">
			Centralized management for enterprise security deployments
		</p>
	</div>

	{#if loading}
		<LoadingSpinner />
	{:else if dashboardData}
		<!-- Navigation Tabs -->
		<div class="mb-6">
			<div class="flex space-x-1 bg-gray-100 dark:bg-gray-800 p-1 rounded-lg">
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'dashboard' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'dashboard'}
				>
					<Activity class="inline w-4 h-4 mr-2" />
					Dashboard
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'instances' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'instances'}
				>
					<Server class="inline w-4 h-4 mr-2" />
					Instances
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'users' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'users'}
				>
					<Users class="inline w-4 h-4 mr-2" />
					Users
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'policies' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'policies'}
				>
					<Shield class="inline w-4 h-4 mr-2" />
					Policies
				</button>
			</div>
		</div>

		<!-- Dashboard Tab -->
		{#if activeTab === 'dashboard'}
			<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Total Instances</CardTitle>
						<Server class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboardData.total_instances}</div>
						<p class="text-xs text-muted-foreground">
							{dashboardData.online_instances} online
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Active Users</CardTitle>
						<Users class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboardData.total_users}</div>
						<p class="text-xs text-muted-foreground">
							Managed accounts
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Active Alerts</CardTitle>
						<AlertTriangle class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboardData.active_alerts}</div>
						<p class="text-xs text-muted-foreground">
							Require attention
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Security Policies</CardTitle>
						<Shield class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboardData.policies_count}</div>
						<p class="text-xs text-muted-foreground">
							Active policies
						</p>
					</CardContent>
				</Card>
			</div>

			<!-- Recent Activity -->
			<Card>
				<CardHeader>
					<CardTitle>Recent Activity</CardTitle>
				</CardHeader>
				<CardContent>
					<div class="space-y-4">
						<div class="flex items-center">
							<div class="w-2 h-2 bg-green-500 rounded-full mr-3"></div>
							<div class="flex-1">
								<p class="text-sm font-medium">Instance "prod-web-01" came online</p>
								<p class="text-xs text-muted-foreground">2 minutes ago</p>
							</div>
						</div>
						<div class="flex items-center">
							<div class="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
							<div class="flex-1">
								<p class="text-sm font-medium">New user "analyst@example.com" created</p>
								<p class="text-xs text-muted-foreground">15 minutes ago</p>
							</div>
						</div>
						<div class="flex items-center">
							<div class="w-2 h-2 bg-yellow-500 rounded-full mr-3"></div>
							<div class="flex-1">
								<p class="text-sm font-medium">Security policy updated</p>
								<p class="text-xs text-muted-foreground">1 hour ago</p>
							</div>
						</div>
					</div>
				</CardContent>
			</Card>
		{/if}

		<!-- Instances Tab -->
		{#if activeTab === 'instances'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Managed Instances</h2>
					<Button>
						<Server class="w-4 h-4 mr-2" />
						Register Instance
					</Button>
				</div>

				<div class="grid gap-4">
					{#each instances as instance}
						<Card>
							<CardHeader>
								<div class="flex justify-between items-start">
									<div>
										<CardTitle class="flex items-center gap-2">
											{instance.name}
											<div class="w-2 h-2 rounded-full {getStatusColor(instance.status)}"></div>
										</CardTitle>
										<p class="text-sm text-muted-foreground">{instance.endpoint}</p>
									</div>
									<Badge variant="outline">{instance.status}</Badge>
								</div>
							</CardHeader>
							<CardContent>
								<div class="grid grid-cols-2 gap-4 text-sm">
									<div>
										<span class="font-medium">Version:</span> {instance.version}
									</div>
									<div>
										<span class="font-medium">Modules:</span> {instance.modules.length}
									</div>
									<div>
										<span class="font-medium">Last Heartbeat:</span>
										{new Date(instance.last_heartbeat).toLocaleString()}
									</div>
									<div>
										<span class="font-medium">Auto Update:</span>
										{instance.config.auto_update ? 'Enabled' : 'Disabled'}
									</div>
								</div>
								<Separator class="my-4" />
								<div class="flex gap-2">
									<Button variant="outline" size="sm">Configure</Button>
									<Button variant="outline" size="sm">View Logs</Button>
									<Button variant="outline" size="sm" class="text-red-600">Remove</Button>
								</div>
							</CardContent>
						</Card>
					{/each}
				</div>
			</div>
		{/if}

		<!-- Users Tab -->
		{#if activeTab === 'users'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">User Management</h2>
					<Button>
						<Users class="w-4 h-4 mr-2" />
						Add User
					</Button>
				</div>

				<div class="grid gap-4">
					{#each users as user}
						<Card>
							<CardHeader>
								<div class="flex justify-between items-start">
									<div>
										<CardTitle>{user.username}</CardTitle>
										<p class="text-sm text-muted-foreground">{user.email}</p>
									</div>
									<Badge class={getRoleColor(user.role)}>{user.role}</Badge>
								</div>
							</CardHeader>
							<CardContent>
								<div class="grid grid-cols-2 gap-4 text-sm">
									<div>
										<span class="font-medium">Created:</span>
										{new Date(user.created_at).toLocaleDateString()}
									</div>
									<div>
										<span class="font-medium">Last Login:</span>
										{user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}
									</div>
									<div class="col-span-2">
										<span class="font-medium">Permissions:</span>
										<div class="flex flex-wrap gap-1 mt-1">
											{#each user.permissions as permission}
												<Badge variant="secondary" class="text-xs">{permission}</Badge>
											{/each}
										</div>
									</div>
								</div>
								<Separator class="my-4" />
								<div class="flex gap-2">
									<Button variant="outline" size="sm">Edit</Button>
									<Button variant="outline" size="sm">Reset Password</Button>
									<Button variant="outline" size="sm" class="text-red-600">Delete</Button>
								</div>
							</CardContent>
						</Card>
					{/each}
				</div>
			</div>
		{/if}

		<!-- Policies Tab -->
		{#if activeTab === 'policies'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Security Policies</h2>
					<Button>
						<Shield class="w-4 h-4 mr-2" />
						Create Policy
					</Button>
				</div>

				<Card>
					<CardHeader>
						<CardTitle>Password Security Policy</CardTitle>
						<p class="text-sm text-muted-foreground">Enforces strong password requirements</p>
					</CardHeader>
					<CardContent>
						<div class="space-y-2">
							<div class="flex items-center justify-between">
								<span class="text-sm">Minimum password length: 12 characters</span>
								<Badge variant="secondary">High Priority</Badge>
							</div>
							<div class="flex items-center justify-between">
								<span class="text-sm">Require special characters</span>
								<Badge variant="secondary">Medium Priority</Badge>
							</div>
						</div>
						<Separator class="my-4" />
						<div class="flex gap-2">
							<Button variant="outline" size="sm">Edit</Button>
							<Button variant="outline" size="sm">Disable</Button>
						</div>
					</CardContent>
				</Card>

				<Card>
					<CardHeader>
						<CardTitle>Access Control Policy</CardTitle>
						<p class="text-sm text-muted-foreground">Controls user access to sensitive resources</p>
					</CardHeader>
					<CardContent>
						<div class="space-y-2">
							<div class="flex items-center justify-between">
								<span class="text-sm">Admin-only access to critical systems</span>
								<Badge class="bg-red-500">Critical</Badge>
							</div>
							<div class="flex items-center justify-between">
								<span class="text-sm">Multi-factor authentication required</span>
								<Badge variant="secondary">High Priority</Badge>
							</div>
						</div>
						<Separator class="my-4" />
						<div class="flex gap-2">
							<Button variant="outline" size="sm">Edit</Button>
							<Button variant="outline" size="sm">Disable</Button>
						</div>
					</CardContent>
				</Card>
			</div>
		{/if}
	{:else}
		<div class="text-center py-12">
			<p class="text-gray-500 dark:text-gray-400">Unable to load management console data</p>
		</div>
	{/if}
</div>