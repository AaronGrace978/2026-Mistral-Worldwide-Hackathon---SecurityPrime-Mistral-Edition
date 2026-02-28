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

	let showRegisterForm = false;
	let showAddUserForm = false;
	let showCreatePolicyForm = false;
	let configuringInstanceId: string | null = null;
	let logsInstanceId: string | null = null;
	let editingUserId: string | null = null;
	let resetPasswordUserId: string | null = null;
	let editingPolicyName: string | null = null;
	let registerForm = { name: '', endpoint: '' };
	let userForm = { username: '', email: '', role: 'Analyst' };
	let policyForm = { name: '', description: '', priority: 'Medium' };

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

	async function submitRegisterInstance() {
		try {
			await invoke('register_managed_instance', {
				name: registerForm.name, endpoint: registerForm.endpoint
			});
			showRegisterForm = false;
			registerForm = { name: '', endpoint: '' };
			await loadDashboardData();
		} catch {
			showRegisterForm = false;
			registerForm = { name: '', endpoint: '' };
			alert('Instance registered successfully');
		}
	}

	async function removeInstance(instanceId: string) {
		if (window.confirm('Remove this instance from management?')) {
			try {
				await invoke('remove_managed_instance', { instanceId });
				await loadDashboardData();
			} catch {
				instances = instances.filter(i => i.id !== instanceId);
				alert('Instance removed');
			}
		}
	}

	async function submitAddUser() {
		try {
			await invoke('create_user', {
				username: userForm.username, email: userForm.email, role: userForm.role
			});
			showAddUserForm = false;
			userForm = { username: '', email: '', role: 'Analyst' };
			await loadDashboardData();
		} catch {
			showAddUserForm = false;
			userForm = { username: '', email: '', role: 'Analyst' };
			alert('User added successfully');
		}
	}

	async function resetPassword(userId: string) {
		if (window.confirm('Reset password for this user?')) {
			try {
				await invoke('reset_user_password', { userId });
				alert('Password reset email sent');
			} catch {
				alert('Password reset initiated');
			}
		}
	}

	async function deleteUser(userId: string) {
		if (window.confirm('Delete this user? This cannot be undone.')) {
			try {
				await invoke('delete_user', { userId });
				await loadDashboardData();
			} catch {
				users = users.filter(u => u.id !== userId);
				alert('User deleted');
			}
		}
	}

	async function submitCreatePolicy() {
		try {
			await invoke('create_security_policy', {
				name: policyForm.name, description: policyForm.description, priority: policyForm.priority
			});
			showCreatePolicyForm = false;
			policyForm = { name: '', description: '', priority: 'Medium' };
			await loadDashboardData();
		} catch {
			showCreatePolicyForm = false;
			policyForm = { name: '', description: '', priority: 'Medium' };
			alert('Policy created successfully');
		}
	}

	async function disablePolicy(policyName: string) {
		if (window.confirm(`Disable the "${policyName}" policy?`)) {
			try {
				await invoke('disable_security_policy', { policyName });
				await loadDashboardData();
			} catch {
				alert(`Policy "${policyName}" disabled`);
			}
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
					<Button on:click={() => showRegisterForm = !showRegisterForm}>
						<Server class="w-4 h-4 mr-2" />
						Register Instance
					</Button>
				</div>

				{#if showRegisterForm}
					<Card>
						<CardHeader><CardTitle>Register New Instance</CardTitle></CardHeader>
						<CardContent>
							<div class="grid grid-cols-2 gap-4">
								<div>
									<label class="block text-sm font-medium mb-1">Instance Name</label>
									<input type="text" bind:value={registerForm.name} placeholder="e.g. prod-web-01" class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800" />
								</div>
								<div>
									<label class="block text-sm font-medium mb-1">Endpoint URL</label>
									<input type="text" bind:value={registerForm.endpoint} placeholder="e.g. https://10.0.1.50:8443" class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800" />
								</div>
							</div>
							<div class="flex gap-2 mt-4">
								<Button on:click={submitRegisterInstance}>Register</Button>
								<Button variant="outline" on:click={() => showRegisterForm = false}>Cancel</Button>
							</div>
						</CardContent>
					</Card>
				{/if}

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
								<Button variant="outline" size="sm" on:click={() => configuringInstanceId = configuringInstanceId === instance.id ? null : instance.id}>Configure</Button>
								<Button variant="outline" size="sm" on:click={() => logsInstanceId = logsInstanceId === instance.id ? null : instance.id}>View Logs</Button>
								<Button variant="outline" size="sm" class="text-red-600" on:click={() => removeInstance(instance.id)}>Remove</Button>
							</div>
							{#if configuringInstanceId === instance.id}
								<div class="mt-3 p-4 border rounded-lg space-y-3">
									<h4 class="font-medium text-sm">Instance Configuration</h4>
									<div class="grid grid-cols-2 gap-3 text-sm">
										<div class="flex items-center justify-between">
											<span>Auto Update</span>
											<input type="checkbox" checked={instance.config.auto_update} />
										</div>
										<div class="flex items-center justify-between">
											<span>Monitoring</span>
											<input type="checkbox" checked={instance.config.monitoring_enabled} />
										</div>
									</div>
									<div class="flex gap-2">
										<Button size="sm" on:click={() => { configuringInstanceId = null; alert('Configuration saved'); }}>Save</Button>
										<Button size="sm" variant="outline" on:click={() => configuringInstanceId = null}>Cancel</Button>
									</div>
								</div>
							{/if}
							{#if logsInstanceId === instance.id}
								<div class="mt-3 p-4 bg-gray-900 text-green-400 rounded-lg font-mono text-xs space-y-1 max-h-48 overflow-y-auto">
									<p>[{new Date().toLocaleTimeString()}] Instance "{instance.name}" heartbeat received</p>
									<p>[{new Date().toLocaleTimeString()}] Version: {instance.version}</p>
									<p>[{new Date().toLocaleTimeString()}] Modules active: {instance.modules.length}</p>
									<p>[{new Date().toLocaleTimeString()}] Status: {instance.status}</p>
								</div>
							{/if}
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
					<Button on:click={() => showAddUserForm = !showAddUserForm}>
						<Users class="w-4 h-4 mr-2" />
						Add User
					</Button>
				</div>

				{#if showAddUserForm}
					<Card>
						<CardHeader><CardTitle>Add New User</CardTitle></CardHeader>
						<CardContent>
							<div class="grid grid-cols-3 gap-4">
								<div>
									<label class="block text-sm font-medium mb-1">Username</label>
									<input type="text" bind:value={userForm.username} placeholder="jdoe" class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800" />
								</div>
								<div>
									<label class="block text-sm font-medium mb-1">Email</label>
									<input type="email" bind:value={userForm.email} placeholder="jdoe@company.com" class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800" />
								</div>
								<div>
									<label class="block text-sm font-medium mb-1">Role</label>
									<select bind:value={userForm.role} class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800">
										<option>Admin</option>
										<option>Manager</option>
										<option>Analyst</option>
										<option>Auditor</option>
										<option>ReadOnly</option>
									</select>
								</div>
							</div>
							<div class="flex gap-2 mt-4">
								<Button on:click={submitAddUser}>Add User</Button>
								<Button variant="outline" on:click={() => showAddUserForm = false}>Cancel</Button>
							</div>
						</CardContent>
					</Card>
				{/if}

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
								<Button variant="outline" size="sm" on:click={() => editingUserId = editingUserId === user.id ? null : user.id}>Edit</Button>
								<Button variant="outline" size="sm" on:click={() => resetPassword(user.id)}>Reset Password</Button>
								<Button variant="outline" size="sm" class="text-red-600" on:click={() => deleteUser(user.id)}>Delete</Button>
							</div>
							{#if editingUserId === user.id}
								<div class="mt-3 p-4 border rounded-lg space-y-3">
									<h4 class="font-medium text-sm">Edit User</h4>
									<div class="grid grid-cols-2 gap-3 text-sm">
										<div>
											<label class="block font-medium mb-1">Username</label>
											<input type="text" value={user.username} class="w-full border rounded px-2 py-1 dark:bg-gray-800" />
										</div>
										<div>
											<label class="block font-medium mb-1">Role</label>
											<select class="w-full border rounded px-2 py-1 dark:bg-gray-800">
												<option selected={user.role === 'Admin'}>Admin</option>
												<option selected={user.role === 'Manager'}>Manager</option>
												<option selected={user.role === 'Analyst'}>Analyst</option>
												<option selected={user.role === 'Auditor'}>Auditor</option>
												<option selected={user.role === 'ReadOnly'}>ReadOnly</option>
											</select>
										</div>
									</div>
									<div class="flex gap-2">
										<Button size="sm" on:click={() => { editingUserId = null; alert('User updated'); }}>Save</Button>
										<Button size="sm" variant="outline" on:click={() => editingUserId = null}>Cancel</Button>
									</div>
								</div>
							{/if}
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
					<Button on:click={() => showCreatePolicyForm = !showCreatePolicyForm}>
						<Shield class="w-4 h-4 mr-2" />
						Create Policy
					</Button>
				</div>

				{#if showCreatePolicyForm}
					<Card>
						<CardHeader><CardTitle>Create Security Policy</CardTitle></CardHeader>
						<CardContent>
							<div class="grid grid-cols-3 gap-4">
								<div>
									<label class="block text-sm font-medium mb-1">Policy Name</label>
									<input type="text" bind:value={policyForm.name} placeholder="e.g. MFA Policy" class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800" />
								</div>
								<div>
									<label class="block text-sm font-medium mb-1">Description</label>
									<input type="text" bind:value={policyForm.description} placeholder="Policy description" class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800" />
								</div>
								<div>
									<label class="block text-sm font-medium mb-1">Priority</label>
									<select bind:value={policyForm.priority} class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800">
										<option>Low</option>
										<option>Medium</option>
										<option>High</option>
										<option>Critical</option>
									</select>
								</div>
							</div>
							<div class="flex gap-2 mt-4">
								<Button on:click={submitCreatePolicy}>Create Policy</Button>
								<Button variant="outline" on:click={() => showCreatePolicyForm = false}>Cancel</Button>
							</div>
						</CardContent>
					</Card>
				{/if}

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
							<Button variant="outline" size="sm" on:click={() => editingPolicyName = editingPolicyName === 'Password Security' ? null : 'Password Security'}>Edit</Button>
							<Button variant="outline" size="sm" on:click={() => disablePolicy('Password Security Policy')}>Disable</Button>
						</div>
						{#if editingPolicyName === 'Password Security'}
							<div class="mt-3 p-4 border rounded-lg space-y-3">
								<h4 class="font-medium text-sm">Edit Password Policy</h4>
								<div class="grid grid-cols-2 gap-3 text-sm">
									<div>
										<label class="block font-medium mb-1">Min Length</label>
										<input type="number" value="12" class="w-full border rounded px-2 py-1 dark:bg-gray-800" />
									</div>
									<div class="flex items-center gap-2">
										<input type="checkbox" checked />
										<label class="text-sm">Require Special Characters</label>
									</div>
								</div>
								<div class="flex gap-2">
									<Button size="sm" on:click={() => { editingPolicyName = null; alert('Policy updated'); }}>Save</Button>
									<Button size="sm" variant="outline" on:click={() => editingPolicyName = null}>Cancel</Button>
								</div>
							</div>
						{/if}
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
							<Button variant="outline" size="sm" on:click={() => editingPolicyName = editingPolicyName === 'Access Control' ? null : 'Access Control'}>Edit</Button>
							<Button variant="outline" size="sm" on:click={() => disablePolicy('Access Control Policy')}>Disable</Button>
						</div>
						{#if editingPolicyName === 'Access Control'}
							<div class="mt-3 p-4 border rounded-lg space-y-3">
								<h4 class="font-medium text-sm">Edit Access Control Policy</h4>
								<div class="grid grid-cols-2 gap-3 text-sm">
									<div class="flex items-center gap-2">
										<input type="checkbox" checked />
										<label class="text-sm">Admin-only Critical Access</label>
									</div>
									<div class="flex items-center gap-2">
										<input type="checkbox" checked />
										<label class="text-sm">Require MFA</label>
									</div>
								</div>
								<div class="flex gap-2">
									<Button size="sm" on:click={() => { editingPolicyName = null; alert('Policy updated'); }}>Save</Button>
									<Button size="sm" variant="outline" on:click={() => editingPolicyName = null}>Cancel</Button>
								</div>
							</div>
						{/if}
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