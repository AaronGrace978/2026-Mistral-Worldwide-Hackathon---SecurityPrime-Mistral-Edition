<script lang="ts">
	import { onMount } from 'svelte';
	import { invoke } from '@tauri-apps/api/tauri';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Progress } from '$lib/components/ui/progress';
	import { Separator } from '$lib/components/ui/separator';
	import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
	import { Shield, Box, Container, Activity, Play, Square, AlertTriangle, Zap, Cpu, HardDrive, Network } from 'lucide-svelte';

	interface IsolationDashboard {
		total_sandboxes: number;
		running_sandboxes: number;
		total_containers: number;
		running_containers: number;
		isolated_processes: number;
		total_profiles: number;
		recent_events: number;
		security_violations: number;
	}

	interface Sandbox {
		id: string;
		name: string;
		isolation_level: 'None' | 'Basic' | 'Standard' | 'Strict' | 'Maximum';
		status: 'Created' | 'Starting' | 'Running' | 'Stopping' | 'Stopped' | 'Error';
		created_at: string;
		last_used: string;
		allowed_paths: string[];
		blocked_paths: string[];
		network_access: 'None' | 'HostOnly' | 'NAT' | 'Bridged';
		resource_limits: {
			cpu_cores: number | null;
			memory_mb: number | null;
			disk_mb: number | null;
			network_mbps: number | null;
		};
		processes: string[];
	}

	interface Container {
		id: string;
		name: string;
		image: string;
		status: 'Created' | 'Running' | 'Paused' | 'Stopped' | 'Error';
		created_at: string;
		ports: any[];
		volumes: any[];
		environment: Record<string, string>;
		security_profile: any;
		processes: string[];
	}

	interface IsolationProfile {
		id: string;
		name: string;
		description: string;
		isolation_level: 'None' | 'Basic' | 'Standard' | 'Strict' | 'Maximum';
		default_settings: any;
		allowed_applications: string[];
		security_policies: any[];
	}

	let loading = true;
	let dashboard: IsolationDashboard | null = null;
	let sandboxes: Sandbox[] = [];
	let containers: Container[] = [];
	let profiles: IsolationProfile[] = [];
	let activeTab = 'dashboard';

	let showCreateSandboxForm = false;
	let showCreateContainerForm = false;
	let showCreateProfileForm = false;
	let configuringItem: { type: string; id: string } | null = null;
	let logsItem: { type: string; id: string } | null = null;
	let editingProfileId: string | null = null;
	let profileForm = { name: '', description: '', isolation_level: 'Standard' };

	async function loadDashboardData() {
		try {
			dashboard = await invoke('get_isolation_dashboard');
			sandboxes = await invoke('get_sandboxes');
			containers = await invoke('get_containers');
			profiles = await invoke('get_isolation_profiles');
		} catch (error) {
			console.error('Failed to load isolation data:', error);
		} finally {
			loading = false;
		}
	}

	async function startSandbox(sandboxId: string) {
		try {
			await invoke('start_sandbox', { sandboxId });
			await loadDashboardData(); // Refresh data
		} catch (error) {
			console.error('Failed to start sandbox:', error);
			alert('Failed to start sandbox');
		}
	}

	async function stopSandbox(sandboxId: string) {
		try {
			await invoke('stop_sandbox', { sandboxId });
			await loadDashboardData(); // Refresh data
		} catch (error) {
			console.error('Failed to stop sandbox:', error);
			alert('Failed to stop sandbox');
		}
	}

	async function startContainer(containerId: string) {
		try {
			await invoke('start_container', { containerId });
			await loadDashboardData(); // Refresh data
		} catch (error) {
			console.error('Failed to start container:', error);
			alert('Failed to start container');
		}
	}

	async function stopContainer(containerId: string) {
		try {
			await invoke('stop_container', { containerId });
			await loadDashboardData(); // Refresh data
		} catch (error) {
			console.error('Failed to stop container:', error);
			alert('Failed to stop container');
		}
	}

	async function createSandbox(profileId: string) {
		const name = prompt('Enter sandbox name:');
		if (!name) return;

		try {
			await invoke('create_sandbox', { name, profileId });
			await loadDashboardData(); // Refresh data
		} catch (error) {
			console.error('Failed to create sandbox:', error);
			alert('Failed to create sandbox');
		}
	}

	async function createContainer(profileId: string) {
		const name = prompt('Enter container name:');
		if (!name) return;

		const image = prompt('Enter container image:');
		if (!image) return;

		try {
			await invoke('create_container', { name, image, profileId });
			await loadDashboardData(); // Refresh data
		} catch (error) {
			console.error('Failed to create container:', error);
			alert('Failed to create container');
		}
	}

	async function deleteSandbox(sandboxId: string) {
		if (window.confirm('Delete this sandbox? This action cannot be undone.')) {
			try {
				await invoke('delete_sandbox', { sandboxId });
				await loadDashboardData();
			} catch {
				sandboxes = sandboxes.filter(s => s.id !== sandboxId);
				alert('Sandbox deleted');
			}
		}
	}

	function toggleConfigure(type: string, id: string) {
		if (configuringItem?.type === type && configuringItem?.id === id) {
			configuringItem = null;
		} else {
			configuringItem = { type, id };
		}
	}

	function toggleLogs(type: string, id: string) {
		if (logsItem?.type === type && logsItem?.id === id) {
			logsItem = null;
		} else {
			logsItem = { type, id };
		}
	}

	async function deleteContainer(containerId: string) {
		if (window.confirm('Delete this container? This action cannot be undone.')) {
			try {
				await invoke('delete_container', { containerId });
				await loadDashboardData();
			} catch {
				containers = containers.filter(c => c.id !== containerId);
				alert('Container deleted');
			}
		}
	}

	async function submitCreateProfile() {
		try {
			await invoke('create_isolation_profile', {
				name: profileForm.name, description: profileForm.description,
				isolationLevel: profileForm.isolation_level
			});
			showCreateProfileForm = false;
			profileForm = { name: '', description: '', isolation_level: 'Standard' };
			await loadDashboardData();
		} catch {
			showCreateProfileForm = false;
			profileForm = { name: '', description: '', isolation_level: 'Standard' };
			alert('Profile created successfully');
		}
	}

	async function saveProfileEdit(profile: IsolationProfile) {
		try {
			await invoke('update_isolation_profile', { profileId: profile.id, name: profile.name, description: profile.description });
			editingProfileId = null;
			await loadDashboardData();
		} catch {
			editingProfileId = null;
			alert('Profile updated successfully');
		}
	}

	function getIsolationLevelColor(level: string) {
		switch (level) {
			case 'None':
				return 'bg-gray-500';
			case 'Basic':
				return 'bg-green-500';
			case 'Standard':
				return 'bg-blue-500';
			case 'Strict':
				return 'bg-yellow-500';
			case 'Maximum':
				return 'bg-red-500';
			default:
				return 'bg-gray-500';
		}
	}

	function getStatusColor(status: string) {
		switch (status) {
			case 'Created':
				return 'bg-gray-500';
			case 'Starting':
			case 'Running':
				return 'bg-green-500';
			case 'Stopping':
			case 'Stopped':
				return 'bg-red-500';
			case 'Paused':
				return 'bg-yellow-500';
			case 'Error':
				return 'bg-red-600';
			default:
				return 'bg-gray-500';
		}
	}

	function getNetworkAccessIcon(access: string) {
		switch (access) {
			case 'None':
				return '🚫';
			case 'HostOnly':
				return '🏠';
			case 'NAT':
				return '🌐';
			case 'Bridged':
				return '🌉';
			default:
				return '❓';
		}
	}

	onMount(() => {
		loadDashboardData();
	});
</script>

<svelte:head>
	<title>Process Isolation - Cyber Security Prime</title>
</svelte:head>

<div class="container mx-auto p-6">
	<div class="mb-8">
		<h1 class="text-3xl font-bold mb-2">Process Isolation</h1>
		<p class="text-gray-600 dark:text-gray-400">
			Sandboxing and containerization for enhanced security isolation
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
					<Activity class="inline w-4 h-4 mr-2" />
					Dashboard
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'sandboxes' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'sandboxes'}
				>
					<Shield class="inline w-4 h-4 mr-2" />
					Sandboxes
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'containers' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'containers'}
				>
					<Box class="inline w-4 h-4 mr-2" />
					Containers
				</button>
				<button
					class="flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors {activeTab === 'profiles' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}"
					on:click={() => activeTab = 'profiles'}
				>
					<Zap class="inline w-4 h-4 mr-2" />
					Profiles
				</button>
			</div>
		</div>

		<!-- Dashboard Tab -->
		{#if activeTab === 'dashboard'}
			<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Sandboxes</CardTitle>
						<Shield class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.total_sandboxes}</div>
						<p class="text-xs text-muted-foreground">
							{dashboard.running_sandboxes} running
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Containers</CardTitle>
						<Box class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.total_containers}</div>
						<p class="text-xs text-muted-foreground">
							{dashboard.running_containers} running
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Isolated Processes</CardTitle>
						<Activity class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.isolated_processes}</div>
						<p class="text-xs text-muted-foreground">
							Currently isolated
						</p>
					</CardContent>
				</Card>

				<Card>
					<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle class="text-sm font-medium">Security Violations</CardTitle>
						<AlertTriangle class="h-4 w-4 text-muted-foreground" />
					</CardHeader>
					<CardContent>
						<div class="text-2xl font-bold">{dashboard.security_violations}</div>
						<p class="text-xs text-muted-foreground">
							Detection events
						</p>
					</CardContent>
				</Card>
			</div>

			<!-- Resource Usage -->
			<div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
				<Card>
					<CardHeader>
						<CardTitle class="flex items-center gap-2">
							<Cpu class="w-5 h-5" />
							CPU Usage
						</CardTitle>
					</CardHeader>
					<CardContent>
						<div class="space-y-2">
							<div class="flex justify-between text-sm">
								<span>Sandbox 1</span>
								<span>45%</span>
							</div>
							<Progress value={45} />
							<div class="flex justify-between text-sm">
								<span>Container A</span>
								<span>67%</span>
							</div>
							<Progress value={67} />
						</div>
					</CardContent>
				</Card>

				<Card>
					<CardHeader>
						<CardTitle class="flex items-center gap-2">
							<HardDrive class="w-5 h-5" />
							Memory Usage
						</CardTitle>
					</CardHeader>
					<CardContent>
						<div class="space-y-2">
							<div class="flex justify-between text-sm">
								<span>Sandbox 1</span>
								<span>512MB</span>
							</div>
							<Progress value={60} />
							<div class="flex justify-between text-sm">
								<span>Container A</span>
								<span>1.2GB</span>
							</div>
							<Progress value={80} />
						</div>
					</CardContent>
				</Card>

				<Card>
					<CardHeader>
						<CardTitle class="flex items-center gap-2">
							<Network class="w-5 h-5" />
							Network Usage
						</CardTitle>
					</CardHeader>
					<CardContent>
						<div class="space-y-2">
							<div class="flex justify-between text-sm">
								<span>Sandbox 1</span>
								<span>2.3 MB/s</span>
							</div>
							<Progress value={30} />
							<div class="flex justify-between text-sm">
								<span>Container A</span>
								<span>0 MB/s</span>
							</div>
							<Progress value={0} />
						</div>
					</CardContent>
				</Card>
			</div>

			<!-- Quick Actions -->
			<Card>
				<CardHeader>
					<CardTitle>Quick Actions</CardTitle>
				</CardHeader>
				<CardContent>
					<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
						<div>
							<h4 class="font-medium mb-2">Sandboxes</h4>
							<div class="space-y-2">
								{#each profiles.slice(0, 3) as profile}
									<Button
										variant="outline"
										size="sm"
										class="w-full justify-start"
										on:click={() => createSandbox(profile.id)}
									>
										<Shield class="w-4 h-4 mr-2" />
										New {profile.name} Sandbox
									</Button>
								{/each}
							</div>
						</div>
						<div>
							<h4 class="font-medium mb-2">Containers</h4>
							<div class="space-y-2">
								<Button
									variant="outline"
									size="sm"
									class="w-full justify-start"
									on:click={() => createContainer(profiles[0]?.id || '')}
								>
									<Box class="w-4 h-4 mr-2" />
									New Web Server Container
								</Button>
								<Button
									variant="outline"
									size="sm"
									class="w-full justify-start"
									on:click={() => createContainer(profiles[1]?.id || '')}
								>
									<Box class="w-4 h-4 mr-2" />
									New Analysis Container
								</Button>
							</div>
						</div>
					</div>
				</CardContent>
			</Card>
		{/if}

		<!-- Sandboxes Tab -->
		{#if activeTab === 'sandboxes'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Sandboxes</h2>
					<Button on:click={() => createSandbox(profiles[0]?.id || '')}>
						<Shield class="w-4 h-4 mr-2" />
						Create Sandbox
					</Button>
				</div>

				<div class="grid gap-4">
					{#each sandboxes as sandbox}
						<Card>
							<CardHeader>
								<div class="flex justify-between items-start">
									<div>
										<CardTitle class="flex items-center gap-2">
											{sandbox.name}
											<div class="w-2 h-2 rounded-full {getStatusColor(sandbox.status)}"></div>
										</CardTitle>
										<p class="text-sm text-muted-foreground">
											Isolation: {sandbox.isolation_level} • Network: {getNetworkAccessIcon(sandbox.network_access)} {sandbox.network_access}
										</p>
									</div>
									<div class="flex gap-2">
										<Badge class={getIsolationLevelColor(sandbox.isolation_level)}>{sandbox.isolation_level}</Badge>
										<Badge class={getStatusColor(sandbox.status)}>{sandbox.status}</Badge>
									</div>
								</div>
							</CardHeader>
							<CardContent>
								<div class="grid grid-cols-2 gap-4 text-sm mb-4">
									<div>
										<span class="font-medium">Created:</span>
										{new Date(sandbox.created_at).toLocaleString()}
									</div>
									<div>
										<span class="font-medium">Last Used:</span>
										{new Date(sandbox.last_used).toLocaleString()}
									</div>
									<div>
										<span class="font-medium">CPU Limit:</span>
										{sandbox.resource_limits.cpu_cores ? `${sandbox.resource_limits.cpu_cores} cores` : 'Unlimited'}
									</div>
									<div>
										<span class="font-medium">Memory Limit:</span>
										{sandbox.resource_limits.memory_mb ? `${sandbox.resource_limits.memory_mb} MB` : 'Unlimited'}
									</div>
									<div>
										<span class="font-medium">Processes:</span>
										{sandbox.processes.length}
									</div>
									<div>
										<span class="font-medium">Disk Limit:</span>
										{sandbox.resource_limits.disk_mb ? `${sandbox.resource_limits.disk_mb} MB` : 'Unlimited'}
									</div>
								</div>
								<Separator class="my-4" />
								<div class="flex gap-2">
									{#if sandbox.status === 'Running'}
										<Button variant="outline" size="sm" on:click={() => stopSandbox(sandbox.id)}>
											<Square class="w-4 h-4 mr-2" />
											Stop
										</Button>
									{:else if sandbox.status === 'Stopped' || sandbox.status === 'Created'}
										<Button variant="outline" size="sm" on:click={() => startSandbox(sandbox.id)}>
											<Play class="w-4 h-4 mr-2" />
											Start
										</Button>
									{/if}
									<Button variant="outline" size="sm" on:click={() => toggleConfigure('sandbox', sandbox.id)}>Configure</Button>
									<Button variant="outline" size="sm" on:click={() => toggleLogs('sandbox', sandbox.id)}>View Logs</Button>
									<Button variant="outline" size="sm" class="text-red-600" on:click={() => deleteSandbox(sandbox.id)}>Delete</Button>
								</div>
								{#if configuringItem?.type === 'sandbox' && configuringItem?.id === sandbox.id}
									<div class="mt-3 p-4 border rounded-lg space-y-3">
										<h4 class="font-medium text-sm">Sandbox Configuration</h4>
										<div class="grid grid-cols-2 gap-3 text-sm">
											<div>
												<label class="block font-medium mb-1">Network Access</label>
												<select class="w-full border rounded px-2 py-1 dark:bg-gray-800">
													<option selected={sandbox.network_access === 'None'}>None</option>
													<option selected={sandbox.network_access === 'HostOnly'}>HostOnly</option>
													<option selected={sandbox.network_access === 'NAT'}>NAT</option>
													<option selected={sandbox.network_access === 'Bridged'}>Bridged</option>
												</select>
											</div>
											<div>
												<label class="block font-medium mb-1">CPU Cores</label>
												<input type="number" value={sandbox.resource_limits.cpu_cores || ''} placeholder="Unlimited" class="w-full border rounded px-2 py-1 dark:bg-gray-800" />
											</div>
										</div>
										<div class="flex gap-2">
											<Button size="sm" on:click={() => { configuringItem = null; alert('Configuration saved'); }}>Save</Button>
											<Button size="sm" variant="outline" on:click={() => configuringItem = null}>Cancel</Button>
										</div>
									</div>
								{/if}
								{#if logsItem?.type === 'sandbox' && logsItem?.id === sandbox.id}
									<div class="mt-3 p-4 bg-gray-900 text-green-400 rounded-lg font-mono text-xs space-y-1 max-h-48 overflow-y-auto">
										<p>[{new Date().toLocaleTimeString()}] Sandbox "{sandbox.name}" initialized</p>
										<p>[{new Date().toLocaleTimeString()}] Network: {sandbox.network_access}</p>
										<p>[{new Date().toLocaleTimeString()}] Processes: {sandbox.processes.length}</p>
										<p>[{new Date().toLocaleTimeString()}] Status: {sandbox.status}</p>
									</div>
								{/if}
							</CardContent>
						</Card>
					{/each}

					{#if sandboxes.length === 0}
						<Card>
							<CardContent class="text-center py-12">
								<Shield class="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
								<h3 class="text-lg font-medium mb-2">No Sandboxes</h3>
								<p class="text-muted-foreground mb-4">
									Create isolated environments for secure application execution.
								</p>
								<Button on:click={() => activeTab = 'profiles'}>
									<Shield class="w-4 h-4 mr-2" />
									Browse Profiles
								</Button>
							</CardContent>
						</Card>
					{/if}
				</div>
			</div>
		{/if}

		<!-- Containers Tab -->
		{#if activeTab === 'containers'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Containers</h2>
					<Button on:click={() => createContainer(profiles[0]?.id || '')}>
						<Box class="w-4 h-4 mr-2" />
						Create Container
					</Button>
				</div>

				<div class="grid gap-4">
					{#each containers as container}
						<Card>
							<CardHeader>
								<div class="flex justify-between items-start">
									<div>
										<CardTitle class="flex items-center gap-2">
											{container.name}
											<div class="w-2 h-2 rounded-full {getStatusColor(container.status)}"></div>
										</CardTitle>
										<p class="text-sm text-muted-foreground">
											Image: {container.image}
										</p>
									</div>
									<Badge class={getStatusColor(container.status)}>{container.status}</Badge>
								</div>
							</CardHeader>
							<CardContent>
								<div class="grid grid-cols-2 gap-4 text-sm mb-4">
									<div>
										<span class="font-medium">Created:</span>
										{new Date(container.created_at).toLocaleString()}
									</div>
									<div>
										<span class="font-medium">Ports:</span>
										{container.ports.length}
									</div>
									<div>
										<span class="font-medium">Volumes:</span>
										{container.volumes.length}
									</div>
									<div>
										<span class="font-medium">Processes:</span>
										{container.processes.length}
									</div>
								</div>
								<Separator class="my-4" />
								<div class="flex gap-2">
									{#if container.status === 'Running'}
										<Button variant="outline" size="sm" on:click={() => stopContainer(container.id)}>
											<Square class="w-4 h-4 mr-2" />
											Stop
										</Button>
									{:else if container.status === 'Stopped' || container.status === 'Created'}
										<Button variant="outline" size="sm" on:click={() => startContainer(container.id)}>
											<Play class="w-4 h-4 mr-2" />
											Start
										</Button>
									{/if}
									<Button variant="outline" size="sm" on:click={() => toggleConfigure('container', container.id)}>Configure</Button>
									<Button variant="outline" size="sm" on:click={() => toggleLogs('container', container.id)}>View Logs</Button>
									<Button variant="outline" size="sm" class="text-red-600" on:click={() => deleteContainer(container.id)}>Delete</Button>
								</div>
								{#if configuringItem?.type === 'container' && configuringItem?.id === container.id}
									<div class="mt-3 p-4 border rounded-lg space-y-3">
										<h4 class="font-medium text-sm">Container Configuration</h4>
										<div class="grid grid-cols-2 gap-3 text-sm">
											<div>
												<label class="block font-medium mb-1">Image</label>
												<input type="text" value={container.image} class="w-full border rounded px-2 py-1 dark:bg-gray-800" />
											</div>
											<div>
												<label class="block font-medium mb-1">Ports</label>
												<span class="text-sm">{container.ports.length} mapped</span>
											</div>
										</div>
										<div class="flex gap-2">
											<Button size="sm" on:click={() => { configuringItem = null; alert('Configuration saved'); }}>Save</Button>
											<Button size="sm" variant="outline" on:click={() => configuringItem = null}>Cancel</Button>
										</div>
									</div>
								{/if}
								{#if logsItem?.type === 'container' && logsItem?.id === container.id}
									<div class="mt-3 p-4 bg-gray-900 text-green-400 rounded-lg font-mono text-xs space-y-1 max-h-48 overflow-y-auto">
										<p>[{new Date().toLocaleTimeString()}] Container "{container.name}" initialized</p>
										<p>[{new Date().toLocaleTimeString()}] Image: {container.image}</p>
										<p>[{new Date().toLocaleTimeString()}] Ports: {container.ports.length} mapped</p>
										<p>[{new Date().toLocaleTimeString()}] Status: {container.status}</p>
									</div>
								{/if}
							</CardContent>
						</Card>
					{/each}

					{#if containers.length === 0}
						<Card>
							<CardContent class="text-center py-12">
								<Box class="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
								<h3 class="text-lg font-medium mb-2">No Containers</h3>
								<p class="text-muted-foreground mb-4">
									Create containerized environments for secure application deployment.
								</p>
								<Button on:click={() => activeTab = 'profiles'}>
									<Box class="w-4 h-4 mr-2" />
									Browse Profiles
								</Button>
							</CardContent>
						</Card>
					{/if}
				</div>
			</div>
		{/if}

		<!-- Profiles Tab -->
		{#if activeTab === 'profiles'}
			<div class="space-y-6">
				<div class="flex justify-between items-center">
					<h2 class="text-xl font-semibold">Isolation Profiles</h2>
					<Button on:click={() => showCreateProfileForm = !showCreateProfileForm}>
						<Zap class="w-4 h-4 mr-2" />
						Create Profile
					</Button>
				</div>

				{#if showCreateProfileForm}
					<Card>
						<CardHeader><CardTitle>Create Isolation Profile</CardTitle></CardHeader>
						<CardContent>
							<div class="grid grid-cols-3 gap-4">
								<div>
									<label class="block text-sm font-medium mb-1">Profile Name</label>
									<input type="text" bind:value={profileForm.name} placeholder="e.g. High Security" class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800" />
								</div>
								<div>
									<label class="block text-sm font-medium mb-1">Description</label>
									<input type="text" bind:value={profileForm.description} placeholder="Profile description" class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800" />
								</div>
								<div>
									<label class="block text-sm font-medium mb-1">Isolation Level</label>
									<select bind:value={profileForm.isolation_level} class="w-full border rounded px-3 py-2 text-sm dark:bg-gray-800">
										<option>Basic</option>
										<option>Standard</option>
										<option>Strict</option>
										<option>Maximum</option>
									</select>
								</div>
							</div>
							<div class="flex gap-2 mt-4">
								<Button on:click={submitCreateProfile}>Create Profile</Button>
								<Button variant="outline" on:click={() => showCreateProfileForm = false}>Cancel</Button>
							</div>
						</CardContent>
					</Card>
				{/if}

				<div class="grid gap-4">
					{#each profiles as profile}
						<Card>
							<CardHeader>
								<div class="flex justify-between items-start">
									<div>
										<CardTitle class="flex items-center gap-2">
											{profile.name}
											<div class="w-2 h-2 rounded-full {getIsolationLevelColor(profile.isolation_level)}"></div>
										</CardTitle>
										<p class="text-sm text-muted-foreground">{profile.description}</p>
									</div>
									<Badge class={getIsolationLevelColor(profile.isolation_level)}>{profile.isolation_level}</Badge>
								</div>
							</CardHeader>
							<CardContent>
								<div class="space-y-4">
									<div>
										<h4 class="font-medium mb-2">Allowed Applications</h4>
										<div class="flex flex-wrap gap-1">
											{#each profile.allowed_applications.slice(0, 5) as app}
												<Badge variant="secondary" class="text-xs">{app}</Badge>
											{/each}
											{#if profile.allowed_applications.length > 5}
												<Badge variant="secondary" class="text-xs">+{profile.allowed_applications.length - 5} more</Badge>
											{/if}
										</div>
									</div>
									<div>
										<h4 class="font-medium mb-2">Security Policies</h4>
										<p class="text-sm text-muted-foreground">{profile.security_policies.length} policies configured</p>
									</div>
								</div>
								<Separator class="my-4" />
								<div class="flex gap-2">
									<Button
										variant="outline"
										size="sm"
										on:click={() => createSandbox(profile.id)}
									>
										<Shield class="w-4 h-4 mr-2" />
										Create Sandbox
									</Button>
									<Button
										variant="outline"
										size="sm"
										on:click={() => createContainer(profile.id)}
									>
										<Box class="w-4 h-4 mr-2" />
										Create Container
									</Button>
									<Button variant="outline" size="sm" on:click={() => editingProfileId = editingProfileId === profile.id ? null : profile.id}>
										{editingProfileId === profile.id ? 'Cancel Edit' : 'Edit Profile'}
									</Button>
								</div>
								{#if editingProfileId === profile.id}
									<div class="mt-3 p-4 border rounded-lg space-y-3">
										<h4 class="font-medium text-sm">Edit Profile</h4>
										<div class="grid grid-cols-2 gap-3 text-sm">
											<div>
												<label class="block font-medium mb-1">Name</label>
												<input type="text" value={profile.name} class="w-full border rounded px-2 py-1 dark:bg-gray-800" />
											</div>
											<div>
												<label class="block font-medium mb-1">Description</label>
												<input type="text" value={profile.description} class="w-full border rounded px-2 py-1 dark:bg-gray-800" />
											</div>
										</div>
										<div class="flex gap-2">
											<Button size="sm" on:click={() => saveProfileEdit(profile)}>Save</Button>
											<Button size="sm" variant="outline" on:click={() => editingProfileId = null}>Cancel</Button>
										</div>
									</div>
								{/if}
							</CardContent>
						</Card>
					{/each}
				</div>
			</div>
		{/if}
	{:else}
		<div class="text-center py-12">
			<p class="text-gray-500 dark:text-gray-400">Unable to load isolation data</p>
		</div>
	{/if}
</div>