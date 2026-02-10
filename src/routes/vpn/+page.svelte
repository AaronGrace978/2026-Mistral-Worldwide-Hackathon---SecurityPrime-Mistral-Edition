<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { invoke } from '@tauri-apps/api/tauri';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Progress } from '$lib/components/ui/progress';
	import { 
		Shield,
		Globe,
		Loader2,
		Check,
		X,
		Wifi,
		WifiOff,
		MapPin,
		Server,
		Upload,
		Download,
		RefreshCw,
		ExternalLink,
		Clock,
		Zap,
		Lock,
		Unlock,
		Signal,
		AlertTriangle
	} from 'lucide-svelte';

	interface VpnServer {
		id: string;
		name: string;
		country: string;
		country_code: string;
		city: string;
		endpoint: string;
		load: number;
		ping?: number;
		protocol: string;
		free: boolean;
	}

	interface VpnConnection {
		status: 'disconnected' | 'connecting' | 'connected' | 'disconnecting' | 'error';
		server?: VpnServer;
		connected_at?: string;
		bytes_sent: number;
		bytes_received: number;
		current_ip?: string;
		original_ip?: string;
	}

	interface IpInfo {
		ip: string;
		city?: string;
		country?: string;
		isp?: string;
		is_vpn: boolean;
	}

	interface Requirements {
		wireguard_installed: boolean;
		admin_privileges: boolean;
	}

	let connection: VpnConnection = {
		status: 'disconnected',
		bytes_sent: 0,
		bytes_received: 0
	};
	let servers: VpnServer[] = [];
	let selectedServer: VpnServer | null = null;
	let ipInfo: IpInfo | null = null;
	let requirements: Requirements | null = null;
	let loading = false;
	let connectingServerId: string | null = null;

	let refreshInterval: ReturnType<typeof setInterval>;

	onMount(async () => {
		await Promise.all([
			loadServers(),
			loadStatus(),
			loadIpInfo(),
			checkRequirements()
		]);

		// Refresh status periodically
		refreshInterval = setInterval(async () => {
			if (connection.status === 'connected') {
				await loadStatus();
			}
		}, 5000);
	});

	onDestroy(() => {
		if (refreshInterval) clearInterval(refreshInterval);
	});

	async function loadServers() {
		try {
			servers = await invoke<VpnServer[]>('get_vpn_servers');
		} catch (e) {
			console.error('Failed to load servers:', e);
		}
	}

	async function loadStatus() {
		try {
			connection = await invoke<VpnConnection>('get_vpn_status');
			if (connection.server) {
				selectedServer = connection.server;
			}
		} catch (e) {
			console.error('Failed to load status:', e);
		}
	}

	async function loadIpInfo() {
		try {
			ipInfo = await invoke<IpInfo>('get_ip_info');
		} catch (e) {
			console.error('Failed to load IP info:', e);
		}
	}

	async function checkRequirements() {
		try {
			requirements = await invoke<Requirements>('check_vpn_requirements');
		} catch (e) {
			console.error('Failed to check requirements:', e);
		}
	}

	async function connect(server: VpnServer) {
		if (connection.status === 'connected' || connection.status === 'connecting') return;
		
		loading = true;
		connectingServerId = server.id;
		
		try {
			connection = await invoke<VpnConnection>('connect_vpn', { serverId: server.id });
			selectedServer = server;
			await loadIpInfo(); // Refresh IP after connecting
		} catch (e: any) {
			console.error('Failed to connect:', e);
			alert(`Connection failed: ${e.toString()}`);
		} finally {
			loading = false;
			connectingServerId = null;
		}
	}

	async function disconnect() {
		if (connection.status !== 'connected') return;
		
		loading = true;
		try {
			connection = await invoke<VpnConnection>('disconnect_vpn');
			await loadIpInfo(); // Refresh IP after disconnecting
		} catch (e) {
			console.error('Failed to disconnect:', e);
		} finally {
			loading = false;
		}
	}

	async function pingServer(server: VpnServer) {
		try {
			const ping = await invoke<number>('ping_vpn_server', { serverId: server.id });
			servers = servers.map(s => s.id === server.id ? { ...s, ping } : s);
		} catch (e) {
			console.error('Failed to ping server:', e);
		}
	}

	async function downloadWireGuard() {
		try {
			const url = await invoke<string>('get_wireguard_download_url');
			window.open(url, '_blank');
		} catch (e) {
			console.error('Failed to get download URL:', e);
		}
	}

	function formatBytes(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
		return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
	}

	function getLoadColor(load: number): string {
		if (load < 40) return 'text-neon-green';
		if (load < 70) return 'text-neon-yellow';
		return 'text-danger';
	}

	function getCountryFlag(code: string): string {
		// Convert country code to flag emoji
		const codePoints = code
			.toUpperCase()
			.split('')
			.map(char => 127397 + char.charCodeAt(0));
		return String.fromCodePoint(...codePoints);
	}

	$: isConnected = connection.status === 'connected';
	$: isConnecting = connection.status === 'connecting';
</script>

<svelte:head>
	<title>VPN - Cyber Security Prime</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-3">
			<div class="flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-neon-green to-cyber-blue">
				<Shield class="w-6 h-6 text-white" />
			</div>
			<div>
				<h1 class="text-2xl font-bold tracking-tight text-foreground">
					VPN Protection
				</h1>
				<p class="text-muted-foreground text-sm">
					Free, open-source VPN powered by WireGuard
				</p>
			</div>
		</div>
		<Badge variant={isConnected ? 'success' : 'secondary'} class="gap-1 text-sm px-3 py-1">
			{#if isConnected}
				<Lock class="w-3 h-3" /> Protected
			{:else if isConnecting}
				<Loader2 class="w-3 h-3 animate-spin" /> Connecting
			{:else}
				<Unlock class="w-3 h-3" /> Not Protected
			{/if}
		</Badge>
	</div>

	<!-- Requirements Warning -->
	{#if requirements && !requirements.wireguard_installed}
		<Card variant="glass" class="border-warning/50 bg-warning/5">
			<CardContent class="py-4">
				<div class="flex items-center gap-4">
					<AlertTriangle class="w-8 h-8 text-warning" />
					<div class="flex-1">
						<p class="font-medium text-warning">WireGuard Not Installed</p>
						<p class="text-sm text-muted-foreground">
							WireGuard is required for VPN functionality. Click to download and install.
						</p>
					</div>
					<Button variant="warning" on:click={downloadWireGuard}>
						<ExternalLink class="w-4 h-4 mr-2" />
						Download WireGuard
					</Button>
				</div>
			</CardContent>
		</Card>
	{/if}

	<!-- Connection Status Card -->
	<Card variant="glass" class="neon-border overflow-hidden">
		<div class="absolute inset-0 bg-gradient-to-r {isConnected ? 'from-neon-green/5 to-cyber-blue/5' : 'from-muted/5 to-muted/5'}" />
		<CardContent class="relative py-8">
			<div class="flex items-center justify-between">
				<!-- Left: Status -->
				<div class="flex items-center gap-6">
					<div class="relative">
						<div class="w-24 h-24 rounded-full flex items-center justify-center {isConnected ? 'bg-neon-green/20 ring-2 ring-neon-green' : 'bg-muted/50 ring-2 ring-muted'}">
							{#if isConnected}
								<Wifi class="w-10 h-10 text-neon-green" />
							{:else if isConnecting}
								<Loader2 class="w-10 h-10 text-cyber-blue animate-spin" />
							{:else}
								<WifiOff class="w-10 h-10 text-muted-foreground" />
							{/if}
						</div>
						{#if isConnected}
							<div class="absolute -inset-2 rounded-full bg-neon-green/20 animate-pulse" style="z-index: -1;" />
						{/if}
					</div>
					<div>
						<p class="text-3xl font-bold {isConnected ? 'text-neon-green' : 'text-muted-foreground'}">
							{#if isConnected}
								Connected
							{:else if isConnecting}
								Connecting...
							{:else}
								Disconnected
							{/if}
						</p>
						{#if connection.server}
							<p class="text-lg text-muted-foreground mt-1">
								{getCountryFlag(connection.server.country_code)} {connection.server.name}
							</p>
						{/if}
					</div>
				</div>

				<!-- Right: IP Info -->
				<div class="text-right">
					<div class="flex items-center justify-end gap-2 text-sm text-muted-foreground mb-1">
						<Globe class="w-4 h-4" />
						Your IP Address
					</div>
					<p class="text-2xl font-mono {isConnected ? 'text-neon-green' : 'text-foreground'}">
						{ipInfo?.ip || 'Loading...'}
					</p>
					{#if ipInfo?.country}
						<p class="text-sm text-muted-foreground mt-1">
							<MapPin class="w-3 h-3 inline mr-1" />
							{ipInfo.city}, {ipInfo.country}
						</p>
					{/if}
				</div>
			</div>

			<!-- Stats -->
			{#if isConnected}
				<div class="grid grid-cols-3 gap-6 mt-8 pt-6 border-t border-border">
					<div class="text-center">
						<div class="flex items-center justify-center gap-2 text-sm text-muted-foreground mb-1">
							<Upload class="w-4 h-4 text-cyber-blue" />
							Uploaded
						</div>
						<p class="text-xl font-medium">{formatBytes(connection.bytes_sent)}</p>
					</div>
					<div class="text-center">
						<div class="flex items-center justify-center gap-2 text-sm text-muted-foreground mb-1">
							<Download class="w-4 h-4 text-neon-green" />
							Downloaded
						</div>
						<p class="text-xl font-medium">{formatBytes(connection.bytes_received)}</p>
					</div>
					<div class="text-center">
						<div class="flex items-center justify-center gap-2 text-sm text-muted-foreground mb-1">
							<Clock class="w-4 h-4 text-cyber-purple" />
							Connected
						</div>
						<p class="text-xl font-medium">
							{connection.connected_at ? 'Active' : '--:--'}
						</p>
					</div>
				</div>
			{/if}

			<!-- Connect/Disconnect Button -->
			<div class="mt-8 flex justify-center">
				{#if isConnected}
					<Button variant="destructive" size="lg" class="px-12" on:click={disconnect} disabled={loading}>
						{#if loading}
							<Loader2 class="w-5 h-5 mr-2 animate-spin" />
						{:else}
							<X class="w-5 h-5 mr-2" />
						{/if}
						Disconnect
					</Button>
				{:else if selectedServer}
					<Button variant="cyber" size="lg" class="px-12" on:click={() => selectedServer && connect(selectedServer)} disabled={loading || !requirements?.wireguard_installed}>
						{#if loading}
							<Loader2 class="w-5 h-5 mr-2 animate-spin" />
						{:else}
							<Zap class="w-5 h-5 mr-2" />
						{/if}
						Quick Connect
					</Button>
				{/if}
			</div>
		</CardContent>
	</Card>

	<!-- Server List -->
	<Card variant="glass">
		<CardHeader>
			<div class="flex items-center justify-between">
				<CardTitle class="flex items-center gap-2">
					<Server class="w-5 h-5 text-primary" />
					Available Servers
				</CardTitle>
				<Button variant="ghost" size="sm" on:click={loadServers}>
					<RefreshCw class="w-4 h-4" />
				</Button>
			</div>
		</CardHeader>
		<CardContent>
			<div class="grid grid-cols-1 md:grid-cols-2 gap-3">
				{#each servers as server}
					<button
						class="flex items-center gap-4 p-4 rounded-xl border transition-all duration-200
							{selectedServer?.id === server.id 
								? 'bg-primary/10 border-primary' 
								: 'bg-muted/30 border-border hover:border-primary/50 hover:bg-muted/50'}
							{isConnected && connection.server?.id === server.id ? 'ring-2 ring-neon-green' : ''}"
						on:click={() => selectedServer = server}
						on:dblclick={() => connect(server)}
						disabled={isConnected}
					>
						<div class="text-3xl">
							{getCountryFlag(server.country_code)}
						</div>
						<div class="flex-1 text-left">
							<p class="font-medium">{server.name}</p>
							<p class="text-sm text-muted-foreground">{server.city}, {server.country}</p>
						</div>
						<div class="text-right">
							<div class="flex items-center gap-1 text-sm {getLoadColor(server.load)}">
								<Signal class="w-4 h-4" />
								{server.load}%
							</div>
							{#if server.ping}
								<p class="text-xs text-muted-foreground">{server.ping}ms</p>
							{/if}
						</div>
						{#if connectingServerId === server.id}
							<Loader2 class="w-5 h-5 animate-spin text-cyber-blue" />
						{:else if isConnected && connection.server?.id === server.id}
							<Check class="w-5 h-5 text-neon-green" />
						{/if}
					</button>
				{/each}
			</div>

			{#if servers.length === 0}
				<div class="text-center py-8 text-muted-foreground">
					<Server class="w-12 h-12 mx-auto mb-3 opacity-30" />
					<p>No servers available</p>
					<Button variant="outline" class="mt-4" on:click={loadServers}>
						<RefreshCw class="w-4 h-4 mr-2" />
						Refresh
					</Button>
				</div>
			{/if}
		</CardContent>
	</Card>

	<!-- Info Cards -->
	<div class="grid grid-cols-3 gap-4">
		<Card variant="glass">
			<CardContent class="py-4 text-center">
				<Lock class="w-8 h-8 mx-auto mb-2 text-neon-green" />
				<p class="font-medium">No Logs</p>
				<p class="text-xs text-muted-foreground mt-1">Your activity is never logged</p>
			</CardContent>
		</Card>
		<Card variant="glass">
			<CardContent class="py-4 text-center">
				<Zap class="w-8 h-8 mx-auto mb-2 text-cyber-blue" />
				<p class="font-medium">WireGuard</p>
				<p class="text-xs text-muted-foreground mt-1">Modern, fast protocol</p>
			</CardContent>
		</Card>
		<Card variant="glass">
			<CardContent class="py-4 text-center">
				<Shield class="w-8 h-8 mx-auto mb-2 text-cyber-purple" />
				<p class="font-medium">Free Forever</p>
				<p class="text-xs text-muted-foreground mt-1">No subscriptions needed</p>
			</CardContent>
		</Card>
	</div>
</div>

