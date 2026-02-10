<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { isAuthenticated, logout, getCurrentUser } from '$lib/api';
	import { 
		LayoutDashboard, 
		Building2, 
		Monitor, 
		Bell, 
		Users, 
		Settings, 
		LogOut,
		Shield,
		Menu,
		X
	} from 'lucide-svelte';

	let sidebarOpen = true;
	let user = getCurrentUser();
	
	const navItems = [
		{ href: '/', label: 'Dashboard', icon: LayoutDashboard },
		{ href: '/organizations', label: 'Organizations', icon: Building2 },
		{ href: '/endpoints', label: 'Endpoints', icon: Monitor },
		{ href: '/alerts', label: 'Alerts', icon: Bell },
		{ href: '/users', label: 'Users', icon: Users },
		{ href: '/settings', label: 'Settings', icon: Settings },
	];

	onMount(() => {
		// Check auth on protected routes
		const publicRoutes = ['/login', '/register'];
		if (!publicRoutes.includes($page.url.pathname) && !isAuthenticated()) {
			goto('/login');
		}
		user = getCurrentUser();
	});

	function toggleSidebar() {
		sidebarOpen = !sidebarOpen;
	}

	function handleLogout() {
		logout();
	}

	$: isPublicRoute = $page.url.pathname === '/login' || $page.url.pathname === '/register';
</script>

{#if isPublicRoute}
	<slot />
{:else}
	<div class="flex h-screen bg-background">
		<!-- Sidebar -->
		<aside 
			class="fixed inset-y-0 left-0 z-50 w-64 transform transition-transform duration-200 ease-in-out glass border-r border-border"
			class:translate-x-0={sidebarOpen}
			class:-translate-x-full={!sidebarOpen}
		>
			<div class="flex h-full flex-col">
				<!-- Logo -->
				<div class="flex h-16 items-center gap-3 px-6 border-b border-border">
					<Shield class="h-8 w-8 text-primary" />
					<div>
						<h1 class="text-lg font-bold">Security Prime</h1>
						<p class="text-xs text-muted-foreground">MSP Dashboard</p>
					</div>
				</div>

				<!-- Navigation -->
				<nav class="flex-1 space-y-1 p-4">
					{#each navItems as item}
						<a
							href={item.href}
							class="flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors
								{$page.url.pathname === item.href 
									? 'bg-primary text-primary-foreground' 
									: 'text-muted-foreground hover:bg-secondary hover:text-foreground'}"
						>
							<svelte:component this={item.icon} class="h-5 w-5" />
							{item.label}
						</a>
					{/each}
				</nav>

				<!-- User section -->
				<div class="border-t border-border p-4">
					<div class="flex items-center gap-3 mb-3">
						<div class="h-10 w-10 rounded-full bg-primary/20 flex items-center justify-center">
							<span class="text-sm font-medium text-primary">
								{user?.name?.charAt(0) || 'U'}
							</span>
						</div>
						<div class="flex-1 min-w-0">
							<p class="text-sm font-medium truncate">{user?.name || 'User'}</p>
							<p class="text-xs text-muted-foreground truncate">{user?.email || ''}</p>
						</div>
					</div>
					<button
						on:click={handleLogout}
						class="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm text-muted-foreground hover:bg-secondary hover:text-foreground transition-colors"
					>
						<LogOut class="h-4 w-4" />
						Sign Out
					</button>
				</div>
			</div>
		</aside>

		<!-- Main content -->
		<div class="flex-1 {sidebarOpen ? 'ml-64' : 'ml-0'} transition-all duration-200">
			<!-- Top bar -->
			<header class="sticky top-0 z-40 h-16 border-b border-border glass">
				<div class="flex h-full items-center justify-between px-6">
					<button
						on:click={toggleSidebar}
						class="rounded-lg p-2 hover:bg-secondary transition-colors"
					>
						{#if sidebarOpen}
							<X class="h-5 w-5" />
						{:else}
							<Menu class="h-5 w-5" />
						{/if}
					</button>

					<div class="flex items-center gap-4">
						<button class="relative rounded-lg p-2 hover:bg-secondary transition-colors">
							<Bell class="h-5 w-5" />
							<span class="absolute -top-1 -right-1 h-4 w-4 rounded-full bg-destructive text-[10px] font-bold flex items-center justify-center">
								3
							</span>
						</button>
					</div>
				</div>
			</header>

			<!-- Page content -->
			<main class="p-6">
				<slot />
			</main>
		</div>
	</div>
{/if}
