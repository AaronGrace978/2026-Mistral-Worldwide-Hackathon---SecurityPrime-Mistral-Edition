<script lang="ts">
	import { page } from '$app/stores';
	import { allModules, type ModuleInfo } from '$lib/stores/modules';
	import { moduleStatuses } from '$lib/stores/security';
	import { cn } from '$lib/utils';
	import { Badge } from '$lib/components/ui/badge';
	import { Separator } from '$lib/components/ui/separator';
	import { Shield, ChevronLeft, ChevronRight } from 'lucide-svelte';

	export let collapsed = false;

	$: currentPath = $page.url.pathname;

	// Get navigation items (excluding settings)
	$: navItems = allModules.filter((m) => m.id !== 'settings');
	$: settingsModule = allModules.find((m) => m.id === 'settings');

	function getModuleStatus(moduleId: string): string | undefined {
		const status = $moduleStatuses.find((s) => s.name === moduleId);
		return status?.status;
	}

	function isActive(route: string): boolean {
		if (route === '/') return currentPath === '/';
		return currentPath.startsWith(route);
	}
</script>

<aside
	class={cn(
		'flex flex-col h-full bg-card/50 backdrop-blur-xl border-r border-border/50 transition-all duration-300',
		collapsed ? 'w-16' : 'w-64'
	)}
>
	<!-- Logo & Brand -->
	<a href="/" class="flex items-center gap-3 p-4 border-b border-border/50 hover:bg-primary/5 transition-colors cursor-pointer">
		<div class="relative flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-cyber-blue to-cyber-purple">
			<Shield class="w-6 h-6 text-white" />
			<div class="absolute inset-0 rounded-lg animate-pulse-glow opacity-50" />
		</div>
		{#if !collapsed}
			<div class="flex flex-col">
				<span class="font-cyber text-sm font-bold tracking-wider text-cyber-blue text-glow-blue">
					CYBER SECURITY
				</span>
				<span class="text-xs text-muted-foreground font-medium tracking-widest">
					PRIME
				</span>
			</div>
		{/if}
	</a>

	<!-- Navigation -->
	<nav class="flex-1 overflow-y-auto p-2 space-y-1">
		<!-- Main modules group -->
		{#if !collapsed}
			<div class="px-2 py-2">
				<span class="text-xs font-medium text-muted-foreground uppercase tracking-wider">
					Security Modules
				</span>
			</div>
		{/if}

		{#each navItems as module (module.id)}
			{@const status = getModuleStatus(module.id)}
			{@const active = isActive(module.route)}
			
			<a
				href={module.route}
				class={cn(
					'group flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200',
					'hover:bg-primary/10 hover:border-primary/30',
					active && 'bg-primary/15 border border-primary/40 shadow-neon-blue',
					!active && 'border border-transparent',
					collapsed && 'justify-center'
				)}
				title={collapsed ? module.name : undefined}
			>
				<div class={cn(
					'flex items-center justify-center w-8 h-8 rounded-md transition-colors',
					active ? 'text-primary' : 'text-muted-foreground group-hover:text-primary'
				)}>
					<svelte:component this={module.icon} class="w-5 h-5" />
				</div>
				
				{#if !collapsed}
					<div class="flex-1 min-w-0">
						<div class="flex items-center gap-2">
							<span class={cn(
								'text-sm font-medium truncate',
								active ? 'text-foreground' : 'text-muted-foreground group-hover:text-foreground'
							)}>
								{module.name}
							</span>
							{#if module.comingSoon}
								<Badge variant="outline" class="text-[10px] px-1.5 py-0">Soon</Badge>
							{/if}
						</div>
					</div>

					<!-- Status indicator -->
					{#if status && module.id !== 'dashboard'}
						<div class={cn(
							'w-2 h-2 rounded-full',
							status === 'active' && 'status-active',
							status === 'inactive' && 'status-inactive',
							status === 'warning' && 'status-warning',
							status === 'error' && 'status-error',
							status === 'scanning' && 'status-active animate-pulse'
						)} />
					{/if}
				{/if}
			</a>
		{/each}
	</nav>

	<!-- Settings & Collapse -->
	<div class="p-2 border-t border-border/50 space-y-1">
		{#if settingsModule}
			{@const active = isActive(settingsModule.route)}
			<a
				href={settingsModule.route}
				class={cn(
					'group flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200',
					'hover:bg-muted',
					active && 'bg-muted',
					collapsed && 'justify-center'
				)}
				title={collapsed ? settingsModule.name : undefined}
			>
				<svelte:component 
					this={settingsModule.icon} 
					class={cn(
						'w-5 h-5 transition-colors',
						active ? 'text-foreground' : 'text-muted-foreground group-hover:text-foreground'
					)} 
				/>
				{#if !collapsed}
					<span class={cn(
						'text-sm font-medium',
						active ? 'text-foreground' : 'text-muted-foreground group-hover:text-foreground'
					)}>
						{settingsModule.name}
					</span>
				{/if}
			</a>
		{/if}

		<Separator class="my-2" />

		<button
			on:click={() => (collapsed = !collapsed)}
			class={cn(
				'w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-colors',
				'text-muted-foreground hover:text-foreground hover:bg-muted',
				collapsed && 'justify-center'
			)}
		>
			{#if collapsed}
				<ChevronRight class="w-5 h-5" />
			{:else}
				<ChevronLeft class="w-5 h-5" />
				<span class="text-sm">Collapse</span>
			{/if}
		</button>
	</div>
</aside>

