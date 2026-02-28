<script lang="ts">
	import { page } from '$app/stores';
	import { allModules, type ModuleInfo } from '$lib/stores/modules';
	import { moduleStatuses } from '$lib/stores/security';
	import { cn } from '$lib/utils';
	import { Badge } from '$lib/components/ui/badge';
	import { Separator } from '$lib/components/ui/separator';
	import { ChevronLeft, ChevronRight } from 'lucide-svelte';
	import MistralLogo from '$lib/components/MistralLogo.svelte';

	export let collapsed = false;

	$: currentPath = $page.url.pathname;

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
	<!-- Mistral Brand Header -->
	<a href="/" class="flex items-center gap-3 p-4 border-b border-border/50 hover:bg-primary/5 transition-colors cursor-pointer group">
		<div class="relative flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-[#E10500] via-[#FF8205] to-[#FFD800] overflow-hidden">
			<MistralLogo size={28} className="drop-shadow-sm" />
			<div class="absolute inset-0 rounded-lg opacity-0 group-hover:opacity-40 transition-opacity"
				style="box-shadow: 0 0 15px #FF8205, 0 0 30px rgba(255, 130, 5, 0.3);" />
		</div>
		{#if !collapsed}
			<div class="flex flex-col">
				<span class="font-bold text-sm tracking-wide text-mistral-gradient">
					SECURITY PRIME
				</span>
				<span class="text-[10px] text-muted-foreground font-medium tracking-widest flex items-center gap-1">
					MISTRAL EDITION
					<span class="inline-block w-1 h-1 rounded-full bg-[#FF8205] animate-pulse" />
				</span>
			</div>
		{/if}
	</a>

	<!-- Navigation -->
	<nav class="flex-1 overflow-y-auto p-2 space-y-1">
		{#if !collapsed}
			<div class="px-2 py-2">
				<span class="text-[10px] font-semibold text-muted-foreground uppercase tracking-[0.15em]">
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
					active && 'bg-primary/15 border border-primary/40',
					active && 'shadow-[0_0_15px_rgba(255,130,5,0.15)]',
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

	<!-- Footer -->
	<div class="p-2 border-t border-border/50 space-y-1">
		{#if !collapsed}
			<div class="flex items-center justify-center py-2 mb-1">
				<span class="text-[10px] text-muted-foreground">
					Powered by <a href="https://mistral.ai" target="_blank" rel="noopener" class="font-semibold text-foreground hover:text-orange-400 transition-colors">Mistral AI</a>
				</span>
			</div>
		{/if}

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
