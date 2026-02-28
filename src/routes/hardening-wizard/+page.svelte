<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import * as api from '$lib/api';
	import type { HardeningStep } from '$lib/api';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { cn } from '$lib/utils';
	import { moduleStatuses } from '$lib/stores/security';
	import {
		Wand2, Shield, CheckCircle2, Circle, ChevronRight,
		Flame, Lock, Bug, Network, Zap, AlertTriangle, ArrowRight
	} from 'lucide-svelte';

	let steps: HardeningStep[] = [];
	let loading = true;
	let activeStep = 0;
	let completing = '';

	$: completedCount = steps.filter(s => s.completed).length;
	$: totalSteps = steps.length;
	$: progress = totalSteps > 0 ? Math.round((completedCount / totalSteps) * 100) : 0;

	const categoryIcons: Record<string, any> = {
		'Network': Flame,
		'Endpoint': Shield,
		'Data': Lock,
		'System': Zap,
	};

	const impactColors: Record<string, string> = {
		'critical': 'bg-red-500/20 text-red-400 border-red-500/30',
		'high': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
		'medium': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
		'low': 'bg-blue-500/20 text-blue-400 border-blue-500/30',
	};

	onMount(async () => {
		try {
			steps = await api.getHardeningSteps();
		} catch (e) {
			console.error('Failed to load hardening steps:', e);
		} finally {
			loading = false;
		}
	});

	async function executeStep(step: HardeningStep, idx: number) {
		completing = step.id;
		try {
			if (step.action.startsWith('toggle_module:')) {
				const moduleName = step.action.split(':')[1];
				await api.toggleModule(moduleName, true);
				await moduleStatuses.fetch();
				steps = steps.map((s, i) => i === idx ? { ...s, completed: true } : s);
				const next = steps.findIndex((s, i) => i > idx && !s.completed);
				if (next !== -1) activeStep = next;
			} else if (step.action.startsWith('navigate:')) {
				const route = step.action.split(':')[1];
				goto(route);
			}
		} catch (e) {
			console.error('Failed to execute step:', e);
		} finally {
			completing = '';
		}
	}
</script>

<div class="flex-1 p-6 space-y-6 max-w-5xl mx-auto">
	<!-- Header -->
	<div class="flex items-center gap-4">
		<div class="p-3 rounded-xl bg-gradient-to-br from-orange-500/20 to-amber-500/20 border border-orange-500/30">
			<Wand2 class="w-8 h-8 text-orange-400" />
		</div>
		<div>
			<h1 class="text-2xl font-bold text-foreground">10-Minute Hardening Wizard</h1>
			<p class="text-muted-foreground">Follow these steps to secure your system in minutes</p>
		</div>
	</div>

	<!-- Progress Bar -->
	<Card variant="glass">
		<CardContent class="pt-6">
			<div class="flex items-center justify-between mb-3">
				<span class="text-sm font-medium text-foreground">Setup Progress</span>
				<span class="text-sm text-muted-foreground">{completedCount} / {totalSteps} complete</span>
			</div>
			<div class="w-full h-3 bg-muted/50 rounded-full overflow-hidden">
				<div
					class="h-full rounded-full transition-all duration-700 ease-out"
					style="width: {progress}%; background: linear-gradient(90deg, #FF8205, #FFD800);"
				/>
			</div>
			{#if progress === 100}
				<div class="mt-3 flex items-center gap-2 text-green-400">
					<CheckCircle2 class="w-5 h-5" />
					<span class="text-sm font-medium">All steps complete — your system is hardened!</span>
				</div>
			{:else}
				<p class="mt-3 text-xs text-muted-foreground">
					Estimated time: ~{Math.max(1, Math.ceil((totalSteps - completedCount) * 1.2))} minutes remaining
				</p>
			{/if}
		</CardContent>
	</Card>

	<!-- Steps -->
	{#if loading}
		<div class="flex items-center justify-center py-20">
			<div class="w-10 h-10 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
		</div>
	{:else}
		<div class="space-y-3">
			{#each steps as step, idx (step.id)}
				{@const Icon = categoryIcons[step.category] || Shield}
				{@const isActive = idx === activeStep}
				{@const isCompleted = step.completed}
				<button
					class={cn(
						'w-full text-left rounded-xl border transition-all duration-200',
						isCompleted
							? 'bg-green-500/5 border-green-500/20'
							: isActive
								? 'bg-primary/5 border-primary/40 shadow-[0_0_20px_rgba(255,130,5,0.1)]'
								: 'bg-card/50 border-border/50 hover:border-border'
					)}
					on:click={() => { if (!isCompleted) activeStep = idx; }}
				>
					<div class="flex items-center gap-4 p-4">
						<div class={cn(
							'flex items-center justify-center w-10 h-10 rounded-lg transition-colors',
							isCompleted ? 'bg-green-500/20' : isActive ? 'bg-primary/20' : 'bg-muted/50'
						)}>
							{#if isCompleted}
								<CheckCircle2 class="w-5 h-5 text-green-400" />
							{:else}
								<span class="text-sm font-bold text-muted-foreground">{idx + 1}</span>
							{/if}
						</div>

						<div class="flex-1 min-w-0">
							<div class="flex items-center gap-2">
								<span class={cn(
									'font-semibold text-sm',
									isCompleted ? 'text-green-400 line-through opacity-70' : 'text-foreground'
								)}>
									{step.title}
								</span>
								<Badge class={cn('text-[10px] border', impactColors[step.impact] || '')}>
									{step.impact}
								</Badge>
								<Badge variant="outline" class="text-[10px]">{step.category}</Badge>
							</div>
							<p class="text-xs text-muted-foreground mt-0.5">{step.description}</p>
						</div>

						{#if !isCompleted}
							{#if isActive}
								<Button
									size="sm"
									class="shrink-0"
									disabled={completing === step.id}
									on:click={(e) => { e.stopPropagation(); executeStep(step, idx); }}
								>
									{#if completing === step.id}
										<div class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin mr-2" />
									{/if}
									{step.action.startsWith('toggle_module') ? 'Enable' : 'Open'}
									<ArrowRight class="w-4 h-4 ml-1" />
								</Button>
							{:else}
								<ChevronRight class="w-5 h-5 text-muted-foreground" />
							{/if}
						{/if}
					</div>
				</button>
			{/each}
		</div>
	{/if}
</div>
