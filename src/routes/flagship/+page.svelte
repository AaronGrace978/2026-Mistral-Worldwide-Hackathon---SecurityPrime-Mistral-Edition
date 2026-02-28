<script lang="ts">
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import { flagshipEnhancements, getPillarLabel, type FlagshipPillar } from '$lib/flagship';
	import { Rocket, Shield, Building2, Sparkles } from 'lucide-svelte';

	const pillarIcons: Record<FlagshipPillar, typeof Shield> = {
		'autonomous-defense': Shield,
		'enterprise-trust': Building2,
		'premium-experience': Sparkles
	};

	const pillars: FlagshipPillar[] = ['autonomous-defense', 'enterprise-trust', 'premium-experience'];
</script>

<svelte:head>
	<title>Flagship Program - Cyber Security Prime</title>
</svelte:head>

<div class="space-y-6">
	<Card variant="glass" class="border-neon-pink/30">
		<CardHeader>
			<div class="flex items-center gap-3">
				<div class="flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-neon-pink to-cyber-purple">
					<Rocket class="w-6 h-6 text-white" />
				</div>
				<div>
					<CardTitle class="text-2xl">Flagship Enhancement Program</CardTitle>
					<p class="text-sm text-muted-foreground mt-1">
						All approved flagship capabilities are now wired into product navigation and delivery tracking.
					</p>
				</div>
			</div>
		</CardHeader>
		<CardContent>
			<div class="flex flex-wrap items-center gap-2">
				<Badge variant="success">Scope Locked</Badge>
				<Badge variant="outline">{flagshipEnhancements.length} enhancements mapped</Badge>
				<Badge variant="outline">30/60/90 rollout ready</Badge>
			</div>
		</CardContent>
	</Card>

	{#each pillars as pillar}
		{@const items = flagshipEnhancements.filter((item) => item.pillar === pillar)}
		<Card variant="glass">
			<CardHeader>
				<div class="flex items-center gap-2">
					<svelte:component this={pillarIcons[pillar]} class="w-5 h-5 text-cyber-blue" />
					<CardTitle class="text-lg">{getPillarLabel(pillar)}</CardTitle>
					<Badge variant="outline">{items.length} items</Badge>
				</div>
			</CardHeader>
			<CardContent>
				<div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
					{#each items as item}
						<div class="rounded-lg border border-border/60 bg-card/30 p-4 space-y-3">
							<div>
								<p class="font-medium text-foreground">{item.title}</p>
								<p class="text-sm text-muted-foreground mt-1">{item.description}</p>
							</div>
							<div class="flex items-center justify-between">
								<Badge variant="outline">Wired</Badge>
								<a href={item.route}>
									<Button variant="outline" size="sm">Open</Button>
								</a>
							</div>
						</div>
					{/each}
				</div>
			</CardContent>
		</Card>
	{/each}
</div>

