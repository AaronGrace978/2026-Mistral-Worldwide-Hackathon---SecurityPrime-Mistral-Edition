<script lang="ts">
	import { goto } from '$app/navigation';
	import { login, setCurrentUser } from '$lib/api';
	import { Shield, Mail, Lock, AlertCircle } from 'lucide-svelte';

	let email = '';
	let password = '';
	let loading = false;
	let error: string | null = null;

	async function handleSubmit() {
		if (!email || !password) {
			error = 'Please enter email and password';
			return;
		}

		loading = true;
		error = null;

		try {
			const response = await login(email, password);
			setCurrentUser(response.user);
			goto('/');
		} catch (e) {
			error = e instanceof Error ? e.message : 'Login failed';
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>Login - Security Prime MSP</title>
</svelte:head>

<div class="min-h-screen flex items-center justify-center bg-background p-4">
	<div class="w-full max-w-md">
		<!-- Logo -->
		<div class="flex flex-col items-center mb-8">
			<div class="rounded-full bg-primary/10 p-4 mb-4">
				<Shield class="h-12 w-12 text-primary" />
			</div>
			<h1 class="text-2xl font-bold">Security Prime</h1>
			<p class="text-muted-foreground">MSP Management Portal</p>
		</div>

		<!-- Login Form -->
		<div class="rounded-lg border border-border bg-card p-6 glass">
			<h2 class="text-xl font-semibold mb-6">Sign In</h2>

			{#if error}
				<div class="mb-4 flex items-center gap-2 rounded-lg border border-destructive/50 bg-destructive/10 p-3">
					<AlertCircle class="h-5 w-5 text-destructive shrink-0" />
					<p class="text-sm text-destructive">{error}</p>
				</div>
			{/if}

			<form on:submit|preventDefault={handleSubmit} class="space-y-4">
				<div>
					<label for="email" class="block text-sm font-medium mb-2">Email</label>
					<div class="relative">
						<Mail class="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
						<input
							id="email"
							type="email"
							bind:value={email}
							placeholder="admin@example.com"
							class="w-full rounded-lg border border-input bg-background pl-10 pr-4 py-2 focus:outline-none focus:ring-2 focus:ring-primary"
							disabled={loading}
						/>
					</div>
				</div>

				<div>
					<label for="password" class="block text-sm font-medium mb-2">Password</label>
					<div class="relative">
						<Lock class="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
						<input
							id="password"
							type="password"
							bind:value={password}
							placeholder="Enter your password"
							class="w-full rounded-lg border border-input bg-background pl-10 pr-4 py-2 focus:outline-none focus:ring-2 focus:ring-primary"
							disabled={loading}
						/>
					</div>
				</div>

				<button
					type="submit"
					class="w-full rounded-lg bg-primary py-2 font-medium text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50"
					disabled={loading}
				>
					{loading ? 'Signing in...' : 'Sign In'}
				</button>
			</form>

			<p class="mt-4 text-center text-sm text-muted-foreground">
				Default credentials: admin@securityprime.local / admin123
			</p>
		</div>
	</div>
</div>
