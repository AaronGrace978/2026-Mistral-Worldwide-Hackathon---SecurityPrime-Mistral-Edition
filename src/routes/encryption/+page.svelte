<script lang="ts">
	import { onMount } from 'svelte';
	import { save, open } from '@tauri-apps/api/dialog';
	import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { ScrollArea } from '$lib/components/ui/scroll-area';
	import { cn, formatBytes, formatRelativeTime } from '$lib/utils';
	import * as api from '$lib/api';
	import { 
		Lock, 
		Unlock, 
		FolderLock,
		FileKey,
		Plus,
		Eye,
		Trash2,
		Shield,
		Key,
		Download,
		Upload
	} from 'lucide-svelte';

	let encryptedFiles: api.EncryptedFile[] = [];
	let loading = true;

	onMount(async () => {
		try {
			encryptedFiles = await api.getEncryptedFiles();
		} catch (error) {
			console.error('Failed to load encrypted files:', error);
		} finally {
			loading = false;
		}
	});

	function handleEncrypt() {
		// Would open file dialog
		console.log('Opening file dialog for encryption...');
	}

	function handleDecrypt(fileId: string) {
		console.log('Decrypting file:', fileId);
	}

	async function exportKeys() {
		const password = prompt('Enter a password to protect the exported key:');
		if (!password) return;

		try {
			const filePath = await save({
				defaultPath: 'encryption-key.json',
				filters: [{ name: 'JSON', extensions: ['json'] }]
			});
			if (filePath) {
				const result = await api.exportEncryptionKeys(filePath, password);
				alert(`Key exported successfully!\nKey ID: ${result.key_id}`);
			}
		} catch (error) {
			console.error('Failed to export key:', error);
			alert('Failed to export key');
		}
	}

	async function importKeys() {
		try {
			const filePath = await open({
				filters: [{ name: 'JSON', extensions: ['json'] }],
				multiple: false
			});
			if (filePath && typeof filePath === 'string') {
				const password = prompt('Enter the password used to protect this key:');
				if (!password) return;
				
				const result = await api.importEncryptionKeys(filePath, password);
				if (result.success) {
					alert(result.message);
				} else {
					alert('Import failed: ' + result.message);
				}
			}
		} catch (error) {
			console.error('Failed to import key:', error);
			alert('Failed to import key: ' + error);
		}
	}
</script>

<svelte:head>
	<title>Encryption - Cyber Security Prime</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-3">
			<div class="flex items-center justify-center w-12 h-12 rounded-xl bg-cyber-purple/10">
				<Lock class="w-6 h-6 text-cyber-purple" />
			</div>
			<div>
				<h1 class="text-2xl font-bold tracking-tight text-foreground">
					File Encryption
				</h1>
				<p class="text-muted-foreground">
					Encrypt and protect your sensitive files and folders
				</p>
			</div>
		</div>
		<div class="flex items-center gap-2">
			<Button variant="outline" size="sm" on:click={exportKeys}>
				<Download class="w-4 h-4 mr-2" />
				Export Keys
			</Button>
			<Button variant="outline" size="sm" on:click={importKeys}>
				<Upload class="w-4 h-4 mr-2" />
				Import Keys
			</Button>
			<Badge variant="info" class="gap-1">
				<Key class="w-3 h-3" />
				AES-256-GCM
			</Badge>
		</div>
	</div>

	<div class="grid grid-cols-12 gap-6">
		<!-- Quick Actions -->
		<div class="col-span-12 lg:col-span-4">
			<div class="space-y-4">
				<Card variant="glass" class="neon-border">
					<CardContent class="pt-6">
						<div class="flex flex-col items-center text-center space-y-4">
							<div class="w-16 h-16 rounded-2xl bg-gradient-to-br from-cyber-purple to-cyber-blue flex items-center justify-center">
								<FolderLock class="w-8 h-8 text-white" />
							</div>
							<div>
								<h3 class="font-semibold text-lg">Encrypt Files</h3>
								<p class="text-sm text-muted-foreground mt-1">
									Select files or folders to encrypt with military-grade encryption
								</p>
							</div>
							<Button variant="cyber" class="w-full" on:click={handleEncrypt}>
								<Plus class="w-4 h-4 mr-2" />
								Encrypt New Files
							</Button>
						</div>
					</CardContent>
				</Card>

				<Card variant="glass">
					<CardContent class="pt-6">
						<div class="space-y-4">
							<div class="flex items-center justify-between">
								<span class="text-sm text-muted-foreground">Total Encrypted</span>
								<span class="text-2xl font-bold">{encryptedFiles.length}</span>
							</div>
							<div class="flex items-center justify-between">
								<span class="text-sm text-muted-foreground">Total Size</span>
								<span class="text-lg font-medium">
									{formatBytes(encryptedFiles.reduce((acc, f) => acc + f.encrypted_size, 0))}
								</span>
							</div>
							<div class="flex items-center justify-between">
								<span class="text-sm text-muted-foreground">Encryption</span>
								<Badge variant="success">AES-256-GCM</Badge>
							</div>
						</div>
					</CardContent>
				</Card>

				<Card variant="glass">
					<CardContent class="pt-6">
						<div class="flex items-center gap-2 mb-3">
							<Shield class="w-5 h-5 text-neon-green" />
							<span class="font-medium">Security Tips</span>
						</div>
						<ul class="space-y-2 text-sm text-muted-foreground">
							<li class="flex items-start gap-2">
								<span class="text-neon-green">•</span>
								Use strong, unique passwords for each encrypted file
							</li>
							<li class="flex items-start gap-2">
								<span class="text-neon-green">•</span>
								Store your passwords in a secure location
							</li>
							<li class="flex items-start gap-2">
								<span class="text-neon-green">•</span>
								Regular backups of encrypted files are recommended
							</li>
						</ul>
					</CardContent>
				</Card>
			</div>
		</div>

		<!-- Encrypted Files List -->
		<div class="col-span-12 lg:col-span-8">
			<Card variant="glass">
				<CardHeader>
					<CardTitle>Encrypted Files</CardTitle>
					<CardDescription>
						Manage your encrypted files and folders
					</CardDescription>
				</CardHeader>
				<CardContent>
					{#if loading}
						<div class="flex items-center justify-center h-64">
							<div class="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
						</div>
					{:else if encryptedFiles.length === 0}
						<div class="flex flex-col items-center justify-center h-64 text-muted-foreground">
							<FileKey class="w-12 h-12 mb-4 opacity-50" />
							<p class="text-lg font-medium">No encrypted files yet</p>
							<p class="text-sm mt-1">Click "Encrypt New Files" to get started</p>
						</div>
					{:else}
						<ScrollArea class="max-h-[500px]">
							<div class="space-y-3">
								{#each encryptedFiles as file}
									<div class="flex items-center justify-between p-4 rounded-lg bg-muted/30 border border-border hover:border-cyber-purple/30 transition-colors group">
										<div class="flex items-center gap-4">
											<div class="w-10 h-10 rounded-lg bg-cyber-purple/10 flex items-center justify-center">
												<Lock class="w-5 h-5 text-cyber-purple" />
											</div>
											<div>
												<p class="font-medium">{file.original_name}</p>
												<div class="flex items-center gap-2 text-xs text-muted-foreground mt-1">
													<span>{formatBytes(file.original_size)}</span>
													<span>•</span>
													<span>{file.algorithm}</span>
													<span>•</span>
													<span>Encrypted {formatRelativeTime(file.encrypted_at)}</span>
												</div>
											</div>
										</div>
										<div class="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
											<Button variant="ghost" size="sm" on:click={() => handleDecrypt(file.id)}>
												<Unlock class="w-4 h-4 mr-2" />
												Decrypt
											</Button>
											<Button variant="ghost" size="icon">
												<Eye class="w-4 h-4" />
											</Button>
											<Button variant="ghost" size="icon" class="text-destructive">
												<Trash2 class="w-4 h-4" />
											</Button>
										</div>
									</div>
								{/each}
							</div>
						</ScrollArea>
					{/if}
				</CardContent>
			</Card>
		</div>
	</div>
</div>

