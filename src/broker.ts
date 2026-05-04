import * as vscode from 'vscode';
import * as http from 'http';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AddressInfo } from 'net';
import { PROVIDER_ID, SelectedAccountStore } from './state';

const DISCOVERY_DIRNAME = '.vscode';
const DISCOVERY_FILENAME = 'azure-service-auth.json';
const USER_DISCOVERY_DIR = path.join(os.homedir(), '.vscode-azure-service-auth');
// VS Code does not expose JWT exp; assume a conservative 55 minutes.
const TOKEN_LIFETIME_MS = 55 * 60 * 1000;

// Visual Studio IdentityService token-provider registration.
// %LOCALAPPDATA%\.IdentityService\AzureServiceAuth\tokenprovider.json
const VS_IDENTITY_SERVICE_DIR = process.platform === 'win32'
	? path.join(process.env.LOCALAPPDATA ?? path.join(os.homedir(), 'AppData', 'Local'), '.IdentityService', 'AzureServiceAuth')
	: null;
const VS_TOKEN_PROVIDER_FILE = VS_IDENTITY_SERVICE_DIR
	? path.join(VS_IDENTITY_SERVICE_DIR, 'tokenprovider.json')
	: null;
const VS_PROVIDER_MARKER = '_vscodeAzureServiceAuth';

interface DiscoveryFile {
	endpoint: string;
	token: string;
	account: string | null;
	pid: number;
}

interface TokenRequestBody {
	scopes?: string[];
	tenantId?: string;
}

export class TokenBroker {
	private server: http.Server | undefined;
	private bearer: string = '';
	private port: number = 0;
	private readonly discoveryFiles: string[] = [];
	private readonly disposables: vscode.Disposable[] = [];

	constructor(
		private readonly store: SelectedAccountStore,
		private readonly log: vscode.LogOutputChannel,
		private readonly extensionPath: string,
	) {}

	async start(): Promise<void> {
		this.bearer = crypto.randomBytes(32).toString('hex');
		this.server = http.createServer((req, res) => this.handle(req, res));

		await new Promise<void>((resolve, reject) => {
			this.server!.once('error', reject);
			this.server!.listen(0, '127.0.0.1', () => {
				this.port = (this.server!.address() as AddressInfo).port;
				resolve();
			});
		});

		this.log.info(`Token broker listening on http://127.0.0.1:${this.port}`);
		await this.writeDiscoveryFiles();
		await this.writeVisualStudioTokenProvider();

		// Rewrite discovery files when the selected account label changes so
		// downstream tooling can show the right account.
		this.disposables.push(this.store.onDidChange(() => {
			void this.writeDiscoveryFiles();
		}));

		// Update discovery files whenever workspace folders change.
		this.disposables.push(vscode.workspace.onDidChangeWorkspaceFolders(() => {
			void this.writeDiscoveryFiles();
		}));
	}

	async dispose(): Promise<void> {
		for (const d of this.disposables) { d.dispose(); }
		this.disposables.length = 0;
		await this.removeDiscoveryFiles();
		await this.removeVisualStudioTokenProvider();
		if (this.server) {
			await new Promise<void>(resolve => this.server!.close(() => resolve()));
			this.server = undefined;
		}
	}

	private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
		try {
			if (req.method !== 'POST' || req.url !== '/token') {
				return reply(res, 404, { error: 'not_found' });
			}
			const auth = req.headers['authorization'];
			if (auth !== `Bearer ${this.bearer}`) {
				return reply(res, 401, { error: 'unauthorized' });
			}

			let body: TokenRequestBody | undefined;
			try {
				body = await readJson<TokenRequestBody>(req);
			} catch (err) {
				const msg = err instanceof Error ? err.message : String(err);
				if (msg === 'payload_too_large') {
					return reply(res, 413, { error: 'payload_too_large' });
				}
				return reply(res, 400, { error: 'invalid_json' });
			}
			const scopes = Array.isArray(body?.scopes) ? body!.scopes!.filter(s => typeof s === 'string') : [];
			if (scopes.length === 0) {
				return reply(res, 400, { error: 'scopes_required' });
			}

			// Limit scope count and per-scope length to prevent abuse.
			if (scopes.length > 20 || scopes.some(s => s.length > 512)) {
				return reply(res, 400, { error: 'scopes_invalid' });
			}

			// Validate tenantId is a GUID or AAD domain (letters/digits/dots/hyphens).
			const tenantId = body?.tenantId;
			if (tenantId !== undefined && tenantId !== null) {
				const validTenant = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$|^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/i;
				if (typeof tenantId !== 'string' || !validTenant.test(tenantId)) {
					return reply(res, 400, { error: 'tenant_id_invalid' });
				}
			}

			const selected = this.store.current;
			if (!selected) {
				return reply(res, 409, { error: 'no_account_selected' });
			}

			// Map the selected account id back to AuthenticationSessionAccountInformation.
			const accounts = await vscode.authentication.getAccounts(PROVIDER_ID);
			const account = accounts.find(a => a.id === selected.id);
			if (!account) {
				return reply(res, 410, { error: 'account_no_longer_available' });
			}

			const effectiveScopes = tenantId
				? [...scopes, `VSCODE_TENANT:${tenantId}`]
				: scopes;

			let session: vscode.AuthenticationSession | undefined;
			try {
				session = await vscode.authentication.getSession(PROVIDER_ID, effectiveScopes, {
					account,
					silent: true,
				});
			} catch (err) {
				this.log.warn(`silent getSession failed: ${formatError(err)}`);
			}

			if (!session) {
				try {
					session = await vscode.authentication.getSession(PROVIDER_ID, effectiveScopes, {
						account,
						createIfNone: true,
					});
				} catch (err) {
					return reply(res, 500, { error: 'interactive_failed', detail: formatError(err) });
				}
			}

			if (!session) {
				return reply(res, 401, { error: 'no_session' });
			}

			const expiresOn = new Date(Date.now() + TOKEN_LIFETIME_MS).toISOString();
			return reply(res, 200, {
				token: session.accessToken,
				expiresOn,
				account: session.account.label,
			});
		} catch (err) {
			this.log.error(`broker error: ${formatError(err)}`);
			return reply(res, 500, { error: 'internal', detail: formatError(err) });
		}
	}

	private async writeDiscoveryFiles(): Promise<void> {
		const payload: DiscoveryFile = {
			endpoint: `http://127.0.0.1:${this.port}`,
			token: this.bearer,
			account: this.store.current?.label ?? null,
			pid: process.pid,
		};
		const json = JSON.stringify(payload, null, 2);

		const targets: string[] = [];
		for (const folder of vscode.workspace.workspaceFolders ?? []) {
			if (folder.uri.scheme !== 'file') { continue; }
			targets.push(path.join(folder.uri.fsPath, DISCOVERY_DIRNAME, DISCOVERY_FILENAME));
		}
		// User-scope fallback for non-workspace test runs.
		const machineId = vscode.env.machineId.replace(/[^a-zA-Z0-9._-]/g, '_');
		targets.push(path.join(USER_DISCOVERY_DIR, `${machineId}.json`));

		// Forget files we used to write but don't anymore (e.g. workspace folder removed).
		const previous = new Set(this.discoveryFiles);
		this.discoveryFiles.length = 0;

		for (const target of targets) {
			try {
				await fs.promises.mkdir(path.dirname(target), { recursive: true });
				await fs.promises.writeFile(target, json, { mode: 0o600 });
				this.discoveryFiles.push(target);
				previous.delete(target);
			} catch (err) {
				this.log.warn(`failed writing discovery file ${target}: ${formatError(err)}`);
			}
		}

		for (const stale of previous) {
			try { await fs.promises.unlink(stale); } catch { /* ignore */ }
		}
	}

	/**
	 * Register a PowerShell token-provider script in the Visual Studio IdentityService
	 * token-provider file (%LOCALAPPDATA%\.IdentityService\AzureServiceAuth\tokenprovider.json).
	 * This lets any .NET project that uses DefaultAzureCredential / VisualStudioCredential
	 * obtain tokens through this extension without installing a NuGet package.
	 */
	private async writeVisualStudioTokenProvider(): Promise<void> {
		if (!VS_TOKEN_PROVIDER_FILE || !VS_IDENTITY_SERVICE_DIR) { return; }

		const scriptPath = path.join(this.extensionPath, 'bin', 'tokenProvider.ps1');
		// Quote the path so spaces survive the space-joined Arguments string that
		// Azure.Identity builds internally before passing to ProcessStartInfo.Arguments.
		const quotedScript = `"${scriptPath.replace(/"/g, '\\"')}"`;

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const newEntry: Record<string, any> = {
			Path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
			Arguments: ['-NonInteractive', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', quotedScript],
			Preference: 0,
			[VS_PROVIDER_MARKER]: true,   // custom field; ignored by Azure.Identity, used by us
		};

		let providers: Record<string, unknown>[] = [];
		try {
			const existing = await fs.promises.readFile(VS_TOKEN_PROVIDER_FILE, 'utf8');
			const parsed = JSON.parse(existing) as { TokenProviders?: Record<string, unknown>[] };
			if (Array.isArray(parsed?.TokenProviders)) {
				providers = parsed.TokenProviders;
			}
		} catch { /* file missing or malformed – start fresh */ }

		// Remove any stale entry we wrote previously, then prepend the current one.
		providers = providers.filter(p => p[VS_PROVIDER_MARKER] !== true);
		providers.unshift(newEntry);

		try {
			await fs.promises.mkdir(VS_IDENTITY_SERVICE_DIR, { recursive: true });
			await fs.promises.writeFile(
				VS_TOKEN_PROVIDER_FILE,
				JSON.stringify({ TokenProviders: providers }, null, 2),
				{ mode: 0o600 },
			);
			this.log.info(`Registered VS IdentityService token provider at ${VS_TOKEN_PROVIDER_FILE}`);
		} catch (err) {
			this.log.warn(`Failed to write VS IdentityService token provider: ${formatError(err)}`);
		}
	}

	/** Remove our entry from the VS IdentityService token-provider file on shutdown. */
	private async removeVisualStudioTokenProvider(): Promise<void> {
		if (!VS_TOKEN_PROVIDER_FILE) { return; }
		try {
			const existing = await fs.promises.readFile(VS_TOKEN_PROVIDER_FILE, 'utf8');
			const parsed = JSON.parse(existing) as { TokenProviders?: Record<string, unknown>[] };
			if (!Array.isArray(parsed?.TokenProviders)) { return; }
			const filtered = parsed.TokenProviders.filter(p => p[VS_PROVIDER_MARKER] !== true);
			await fs.promises.writeFile(
				VS_TOKEN_PROVIDER_FILE,
				JSON.stringify({ TokenProviders: filtered }, null, 2),
				{ mode: 0o600 },
			);
		} catch { /* ignore – best effort */ }
	}

	private async removeDiscoveryFiles(): Promise<void> {
		for (const f of this.discoveryFiles) {
			try { await fs.promises.unlink(f); } catch { /* ignore */ }
		}
		this.discoveryFiles.length = 0;
	}
}

function reply(res: http.ServerResponse, status: number, body: object): void {
	const json = JSON.stringify(body);
	res.writeHead(status, {
		'Content-Type': 'application/json; charset=utf-8',
		'Content-Length': Buffer.byteLength(json),
		'Cache-Control': 'no-store',
	});
	res.end(json);
}

function readJson<T>(req: http.IncomingMessage): Promise<T | undefined> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		let total = 0;
		req.on('data', c => {
			chunks.push(c);
			total += c.length;
			// Hard cap to avoid memory abuse from a misbehaving client.
			if (total > 64 * 1024) {
				req.destroy(new Error('payload_too_large'));
			}
		});
		req.on('end', () => {
			if (chunks.length === 0) { return resolve(undefined); }
			try {
				resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as T);
			} catch (err) {
				reject(err);
			}
		});
		req.on('error', reject);
	});
}

function formatError(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
