import * as vscode from 'vscode';
import { SelectedAccountStore, PROVIDER_ID } from './state';
import { StatusBar } from './statusBar';
import { pickAccount } from './accountPicker';
import { TokenBroker } from './broker';

let broker: TokenBroker | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
	const log = vscode.window.createOutputChannel('Azure Service Authentication', { log: true });
	context.subscriptions.push(log);

	const store = new SelectedAccountStore(context);
	context.subscriptions.push({ dispose: () => store.dispose() });

	const statusBar = new StatusBar(store);
	context.subscriptions.push(statusBar);

	context.subscriptions.push(
		vscode.commands.registerCommand('azureServiceAuth.selectAccount', () => pickAccount(store)),
		vscode.commands.registerCommand('azureServiceAuth.signOut', () => store.set(undefined)),
	);

	// Clear the selection if the chosen account disappears from VS Code.
	context.subscriptions.push(
		vscode.authentication.onDidChangeSessions(async e => {
			if (e.provider.id !== PROVIDER_ID) { return; }
			const current = store.current;
			if (!current) { return; }
			const accounts = await vscode.authentication.getAccounts(PROVIDER_ID);
			if (!accounts.some(a => a.id === current.id)) {
				await store.set(undefined);
			}
		}),
	);

	broker = new TokenBroker(store, log, context.extensionPath);
	try {
		await broker.start();
	} catch (err) {
		log.error(`failed to start token broker: ${err instanceof Error ? err.message : String(err)}`);
		vscode.window.showErrorMessage('Azure Service Authentication: failed to start local token broker.');
	}
}

export async function deactivate(): Promise<void> {
	if (broker) {
		await broker.dispose();
		broker = undefined;
	}
}
