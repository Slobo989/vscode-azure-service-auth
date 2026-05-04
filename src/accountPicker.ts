import * as vscode from 'vscode';
import { PROVIDER_ID, SelectedAccount, SelectedAccountStore } from './state';

// A minimal default scope just to surface a sign-in prompt; tokens for real
// resources are acquired on-demand by the broker using the actual scopes.
const DEFAULT_SIGN_IN_SCOPES = ['https://management.azure.com/.default'];

interface AccountQuickPickItem extends vscode.QuickPickItem {
	account?: vscode.AuthenticationSessionAccountInformation;
	action?: 'add' | 'clear';
}

export async function pickAccount(store: SelectedAccountStore): Promise<void> {
	const accounts = await vscode.authentication.getAccounts(PROVIDER_ID);
	const current = store.current;

	const items: AccountQuickPickItem[] = accounts.map(a => ({
		label: a.label,
		description: current?.id === a.id ? '(selected)' : undefined,
		account: a,
	}));

	items.push({ label: '', kind: vscode.QuickPickItemKind.Separator });
	items.push({
		label: '$(add) Sign in to another account…',
		action: 'add',
	});
	if (current) {
		items.push({
			label: '$(clear-all) Clear selection',
			action: 'clear',
		});
	}

	const picked = await vscode.window.showQuickPick(items, {
		title: 'Azure Service Authentication',
		placeHolder: 'Choose a Microsoft account for tests and Azure SDK calls',
		ignoreFocusOut: true,
	});

	if (!picked) {
		return;
	}

	if (picked.action === 'clear') {
		await store.set(undefined);
		return;
	}

	if (picked.action === 'add') {
		try {
			const session = await vscode.authentication.getSession(
				PROVIDER_ID,
				DEFAULT_SIGN_IN_SCOPES,
				{ createIfNone: true, clearSessionPreference: true },
			);
			await store.set({ id: session.account.id, label: session.account.label });
		} catch (err) {
			vscode.window.showErrorMessage(`Sign-in cancelled or failed: ${formatError(err)}`);
		}
		return;
	}

	if (picked.account) {
		const acc: SelectedAccount = { id: picked.account.id, label: picked.account.label };
		await store.set(acc);
	}
}

function formatError(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
