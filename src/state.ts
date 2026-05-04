import * as vscode from 'vscode';

export const PROVIDER_ID = 'microsoft';
const STATE_KEY = 'azureServiceAuth.selectedAccount';

export interface SelectedAccount {
	id: string;
	label: string;
}

export class SelectedAccountStore {
	private readonly _onDidChange = new vscode.EventEmitter<SelectedAccount | undefined>();
	readonly onDidChange = this._onDidChange.event;

	constructor(private readonly context: vscode.ExtensionContext) {}

	get current(): SelectedAccount | undefined {
		return this.context.globalState.get<SelectedAccount>(STATE_KEY);
	}

	async set(account: SelectedAccount | undefined): Promise<void> {
		await this.context.globalState.update(STATE_KEY, account);
		this._onDidChange.fire(account);
	}

	dispose(): void {
		this._onDidChange.dispose();
	}
}
