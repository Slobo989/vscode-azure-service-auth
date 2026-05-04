import * as vscode from 'vscode';
import { SelectedAccountStore } from './state';

export class StatusBar {
	private readonly item: vscode.StatusBarItem;

	constructor(private readonly store: SelectedAccountStore) {
		this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
		this.item.command = 'azureServiceAuth.selectAccount';
		this.item.tooltip = 'Select the Microsoft account used by Azure SDK during tests';
		this.refresh();
		this.item.show();
		store.onDidChange(() => this.refresh());
	}

	refresh(): void {
		const current = this.store.current;
		if (current) {
			this.item.text = `$(azure) ${current.label}`;
		} else {
			this.item.text = '$(azure) Sign in to Azure';
		}
	}

	dispose(): void {
		this.item.dispose();
	}
}
