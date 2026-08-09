import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

import { ConnectionManager } from '../shared/ConnectionManager';
import type { SharedConnection } from '../shared/ConnectionManager';
import { meshCoreTcpApiTest } from '../shared/credentialTest';
import { operations } from './operations';
import { properties } from './properties';
import { offlineOperations } from './utilities';

export class MeshCore implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'MeshCore',
		name: 'meshCore',
		icon: { light: 'file:../../icons/meshcore.svg', dark: 'file:../../icons/meshcore.dark.svg' },
		group: ['transform'],
		version: 1,
		subtitle: '={{ $parameter["operation"] + ": " + $parameter["resource"] }}',
		description: 'Interact with a MeshCore device over TCP/WiFi',
		defaults: {
			name: 'MeshCore',
		},
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		usableAsTool: true,
		credentials: [
			{
				name: 'meshCoreTcpApi',
				// Not required: the Utilities operations encode and decode packets without a
				// device, and demanding credentials for them would be noise. Every other
				// resource asks for the connection lazily and fails clearly without it.
				required: false,
				testedBy: 'meshCoreTcpApiTest',
			},
		],
		properties,
	};

	methods = {
		credentialTest: {
			meshCoreTcpApiTest,
		},
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		// Acquired on first use, so a workflow that only encodes or decodes never opens a
		// socket — and never kicks a running trigger off the radio (one TCP client only).
		let connection: SharedConnection | null = null;
		const connect = async (): Promise<SharedConnection> => {
			if (!connection) {
				const credentials = await this.getCredentials('meshCoreTcpApi');
				const host = (credentials.host as string)?.trim();
				const port = Number(credentials.port) || 5000;
				connection = await ConnectionManager.acquire({ host, port });
			}
			return connection;
		};

		try {
			for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
				try {
					const resource = this.getNodeParameter('resource', itemIndex) as string;
					const operation = this.getNodeParameter('operation', itemIndex) as string;
					const key = `${resource}:${operation}`;

					const offline = offlineOperations[key];
					if (offline) {
						const json = await offline(this, itemIndex);
						// null means the item was filtered out and emits nothing
						if (json) {
							returnData.push({ json, pairedItem: itemIndex });
						}
						continue;
					}

					const handler = operations[key];
					if (!handler) {
						throw new NodeOperationError(
							this.getNode(),
							`Unsupported operation "${resource}: ${operation}"`,
							{ itemIndex },
						);
					}

					const result = await handler(await connect(), this, itemIndex);
					const rows = Array.isArray(result) ? result : [result];
					for (const json of rows) {
						returnData.push({ json, pairedItem: itemIndex });
					}
				} catch (error) {
					if (this.continueOnFail()) {
						returnData.push({
							json: items[itemIndex].json,
							error: error as NodeOperationError,
							pairedItem: itemIndex,
						});
						continue;
					}
					throw new NodeOperationError(this.getNode(), error as Error, { itemIndex });
				}
			}
		} finally {
			if (connection) {
				ConnectionManager.release(connection);
			}
		}

		return [returnData];
	}
}
