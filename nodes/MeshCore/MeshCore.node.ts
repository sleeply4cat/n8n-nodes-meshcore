import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

import { ConnectionManager } from '../shared/ConnectionManager';
import { meshCoreTcpApiTest } from '../shared/credentialTest';
import { operations } from './operations';
import { properties } from './properties';

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
				required: true,
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

		const credentials = await this.getCredentials('meshCoreTcpApi');
		const host = (credentials.host as string)?.trim();
		const port = Number(credentials.port) || 5000;

		const connection = await ConnectionManager.acquire({ host, port });
		try {
			for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
				try {
					const resource = this.getNodeParameter('resource', itemIndex) as string;
					const operation = this.getNodeParameter('operation', itemIndex) as string;
					const handler = operations[`${resource}:${operation}`];
					if (!handler) {
						throw new NodeOperationError(
							this.getNode(),
							`Unsupported operation "${resource}: ${operation}"`,
							{ itemIndex },
						);
					}

					const result = await handler(connection, this, itemIndex);
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
			ConnectionManager.release(connection);
		}

		return [returnData];
	}
}
