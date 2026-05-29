import type {
	IDataObject,
	ITriggerFunctions,
	INodeType,
	INodeTypeDescription,
	ITriggerResponse,
} from 'n8n-workflow';
import { NodeConnectionTypes } from 'n8n-workflow';

import { ConnectionManager } from '../shared/ConnectionManager';
import { meshCoreTcpApiTest } from '../shared/credentialTest';
import { normalizeBytesDeep } from '../shared/params';
import { eventOptions, startSubscriptions } from './events';
import type { EmitFn } from './messageStream';

export class MeshCoreTrigger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'MeshCore Trigger',
		name: 'meshCoreTrigger',
		icon: { light: 'file:../../icons/meshcore.svg', dark: 'file:../../icons/meshcore.dark.svg' },
		group: ['trigger'],
		version: 1,
		subtitle: '={{ $parameter["events"] }}',
		description: 'Starts a workflow on MeshCore device events',
		defaults: {
			name: 'MeshCore Trigger',
		},
		inputs: [],
		outputs: [NodeConnectionTypes.Main],
		usableAsTool: true,
		credentials: [
			{
				name: 'meshCoreTcpApi',
				required: true,
				testedBy: 'meshCoreTcpApiTest',
			},
		],
		properties: [
			{
				displayName: 'Events',
				name: 'events',
				type: 'multiOptions',
				options: eventOptions,
				default: ['directMessage'],
				required: true,
			},
		],
	};

	methods = {
		credentialTest: {
			meshCoreTcpApiTest,
		},
	};

	async trigger(this: ITriggerFunctions): Promise<ITriggerResponse> {
		const credentials = await this.getCredentials('meshCoreTcpApi');
		const host = (credentials.host as string)?.trim();
		const port = Number(credentials.port) || 5000;
		const events = this.getNodeParameter('events', []) as string[];

		const connection = await ConnectionManager.acquire({ host, port });

		const emit: EmitFn = (event: string, payload: IDataObject) => {
			const json = normalizeBytesDeep({ event, ...payload }) as IDataObject;
			this.emit([this.helpers.returnJsonArray([json])]);
		};

		const unsubscribers = startSubscriptions(connection, events, emit);

		const closeFunction = async () => {
			for (const unsubscribe of unsubscribers) {
				unsubscribe();
			}
			ConnectionManager.release(connection);
		};

		// Arm only; queued messages are drained by the hub on subscribe, and live events
		// emit as they arrive. closeFunction hard-stops so the editor's "Stop" never hangs.
		const manualTriggerFunction = async () => {};

		return { closeFunction, manualTriggerFunction };
	}
}
