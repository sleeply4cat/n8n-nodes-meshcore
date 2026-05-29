import type { IDataObject } from 'n8n-workflow';

import type { SharedConnection } from '../shared/ConnectionManager';

/** Emit a tagged event payload (the trigger wires this to this.emit). */
export type EmitFn = (event: string, payload: IDataObject) => void;

/**
 * Maps the key in a drained message envelope (from syncNextMessage) to the trigger
 * event it should fire. Direct messages arrive as `{contactMessage}`, channel text as
 * `{channelMessage}`, channel binary as `{channelData}`.
 */
export const MESSAGE_KEY_TO_EVENT: Record<string, string> = {
	contactMessage: 'directMessage',
	channelMessage: 'channelMessage',
	channelData: 'channelData',
};

/** Emit a single drained message under its matching event, if that type is selected. */
export function routeMessage(message: unknown, messageTypes: string[], emit: EmitFn): void {
	if (!message || typeof message !== 'object') {
		return;
	}
	for (const [key, event] of Object.entries(MESSAGE_KEY_TO_EVENT)) {
		const inner = (message as Record<string, unknown>)[key];
		if (inner && messageTypes.includes(event)) {
			emit(event, inner as IDataObject);
		}
	}
}

/**
 * Stream inbound messages to `emit`, routed by type. Registers with the connection's
 * shared message-hub (a single MSG_WAITING drainer fans out to all consumers), so
 * multiple message triggers / await-reply waiters never race over the queue. Returns an
 * unsubscribe function.
 */
export function startMessageStream(
	conn: SharedConnection,
	messageTypes: string[],
	emit: EmitFn,
): () => void {
	return conn.subscribeMessages((message) => routeMessage(message, messageTypes, emit));
}
