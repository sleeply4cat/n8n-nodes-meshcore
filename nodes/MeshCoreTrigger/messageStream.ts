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

/**
 * The firmware prefixes every channel (group) text message with the sender's node name
 * as `"<name>: <text>"` (see BaseChatMesh::sendGroupMessage). meshcore.js surfaces that
 * whole string as `text`, so split it into the author nick and the bare message body,
 * keeping the original combined string under `rawText`. If no `": "` separator is
 * present (e.g. a message sent without the convention), `author` is empty and the body
 * equals the raw text.
 */
export function parseChannelMessage(inner: IDataObject): IDataObject {
	const rawText = typeof inner.text === 'string' ? inner.text : '';
	const sep = rawText.indexOf(': ');
	const author = sep > 0 ? rawText.slice(0, sep) : '';
	const text = sep > 0 ? rawText.slice(sep + 2) : rawText;
	return { ...inner, author, text, rawText };
}

/**
 * Firmware sets `pathLen=0xFF` on messages that were delivered along a known route
 * ("direct"). For flood-routed messages, `pathLen` is a PACKED byte (low 6 bits =
 * hop count, high 2 bits = path-hash size - 1). Surface that as `via` / `hops` and
 * drop the raw `pathLen` byte from the output (it would just be a useless 255 on
 * direct messages). The hash size is intentionally NOT emitted here: the firmware
 * does NOT include the actual path bytes in CONTACT_MSG_RECV / CHANNEL_MSG_RECV /
 * CHANNEL_DATA_RECV frames, so a hash size with no path to apply it to would be
 * misleading.
 */
function withRoutingFields(inner: IDataObject): IDataObject {
	const pathLen = Number(inner.pathLen);
	if (!Number.isFinite(pathLen)) {
		return inner;
	}
	// eslint-disable-next-line @typescript-eslint/no-unused-vars
	const { pathLen: _pathLen, ...rest } = inner;
	if (pathLen === 0xff) {
		return { ...rest, via: 'direct', hops: 0 };
	}
	return { ...rest, via: 'flood', hops: pathLen & 0x3f };
}

/** Emit a single drained message under its matching event, if that type is selected. */
export function routeMessage(message: unknown, messageTypes: string[], emit: EmitFn): void {
	if (!message || typeof message !== 'object') {
		return;
	}
	for (const [key, event] of Object.entries(MESSAGE_KEY_TO_EVENT)) {
		const inner = (message as Record<string, unknown>)[key];
		if (inner && messageTypes.includes(event)) {
			const base =
				event === 'channelMessage'
					? parseChannelMessage(inner as IDataObject)
					: (inner as IDataObject);
			emit(event, withRoutingFields(base));
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
