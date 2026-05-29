import type { IDataObject, IExecuteFunctions } from 'n8n-workflow';

import type { MeshConnection, SharedConnection } from '../shared/ConnectionManager';
import { bytesToHex, hexToBytes, normalizeBytesDeep } from '../shared/params';
import { PushCodes, TxtTypes } from '../shared/codes';

/**
 * One action-node operation. Reads its parameters from the execution context for the
 * given item, runs the command against the (serialized) shared connection, and returns
 * the JSON to emit (a single object or an array of objects).
 */
export type OperationHandler = (
	conn: SharedConnection,
	ctx: IExecuteFunctions,
	itemIndex: number,
) => Promise<IDataObject | IDataObject[]>;

/**
 * Invoke a meshcore.js high-level method by name, serialized through the shared
 * connection's command queue. Throws a clear error if the installed meshcore.js does
 * not implement it (the coverage gaps that need a protocol extension — see CLAUDE.md §8).
 */
function call<T = unknown>(conn: SharedConnection, method: string, ...args: unknown[]): Promise<T> {
	return conn
		.run((c: MeshConnection) => {
			const fn = (c as Record<string, unknown>)[method];
			if (typeof fn !== 'function') {
				throw new Error(`meshcore.js does not implement "${method}" (needs a protocol extension)`);
			}
			return (fn as (...a: unknown[]) => Promise<T>).apply(c, args);
		})
		.catch((error: unknown) => {
			// meshcore.js rejects with `undefined` on a device ERR response; turn that
			// (and any non-Error rejection) into an actionable message for the user.
			if (error instanceof Error) {
				throw error;
			}
			throw new Error(
				`MeshCore "${method}" failed: the device returned an error or did not respond`,
			);
		});
}

/** Parse an optional hex field; empty string yields an empty byte buffer. */
function optionalHex(value: string): Buffer {
	const trimmed = value.trim();
	return trimmed ? hexToBytes(trimmed) : Buffer.alloc(0);
}

function asObject(value: unknown): IDataObject {
	const normalized = normalizeBytesDeep(value);
	if (normalized && typeof normalized === 'object' && !Array.isArray(normalized)) {
		return normalized as IDataObject;
	}
	return { result: normalized ?? null };
}

function asObjectArray(value: unknown): IDataObject[] {
	return Array.isArray(value) ? value.map(asObject) : [asObject(value)];
}

/**
 * Normalize a contact: meshcore returns `outPath` as a fixed 64-byte buffer regardless of
 * `outPathLen`, so truncate it to the real path length before hex-encoding.
 */
function contactJson(contact: unknown): IDataObject {
	if (contact && typeof contact === 'object') {
		const c = { ...(contact as Record<string, unknown>) };
		const len = Number(c.outPathLen);
		const path = c.outPath;
		if ((path instanceof Uint8Array || Array.isArray(path)) && Number.isFinite(len)) {
			c.outPath = Buffer.from(path as Uint8Array).subarray(0, Math.max(0, len));
		}
		return asObject(c);
	}
	return asObject(contact);
}

/** Result for fire-and-confirm commands that resolve with no payload (OK response). */
const OK: IDataObject = { success: true };

const str = (ctx: IExecuteFunctions, name: string, i: number): string =>
	ctx.getNodeParameter(name, i) as string;
const num = (ctx: IExecuteFunctions, name: string, i: number): number =>
	Number(ctx.getNodeParameter(name, i));

/**
 * Resolve with the first incoming direct message from `targetPublicKey` (matched by the
 * 6-byte sender prefix) within the timeout, else null. Arm this BEFORE sending so a fast
 * reply is not missed. Uses the connection's shared message-hub.
 */
function awaitReply(
	conn: SharedConnection,
	targetPublicKey: Buffer,
	timeoutMs: number,
): Promise<IDataObject | null> {
	const prefixHex = bytesToHex(targetPublicKey.subarray(0, 6));
	return new Promise((resolve) => {
		let done = false;
		const finish = (value: IDataObject | null) => {
			if (done) {
				return;
			}
			done = true;
			clearTimeout(timer);
			unsubscribe();
			resolve(value);
		};
		const unsubscribe = conn.subscribeMessages((message) => {
			const contactMessage = (message as { contactMessage?: { pubKeyPrefix?: unknown } })?.contactMessage;
			if (!contactMessage?.pubKeyPrefix) {
				return;
			}
			if (bytesToHex(contactMessage.pubKeyPrefix as Uint8Array) === prefixHex) {
				finish(normalizeBytesDeep(contactMessage) as IDataObject);
			}
		});
		const timer = setTimeout(() => finish(null), timeoutMs);
	});
}

/** Dispatch table keyed by `${resource}:${operation}`. */
export const operations: Record<string, OperationHandler> = {
	// --- Device ---------------------------------------------------------------
	'device:getSelfInfo': async (conn) => asObject(await call(conn, 'getSelfInfo', 10000)),
	'device:getDeviceTime': async (conn) => asObject(await call(conn, 'getDeviceTime')),
	'device:setDeviceTime': async (conn, ctx, i) => {
		const epoch = num(ctx, 'epochSeconds', i) || Math.floor(Date.now() / 1000);
		await call(conn, 'setDeviceTime', epoch);
		return { ...OK, epochSeconds: epoch };
	},
	'device:syncDeviceTime': async (conn) => {
		await call(conn, 'syncDeviceTime');
		return OK;
	},
	'device:getBatteryVoltage': async (conn) => asObject(await call(conn, 'getBatteryVoltage')),
	'device:setAdvertName': async (conn, ctx, i) => {
		await call(conn, 'setAdvertName', str(ctx, 'name', i));
		return OK;
	},
	'device:setAdvertLatLong': async (conn, ctx, i) => {
		await call(conn, 'setAdvertLatLong', num(ctx, 'latitude', i), num(ctx, 'longitude', i));
		return OK;
	},
	'device:setTxPower': async (conn, ctx, i) => {
		await call(conn, 'setTxPower', num(ctx, 'txPower', i));
		return OK;
	},
	'device:reboot': async (conn) => {
		await call(conn, 'reboot');
		return OK;
	},
	'device:getStats': async (conn, ctx, i) => asObject(await call(conn, 'getStats', num(ctx, 'statsType', i))),
	'device:setDevicePin': async (conn, ctx, i) => {
		await call(conn, 'setDevicePin', num(ctx, 'pin', i));
		return OK;
	},
	'device:getCustomVars': async (conn) => asObject(await call(conn, 'getCustomVars')),
	'device:setCustomVar': async (conn, ctx, i) => {
		await call(conn, 'setCustomVar', str(ctx, 'varName', i), str(ctx, 'varValue', i));
		return OK;
	},
	'device:getTuningParams': async (conn) => asObject(await call(conn, 'getTuningParams')),
	'device:getAllowedRepeatFreq': async (conn) => asObject(await call(conn, 'getAllowedRepeatFreq')),
	'device:setPathHashMode': async (conn, ctx, i) => {
		await call(conn, 'setPathHashMode', num(ctx, 'pathHashMode', i));
		return OK;
	},
	'device:getAutoAddConfig': async (conn) => asObject(await call(conn, 'getAutoAddConfig')),
	'device:setAutoAddConfig': async (conn, ctx, i) => {
		await call(conn, 'setAutoAddConfig', num(ctx, 'autoAddConfig', i), num(ctx, 'autoAddMaxHops', i));
		return OK;
	},
	'device:factoryReset': async (conn, ctx, i) => {
		if (ctx.getNodeParameter('confirm', i) !== true) {
			throw new Error('Factory reset requires the "Confirm" toggle to be enabled');
		}
		return asObject(await call(conn, 'factoryReset'));
	},

	// --- Contact --------------------------------------------------------------
	'contact:getAll': async (conn) => {
		const contacts = (await call<unknown[]>(conn, 'getContacts')) ?? [];
		return contacts.map(contactJson);
	},
	'contact:findByName': async (conn, ctx, i) => {
		const contact = await call(conn, 'findContactByName', str(ctx, 'name', i));
		return contact ? contactJson(contact) : { found: false };
	},
	'contact:findByPublicKeyPrefix': async (conn, ctx, i) => {
		const contact = await call(conn, 'findContactByPublicKeyPrefix', hexToBytes(str(ctx, 'publicKeyPrefix', i)));
		return contact ? contactJson(contact) : { found: false };
	},
	'contact:remove': async (conn, ctx, i) => {
		await call(conn, 'removeContact', hexToBytes(str(ctx, 'publicKey', i)));
		return OK;
	},
	'contact:share': async (conn, ctx, i) => {
		await call(conn, 'shareContact', hexToBytes(str(ctx, 'publicKey', i)));
		return OK;
	},
	'contact:export': async (conn, ctx, i) => {
		const hex = str(ctx, 'exportPublicKey', i).trim();
		const arg = hex ? hexToBytes(hex) : null;
		return asObject(await call(conn, 'exportContact', arg));
	},
	'contact:import': async (conn, ctx, i) => {
		await call(conn, 'importContact', hexToBytes(str(ctx, 'advertPacket', i)));
		return OK;
	},
	'contact:resetPath': async (conn, ctx, i) => {
		await call(conn, 'resetPath', hexToBytes(str(ctx, 'publicKey', i)));
		return OK;
	},
	'contact:addOrUpdate': async (conn, ctx, i) => {
		const publicKey = hexToBytes(str(ctx, 'publicKey', i));
		const outPath = optionalHex(str(ctx, 'outPath', i));
		await call(
			conn,
			'addOrUpdateContact',
			publicKey,
			num(ctx, 'type', i),
			num(ctx, 'flags', i),
			outPath.length,
			outPath,
			str(ctx, 'name', i),
			num(ctx, 'lastAdvert', i),
			num(ctx, 'latitude', i),
			num(ctx, 'longitude', i),
		);
		return OK;
	},
	'contact:setPath': async (conn, ctx, i) => {
		const publicKey = hexToBytes(str(ctx, 'publicKey', i));
		const contact = await call(conn, 'findContactByPublicKeyPrefix', publicKey);
		if (!contact) {
			return { found: false };
		}
		await call(conn, 'setContactPath', contact, hexToBytes(str(ctx, 'path', i)));
		return OK;
	},
	'contact:getByKey': async (conn, ctx, i) => {
		const contact = await call(conn, 'getContactByKey', hexToBytes(str(ctx, 'publicKey', i)));
		return contact ? contactJson(contact) : { found: false };
	},
	'contact:getAdvertPath': async (conn, ctx, i) => {
		const path = await call(conn, 'getAdvertPath', hexToBytes(str(ctx, 'publicKey', i)));
		return path ? asObject(path) : { found: false };
	},

	// --- Message --------------------------------------------------------------
	'message:sendDirect': async (conn, ctx, i) => {
		const publicKey = hexToBytes(str(ctx, 'contactPublicKey', i));
		const txtType = Number(ctx.getNodeParameter('txtType', i, TxtTypes.Plain));
		const result = await call(conn, 'sendTextMessage', publicKey, str(ctx, 'message', i), txtType);
		return result ? asObject(result) : { sent: true };
	},
	'message:sendDirectAwaitDelivery': async (conn, ctx, i) => {
		const publicKey = hexToBytes(str(ctx, 'contactPublicKey', i));
		const txtType = Number(ctx.getNodeParameter('txtType', i, TxtTypes.Plain));
		const timeoutMs = num(ctx, 'ackTimeoutMs', i) || 15000;
		// arm the ack listener BEFORE sending so a fast confirmation is not missed
		const expect = conn.expectPush<{ ackCode: number; roundTrip: number }>(PushCodes.SendConfirmed);
		try {
			const sent = (await call(conn, 'sendTextMessage', publicKey, str(ctx, 'message', i), txtType)) as {
				expectedAckCrc?: number;
			};
			const ackCode = Number(sent?.expectedAckCrc);
			const confirmed = await expect.match((p) => p.ackCode === ackCode, timeoutMs);
			return {
				...asObject(sent),
				ackCode,
				delivered: confirmed !== null,
				roundTrip: confirmed?.roundTrip ?? null,
			};
		} finally {
			expect.cancel(); // no-op if already matched/timed out
		}
	},
	'message:awaitDelivery': async (conn, ctx, i) => {
		const ackCode = num(ctx, 'ackCode', i);
		const timeoutMs = num(ctx, 'ackTimeoutMs', i) || 15000;
		const expect = conn.expectPush<{ ackCode: number; roundTrip: number }>(PushCodes.SendConfirmed);
		const confirmed = await expect.match((p) => p.ackCode === ackCode, timeoutMs);
		return { ackCode, delivered: confirmed !== null, roundTrip: confirmed?.roundTrip ?? null };
	},
	'message:sendChannel': async (conn, ctx, i) => {
		await call(conn, 'sendChannelTextMessage', num(ctx, 'channelIdx', i), str(ctx, 'message', i));
		return OK;
	},
	'message:sendDirectAwaitReply': async (conn, ctx, i) => {
		const publicKey = hexToBytes(str(ctx, 'contactPublicKey', i));
		const txtType = Number(ctx.getNodeParameter('txtType', i, TxtTypes.Plain));
		const timeoutMs = num(ctx, 'replyTimeoutMs', i) || 30000;
		const replyPromise = awaitReply(conn, publicKey, timeoutMs); // arm before sending
		const sent = await call(conn, 'sendTextMessage', publicKey, str(ctx, 'message', i), txtType);
		const reply = await replyPromise;
		return { ...asObject(sent), replied: reply !== null, reply: reply ?? null };
	},
	'message:getWaiting': async (conn) => asObjectArray(await call(conn, 'getWaitingMessages')),
	'message:syncNext': async (conn) => {
		const message = await call(conn, 'syncNextMessage');
		return message ? asObject(message) : { noMoreMessages: true };
	},

	// --- Channel --------------------------------------------------------------
	'channel:get': async (conn, ctx, i) => asObject(await call(conn, 'getChannel', num(ctx, 'channelIdx', i))),
	'channel:getAll': async (conn) => {
		const channels = (await call<unknown[]>(conn, 'getChannels')) ?? [];
		// drop unconfigured slots (firmware returns fixed slots with an empty name)
		const configured = channels.filter((ch) => {
			const name = (ch as { name?: unknown })?.name;
			return typeof name === 'string' && name.length > 0;
		});
		return configured.map(asObject);
	},
	'channel:set': async (conn, ctx, i) => {
		await call(conn, 'setChannel', num(ctx, 'channelIdx', i), str(ctx, 'name', i), hexToBytes(str(ctx, 'secret', i)));
		return OK;
	},
	'channel:delete': async (conn, ctx, i) => {
		await call(conn, 'deleteChannel', num(ctx, 'channelIdx', i));
		return OK;
	},
	'channel:findByName': async (conn, ctx, i) => {
		const channel = await call(conn, 'findChannelByName', str(ctx, 'name', i));
		return channel ? asObject(channel) : { found: false };
	},
	'channel:findBySecret': async (conn, ctx, i) => {
		const channel = await call(conn, 'findChannelBySecret', hexToBytes(str(ctx, 'secret', i)));
		return channel ? asObject(channel) : { found: false };
	},
	'channel:sendData': async (conn, ctx, i) => {
		const path = optionalHex(str(ctx, 'path', i));
		const payload = hexToBytes(str(ctx, 'payload', i));
		await call(conn, 'sendChannelData', num(ctx, 'channelIdx', i), path.length, path, num(ctx, 'dataType', i), payload);
		return OK;
	},

	// --- Advert ---------------------------------------------------------------
	'advert:flood': async (conn) => {
		await call(conn, 'sendFloodAdvert');
		return OK;
	},
	'advert:zeroHop': async (conn) => {
		await call(conn, 'sendZeroHopAdvert');
		return OK;
	},

	// --- Diagnostics ----------------------------------------------------------
	'diagnostics:getStatus': async (conn, ctx, i) =>
		asObject(await call(conn, 'getStatus', hexToBytes(str(ctx, 'contactPublicKey', i)))),
	'diagnostics:getTelemetry': async (conn, ctx, i) =>
		asObject(await call(conn, 'getTelemetry', hexToBytes(str(ctx, 'contactPublicKey', i)))),
	'diagnostics:tracePath': async (conn, ctx, i) =>
		asObject(await call(conn, 'tracePath', optionalHex(str(ctx, 'path', i)), num(ctx, 'extraTimeoutMillis', i))),
	'diagnostics:getNeighbours': async (conn, ctx, i) =>
		asObject(
			await call(
				conn,
				'getNeighbours',
				hexToBytes(str(ctx, 'contactPublicKey', i)),
				num(ctx, 'count', i),
				num(ctx, 'offset', i),
				num(ctx, 'orderBy', i),
				num(ctx, 'pubKeyPrefixLength', i),
			),
		),
	'diagnostics:sendBinaryRequest': async (conn, ctx, i) => {
		const responseData = await call<Uint8Array>(
			conn,
			'sendBinaryRequest',
			hexToBytes(str(ctx, 'contactPublicKey', i)),
			hexToBytes(str(ctx, 'requestData', i)),
			num(ctx, 'extraTimeoutMillis', i),
		);
		return { responseData: bytesToHex(responseData) };
	},
	'diagnostics:sendPathDiscovery': async (conn, ctx, i) =>
		asObject(await call(conn, 'sendPathDiscoveryReq', hexToBytes(str(ctx, 'contactPublicKey', i)))),
	'diagnostics:discoverPath': async (conn, ctx, i) => {
		const publicKey = hexToBytes(str(ctx, 'contactPublicKey', i));
		const prefixHex = bytesToHex(publicKey.subarray(0, 6));
		const timeoutMs = num(ctx, 'resultTimeoutMs', i) || 30000;
		const expect = conn.expectPush<{ pubKeyPrefix: string }>(PushCodes.PathDiscoveryResponse);
		try {
			await call(conn, 'sendPathDiscoveryReq', publicKey);
			const result = await expect.match((p) => p.pubKeyPrefix === prefixHex, timeoutMs);
			return result ? asObject(result) : { found: false };
		} finally {
			expect.cancel(); // no-op if already matched/timed out
		}
	},
	'diagnostics:awaitEvent': async (conn, ctx, i) => {
		const code = num(ctx, 'pushCode', i);
		const timeoutMs = num(ctx, 'resultTimeoutMs', i) || 30000;
		const result = await conn.expectPush(code).match(() => true, timeoutMs);
		return result ? asObject(result) : { received: false };
	},

	// --- Repeater -------------------------------------------------------------
	'repeater:login': async (conn, ctx, i) =>
		asObject(await call(conn, 'login', hexToBytes(str(ctx, 'contactPublicKey', i)), str(ctx, 'password', i))),
	'repeater:sign': async (conn, ctx, i) => {
		const signature = await call<Uint8Array>(conn, 'sign', hexToBytes(str(ctx, 'data', i)));
		return { signature: bytesToHex(signature) };
	},
	'repeater:hasConnection': async (conn, ctx, i) =>
		asObject(await call(conn, 'hasConnection', hexToBytes(str(ctx, 'contactPublicKey', i)))),
	'repeater:logout': async (conn, ctx, i) => {
		await call(conn, 'logout', hexToBytes(str(ctx, 'contactPublicKey', i)));
		return OK;
	},
	'repeater:sendAnonReq': async (conn, ctx, i) =>
		asObject(
			await call(
				conn,
				'sendAnonReq',
				hexToBytes(str(ctx, 'contactPublicKey', i)),
				hexToBytes(str(ctx, 'requestData', i)),
			),
		),
	'repeater:sendControlData': async (conn, ctx, i) => {
		await call(conn, 'sendControlData', hexToBytes(str(ctx, 'controlData', i)));
		return OK;
	},
	'repeater:sendCliCommand': async (conn, ctx, i) => {
		const publicKey = hexToBytes(str(ctx, 'contactPublicKey', i));
		const timeoutMs = num(ctx, 'replyTimeoutMs', i) || 30000;
		const replyPromise = awaitReply(conn, publicKey, timeoutMs); // arm before sending
		await call(conn, 'sendTextMessage', publicKey, str(ctx, 'command', i), TxtTypes.CliData);
		const reply = await replyPromise;
		return { replied: reply !== null, response: reply ?? null };
	},

	// --- Flood Scope ----------------------------------------------------------
	'floodScope:set': async (conn, ctx, i) => {
		await call(conn, 'setFloodScope', hexToBytes(str(ctx, 'transportKey', i)));
		return OK;
	},
	'floodScope:clear': async (conn) => {
		await call(conn, 'clearFloodScope');
		return OK;
	},
	'floodScope:getDefault': async (conn) => asObject(await call(conn, 'getDefaultFloodScope')),
	'floodScope:setDefault': async (conn, ctx, i) => {
		await call(conn, 'setDefaultFloodScope', str(ctx, 'scopeName', i), hexToBytes(str(ctx, 'transportKey', i)));
		return OK;
	},
};
