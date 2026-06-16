import type { IDataObject, IExecuteFunctions } from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';

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
 * Arm a reply watcher BEFORE sending, then call `wait(timeoutMs)` to bound how long to
 * wait for the first incoming direct message from `targetPublicKey` (matched by the
 * 6-byte sender prefix; meshcore.js's raw `pubKeyPrefix` field — renamed only at the
 * output normalizer). The watcher uses the shared message-hub, so concurrent triggers
 * still receive every message. Call `cancel()` if you abandon the wait (e.g. on send
 * failure) so the subscription is released.
 */
interface ReplyWatcher {
	wait(timeoutMs: number): Promise<IDataObject | null>;
	cancel(): void;
}

function startReplyWatcher(conn: SharedConnection, targetPublicKey: Buffer): ReplyWatcher {
	const prefixHex = bytesToHex(targetPublicKey.subarray(0, 6));
	let buffered: IDataObject | null = null;
	let pendingResolve: ((value: IDataObject | null) => void) | null = null;
	let cancelled = false;

	const unsubscribe = conn.subscribeMessages((message) => {
		if (cancelled) {
			return;
		}
		const contactMessage = (message as { contactMessage?: { pubKeyPrefix?: unknown } })
			?.contactMessage;
		if (!contactMessage?.pubKeyPrefix) {
			return;
		}
		if (bytesToHex(contactMessage.pubKeyPrefix as Uint8Array) !== prefixHex) {
			return;
		}
		const normalized = normalizeBytesDeep(contactMessage) as IDataObject;
		if (pendingResolve) {
			const resolve = pendingResolve;
			pendingResolve = null;
			resolve(normalized);
		} else if (buffered === null) {
			buffered = normalized;
		}
	});

	// internal teardown: just stop listening + flag. Kept separate from the public cancel
	// so the wait-resolve path can use it without re-entering its own pending-resolve.
	const teardown = () => {
		if (cancelled) {
			return;
		}
		cancelled = true;
		unsubscribe();
	};

	return {
		wait: (timeoutMs) =>
			new Promise<IDataObject | null>((resolve) => {
				if (buffered !== null) {
					const value = buffered;
					buffered = null;
					teardown();
					resolve(value);
					return;
				}
				if (cancelled) {
					resolve(null);
					return;
				}
				const timer = setTimeout(() => {
					pendingResolve = null;
					teardown();
					resolve(null);
				}, timeoutMs);
				pendingResolve = (value) => {
					clearTimeout(timer);
					teardown();
					resolve(value);
				};
			}),
		cancel: () => {
			teardown();
			if (pendingResolve) {
				const resolve = pendingResolve;
				pendingResolve = null;
				resolve(null);
			}
		},
	};
}

function awaitReply(
	conn: SharedConnection,
	targetPublicKey: Buffer,
	timeoutMs: number,
): Promise<IDataObject | null> {
	return startReplyWatcher(conn, targetPublicKey).wait(timeoutMs);
}

interface ReliableSendOptions {
	publicKey: Buffer;
	message: string;
	txtType: number;
	pathRetries: number;
	floodRetries: number;
	forceFlood: boolean;
	perAttemptTimeoutMs: number;
}

interface ReliableSendResult {
	delivered: boolean;
	ackCode: number | null;
	attempts: number;
	phase: 'path' | 'flood' | null;
	roundTrip: number | null;
	lastSent: unknown;
}

/**
 * Send a direct text message with retry policy that mirrors the MeshCore app: a path
 * phase (up to N attempts using the stored route, if any) followed by a flood phase
 * (M attempts after a path reset, since the device will keep using the cached route
 * until it's cleared). Each attempt re-arms a fresh SendConfirmed listener bound to the
 * fresh ackCode returned by sendTextMessage, then waits up to `perAttemptTimeoutMs`
 * for that specific ack. Retries fire immediately on timeout (no backoff). When
 * `forceFlood` is set, the path phase is skipped after an upfront resetPath.
 */
async function reliableSend(
	conn: SharedConnection,
	opts: ReliableSendOptions,
): Promise<ReliableSendResult> {
	const { publicKey, message, txtType, pathRetries, floodRetries, forceFlood, perAttemptTimeoutMs } =
		opts;
	let attempts = 0;
	let lastSent: unknown = null;

	const tryPhase = async (
		phase: 'path' | 'flood',
		maxAttempts: number,
	): Promise<ReliableSendResult | null> => {
		for (let i = 0; i < maxAttempts; i++) {
			attempts++;
			const expect = conn.expectPush<{ ackCode: number; roundTrip: number }>(
				PushCodes.SendConfirmed,
			);
			try {
				lastSent = await call(conn, 'sendTextMessage', publicKey, message, txtType);
				const ackCode = Number((lastSent as { expectedAckCrc?: number })?.expectedAckCrc);
				const confirmed = await expect.match((p) => p.ackCode === ackCode, perAttemptTimeoutMs);
				if (confirmed !== null) {
					return {
						delivered: true,
						ackCode,
						attempts,
						phase,
						roundTrip: confirmed.roundTrip,
						lastSent,
					};
				}
			} finally {
				expect.cancel();
			}
		}
		return null;
	};

	if (forceFlood) {
		await call(conn, 'resetPath', publicKey);
	} else if (pathRetries > 0) {
		const result = await tryPhase('path', pathRetries);
		if (result) {
			return result;
		}
		// path phase exhausted: the cached route is stale or the contact is unreachable
		// along it; clear it before falling back to flood (otherwise the device keeps
		// re-using the same dead route on the next sendTextMessage).
		await call(conn, 'resetPath', publicKey);
	}

	if (floodRetries > 0) {
		const result = await tryPhase('flood', floodRetries);
		if (result) {
			return result;
		}
	}

	return { delivered: false, ackCode: null, attempts, phase: null, roundTrip: null, lastSent };
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
		const reliableDelivery = ctx.getNodeParameter('reliableDelivery', i, false) as boolean;

		if (!reliableDelivery) {
			// fire-and-forget: one send, surface ackCode so the user can pass it to a
			// later Await Delivery without translating field names.
			const result = (await call(
				conn,
				'sendTextMessage',
				publicKey,
				str(ctx, 'message', i),
				txtType,
			)) as { expectedAckCrc?: number } | undefined;
			if (!result) {
				return { sent: true };
			}
			const ackCode = Number(result.expectedAckCrc);
			return { ...asObject(result), ackCode: Number.isFinite(ackCode) ? ackCode : null };
		}

		// reliable mode: retry along path, then flood. Throws on final non-delivery so
		// the node turns red; Continue On Fail still lets workflows branch on it as data.
		// Defaults are passed to getNodeParameter explicitly: n8n throws "Could not get
		// parameter" when a value isn't saved AND no default was supplied.
		const perAttemptTimeoutMs = Number(ctx.getNodeParameter('ackTimeoutMs', i, 15000)) || 15000;
		const pathRetries = Math.max(0, Number(ctx.getNodeParameter('pathRetries', i, 2)));
		const floodRetries = Math.max(0, Number(ctx.getNodeParameter('floodRetries', i, 2)));
		const forceFlood = ctx.getNodeParameter('forceFlood', i, false) as boolean;

		const result = await reliableSend(conn, {
			publicKey,
			message: str(ctx, 'message', i),
			txtType,
			pathRetries,
			floodRetries,
			forceFlood,
			perAttemptTimeoutMs,
		});

		if (!result.delivered) {
			throw new NodeOperationError(
				ctx.getNode(),
				`MeshCore message delivery not confirmed after ${result.attempts} attempt(s)`,
				{
					itemIndex: i,
					description: `Tried ${pathRetries} path + ${floodRetries} flood attempt(s)${forceFlood ? ' (force flood)' : ''}, ${perAttemptTimeoutMs}ms per attempt`,
				},
			);
		}

		return {
			...asObject(result.lastSent),
			ackCode: result.ackCode,
			delivered: true,
			phase: result.phase,
			attempts: result.attempts,
			roundTrip: result.roundTrip,
		};
	},
	'message:awaitDelivery': async (conn, ctx, i) => {
		const ackCode = num(ctx, 'ackCode', i);
		const timeoutMs = Number(ctx.getNodeParameter('ackTimeoutMs', i, 15000)) || 15000;
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
		const replyTimeoutMs = num(ctx, 'replyTimeoutMs', i) || 30000;
		const reliableDelivery = ctx.getNodeParameter('reliableDelivery', i, false) as boolean;
		// arm the reply watcher BEFORE any send so a fast reply during the send loop is buffered
		const watcher = startReplyWatcher(conn, publicKey);
		try {
			if (reliableDelivery) {
				const perAttemptTimeoutMs = Number(ctx.getNodeParameter('ackTimeoutMs', i, 15000)) || 15000;
				const pathRetries = Math.max(0, Number(ctx.getNodeParameter('pathRetries', i, 2)));
				const floodRetries = Math.max(0, Number(ctx.getNodeParameter('floodRetries', i, 2)));
				const forceFlood = ctx.getNodeParameter('forceFlood', i, false) as boolean;
				const send = await reliableSend(conn, {
					publicKey,
					message: str(ctx, 'message', i),
					txtType,
					pathRetries,
					floodRetries,
					forceFlood,
					perAttemptTimeoutMs,
				});
				if (!send.delivered) {
					throw new NodeOperationError(
						ctx.getNode(),
						`MeshCore message delivery not confirmed after ${send.attempts} attempt(s)`,
						{
							itemIndex: i,
							description: `Tried ${pathRetries} path + ${floodRetries} flood attempt(s)${forceFlood ? ' (force flood)' : ''}, ${perAttemptTimeoutMs}ms per attempt`,
						},
					);
				}
				const reply = await watcher.wait(replyTimeoutMs);
				return {
					...asObject(send.lastSent),
					ackCode: send.ackCode,
					delivered: true,
					phase: send.phase,
					attempts: send.attempts,
					roundTrip: send.roundTrip,
					replied: reply !== null,
					reply: reply ?? null,
				};
			}
			const sent = await call(conn, 'sendTextMessage', publicKey, str(ctx, 'message', i), txtType);
			const reply = await watcher.wait(replyTimeoutMs);
			return { ...asObject(sent), replied: reply !== null, reply: reply ?? null };
		} finally {
			watcher.cancel();
		}
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
		asObject(await call(conn, 'tracePath', optionalHex(str(ctx, 'path', i)), num(ctx, 'extraTimeoutMs', i))),
	'diagnostics:getNeighbours': async (conn, ctx, i) =>
		asObject(
			await call(
				conn,
				'getNeighbours',
				hexToBytes(str(ctx, 'contactPublicKey', i)),
				num(ctx, 'count', i),
				num(ctx, 'offset', i),
				num(ctx, 'orderBy', i),
				num(ctx, 'publicKeyPrefixLength', i),
			),
		),
	'diagnostics:sendBinaryRequest': async (conn, ctx, i) => {
		const responseData = await call<Uint8Array>(
			conn,
			'sendBinaryRequest',
			hexToBytes(str(ctx, 'contactPublicKey', i)),
			hexToBytes(str(ctx, 'requestData', i)),
			num(ctx, 'extraTimeoutMs', i),
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
