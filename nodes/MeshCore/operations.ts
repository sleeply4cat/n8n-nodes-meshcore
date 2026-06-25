import type { IDataObject, IExecuteFunctions } from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';

import type { MeshConnection, SharedConnection } from '../shared/ConnectionManager';
import { bytesToHex, hexToBytes, normalizeBytesDeep } from '../shared/params';
import { PushCodes, ResponseCodes, TxtTypes } from '../shared/codes';
import {
	PAYLOAD_TYPE_GRP_TXT,
	buffersEqual,
	computeGroupTextPacketHash,
	computePacketHash,
	parseRxFrame,
} from '../shared/channelHash';
import { enrichContactRecord, encodePathLen, OUT_PATH_UNKNOWN } from '../shared/contactPath';

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
 * Normalize a contact for output (Get Many / Find / Get by Key). Decoding of
 * `outPathLen` + `outPath` lives in `shared/contactPath.ts` because the trigger
 * does the same enrichment for the NewAdvert push (which carries the same
 * contact-record shape).
 */
function contactJson(contact: unknown): IDataObject {
	if (contact && typeof contact === 'object') {
		const c = enrichContactRecord({ ...(contact as Record<string, unknown>) });
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
	/** When true (default), clear the cached route before the flood phase. */
	resetPathOnFloodFallback: boolean;
	perAttemptTimeoutMs: number;
}

interface ReliableSendResult {
	delivered: boolean;
	ackCode: number | null;
	attempts: number;
	phase: 'path' | 'flood' | null;
	roundTrip: number | null;
	lastSent: SentResponse | null;
}

interface SentResponse {
	result: number;
	expectedAckCrc: number;
	estTimeout: number;
}

/**
 * Send one CMD_SEND_TXT_MSG frame with explicit `attempt` and `senderTimestamp`,
 * waiting for the device's RESP_CODE_SENT (or RESP_CODE_ERR). The pair drives the
 * firmware's `expected_ack = sha256(timestamp || (attempt & 3) || text || senderKey)`
 * computation (BaseChatMesh::composeMsgPacket): a stable timestamp across retries
 * means the receiver recognizes the retries as the SAME logical message and does not
 * surface duplicates in its UI, while the incremented attempt makes each on-air
 * packet hash-unique so the mesh can flood every attempt without collapsing them.
 *
 * Uses meshcore.js's low-level `sendCommandSendTxtMsg` directly because the
 * high-level `sendTextMessage` hardcodes `attempt = 0` and re-stamps a fresh
 * `Date.now()` per call — which is what produced "duplicates on the receiver" when
 * we used it for retries.
 */
async function sendTxtRaw(
	conn: SharedConnection,
	txtType: number,
	attempt: number,
	senderTimestamp: number,
	publicKey: Buffer,
	text: string,
): Promise<SentResponse> {
	return conn.run(
		(c) =>
			new Promise<SentResponse>((resolve, reject) => {
				const off = () => {
					c.off(ResponseCodes.Sent, onSent);
					c.off(ResponseCodes.Err, onErr);
				};
				const onSent = (response: unknown) => {
					off();
					resolve(response as SentResponse);
				};
				const onErr = (response: unknown) => {
					off();
					const errCode = (response as { errCode?: unknown } | null)?.errCode;
					reject(
						new Error(
							`MeshCore device returned ERR for SEND_TXT_MSG${errCode != null ? ` (errCode=${String(errCode)})` : ''}`,
						),
					);
				};
				c.once(ResponseCodes.Sent, onSent);
				c.once(ResponseCodes.Err, onErr);

				const fn = (c as Record<string, unknown>).sendCommandSendTxtMsg as
					| ((
							t: number,
							a: number,
							ts: number,
							pk: Uint8Array,
							txt: string,
					  ) => Promise<void>)
					| undefined;
				if (typeof fn !== 'function') {
					off();
					reject(
						new Error(
							'meshcore.js does not implement "sendCommandSendTxtMsg" (needs a protocol extension)',
						),
					);
					return;
				}
				fn.call(c, txtType, attempt, senderTimestamp, publicKey, text).catch((e: unknown) => {
					off();
					reject(
						e instanceof Error
							? e
							: new Error('sendCommandSendTxtMsg failed: device returned an error or did not respond'),
					);
				});
			}),
	);
}

/**
 * Send one CMD_SEND_CHANNEL_TXT_MSG frame with an explicit `senderTimestamp` (so
 * retries share the same timestamp → same packet hash on air → repeaters dedupe
 * and receivers don't surface duplicates) and wait for the device's RESP_CODE_OK.
 */
async function sendChannelTxtRaw(
	conn: SharedConnection,
	channelIdx: number,
	senderTimestamp: number,
	text: string,
): Promise<void> {
	return conn.run(
		(c) =>
			new Promise<void>((resolve, reject) => {
				const off = () => {
					c.off(ResponseCodes.Ok, onOk);
					c.off(ResponseCodes.Err, onErr);
				};
				const onOk = () => {
					off();
					resolve();
				};
				const onErr = (response: unknown) => {
					off();
					const errCode = (response as { errCode?: unknown } | null)?.errCode;
					reject(
						new Error(
							`MeshCore device returned ERR for SEND_CHANNEL_TXT_MSG${errCode != null ? ` (errCode=${String(errCode)})` : ''}`,
						),
					);
				};
				c.once(ResponseCodes.Ok, onOk);
				c.once(ResponseCodes.Err, onErr);
				const fn = (c as Record<string, unknown>).sendCommandSendChannelTxtMsg as
					| ((t: number, ch: number, ts: number, txt: string) => Promise<void>)
					| undefined;
				if (typeof fn !== 'function') {
					off();
					reject(new Error('meshcore.js does not implement "sendCommandSendChannelTxtMsg"'));
					return;
				}
				fn.call(c, TxtTypes.Plain, channelIdx, senderTimestamp, text).catch((e: unknown) => {
					off();
					reject(
						e instanceof Error
							? e
							: new Error('sendCommandSendChannelTxtMsg failed: device returned an error or did not respond'),
					);
				});
			}),
	);
}

interface ReliableChannelOptions {
	channelIdx: number;
	text: string;
	channelSecret: Buffer; // 16 bytes
	advName: string;
	retries: number;
	perAttemptTimeoutMs: number;
}

interface HeardEcho {
	snr: number;
	rssi: number;
	/** Hex of the LAST hop appended to the on-air path — that's our immediate
	 * retransmitter's publicKey prefix (firmware appends `hashSize` bytes of its
	 * own pubKey, see `Identity::copyHashTo`). May be empty if hops=0 (we heard
	 * our own packet from someone who marked it do-not-retransmit, unusual). */
	relayHashPrefixHex: string;
	/** Full hex of the path field as it was on the wire — `hops * hashSize` bytes,
	 * each chunk a 1..4-byte publicKey prefix of one repeater along the route. */
	fullPathHex: string;
	/** Total hops accumulated in the heard frame — usually 1 for a direct neighbor. */
	hops: number;
	hashSize: number;
}

interface ReliableChannelResult {
	delivered: boolean;
	attempts: number;
	firstHeard: HeardEcho | null;
	expectedHashHex: string;
}

/**
 * Send a channel (broadcast) message reliably. The channel protocol has no
 * per-recipient ACK, so "reliable" here means: at least one neighbor heard our
 * broadcast and retransmitted it on the radio (the only signal of mesh propagation
 * available to a single node). We compute the on-air packet hash locally and
 * watch `PUSH_CODE_LOG_RX_DATA` for a frame whose hash matches.
 *
 * Retries reuse the SAME senderTimestamp + text → SAME packet hash → repeaters
 * dedupe via their hashSeen table and receivers don't get duplicate UI entries
 * (same idea as the direct-message retry path).
 */
async function reliableChannelSend(
	conn: SharedConnection,
	opts: ReliableChannelOptions,
): Promise<ReliableChannelResult> {
	const { channelIdx, text, channelSecret, advName, retries, perAttemptTimeoutMs } = opts;

	const senderTimestamp = Math.floor(Date.now() / 1000);
	const { hash: expectedHash } = computeGroupTextPacketHash(
		channelSecret,
		advName,
		text,
		senderTimestamp,
	);

	let heard: HeardEcho | null = null;
	let pendingResolve: ((h: HeardEcho | null) => void) | null = null;

	const unsubscribe = conn.subscribe(PushCodes.LogRxData, (raw) => {
		if (heard !== null) return;
		const frame = raw as { lastSnr?: number; lastRssi?: number; raw?: unknown };
		const rawBytes =
			frame.raw instanceof Uint8Array
				? frame.raw
				: Array.isArray(frame.raw)
					? Uint8Array.from(frame.raw as number[])
					: null;
		if (!rawBytes) return;
		const parsed = parseRxFrame(rawBytes);
		if (!parsed || parsed.payloadType !== PAYLOAD_TYPE_GRP_TXT) return;
		const hash = computePacketHash(PAYLOAD_TYPE_GRP_TXT, parsed.payload);
		if (!buffersEqual(hash, expectedHash)) return;
		// The LAST hop appended to the path is the most recent retransmitter — i.e.
		// the neighbor we just heard. Each hop's bytes are a prefix of that node's
		// publicKey (Identity::copyHashTo just memcpy's the first `hashSize` bytes).
		const relayHash =
			parsed.hops > 0
				? parsed.path.subarray(parsed.path.length - parsed.hashSize)
				: Buffer.alloc(0);
		heard = {
			snr: Number(frame.lastSnr ?? 0),
			rssi: Number(frame.lastRssi ?? 0),
			relayHashPrefixHex: relayHash.toString('hex'),
			fullPathHex: parsed.path.toString('hex'),
			hops: parsed.hops,
			hashSize: parsed.hashSize,
		};
		if (pendingResolve) {
			const r = pendingResolve;
			pendingResolve = null;
			r(heard);
		}
	});

	const waitForEcho = (timeoutMs: number) =>
		new Promise<HeardEcho | null>((resolve) => {
			if (heard) {
				resolve(heard);
				return;
			}
			const timer = setTimeout(() => {
				pendingResolve = null;
				resolve(null);
			}, timeoutMs);
			pendingResolve = (h) => {
				clearTimeout(timer);
				resolve(h);
			};
		});

	let attempts = 0;
	try {
		for (let i = 0; i < retries; i++) {
			attempts++;
			await sendChannelTxtRaw(conn, channelIdx, senderTimestamp, text);
			const echo = await waitForEcho(perAttemptTimeoutMs);
			if (echo) {
				return {
					delivered: true,
					attempts,
					firstHeard: echo,
					expectedHashHex: expectedHash.toString('hex'),
				};
			}
		}
		return {
			delivered: false,
			attempts,
			firstHeard: null,
			expectedHashHex: expectedHash.toString('hex'),
		};
	} finally {
		unsubscribe();
	}
}

/**
 * Try to resolve a path-hash prefix back to a known contact. Each repeater
 * appends `hashSize` raw bytes of its own publicKey to the path; if any known
 * contact's publicKey starts with the same bytes, it's a candidate. With the
 * default 1-byte hashSize multiple contacts may collide, so we return ALL
 * candidates rather than picking one — the workflow can decide.
 */
function resolveRelayCandidates(
	contacts: unknown[],
	relayHashPrefixHex: string,
): Array<{ publicKey: string; name: string; type: number | null }> {
	if (!relayHashPrefixHex) return [];
	const out: Array<{ publicKey: string; name: string; type: number | null }> = [];
	for (const c of contacts) {
		if (!c || typeof c !== 'object') continue;
		const rec = c as { publicKey?: unknown; advName?: unknown; type?: unknown };
		const pk = rec.publicKey;
		const pkHex =
			pk instanceof Uint8Array
				? Buffer.from(pk).toString('hex')
				: typeof pk === 'string'
					? pk.toLowerCase()
					: null;
		if (!pkHex || !pkHex.startsWith(relayHashPrefixHex.toLowerCase())) continue;
		out.push({
			publicKey: pkHex,
			name: typeof rec.advName === 'string' ? rec.advName : '',
			type: typeof rec.type === 'number' ? rec.type : null,
		});
	}
	return out;
}

/**
 * Send a direct text message with retry policy that mirrors the MeshCore app: a path
 * phase (up to N attempts using the stored route, if any) followed by a flood phase
 * (M attempts after a path reset, since the device will keep using the cached route
 * until it's cleared). Retries fire immediately on per-attempt timeout (no backoff).
 * When `forceFlood` is set, the path phase is skipped after an upfront resetPath.
 *
 * Two safety nets for the ack handling:
 *  1. A STABLE `senderTimestamp` is used for the whole logical send, and `attempt`
 *     is monotonic — so the receiver de-duplicates retries instead of surfacing them
 *     as separate messages to the user (see `sendTxtRaw` for the firmware contract).
 *  2. Ack matching is CUMULATIVE: every attempt's `expectedAckCrc` (returned by the
 *     device in RESP_CODE_SENT) goes into a shared set, and a single SendConfirmed
 *     subscriber resolves on the first push whose ackCode is in that set. A late
 *     ack from attempt #1 arriving during attempt #2's wait is recognized as
 *     "delivered" and short-circuits the loop instead of being silently dropped.
 */
async function reliableSend(
	conn: SharedConnection,
	opts: ReliableSendOptions,
): Promise<ReliableSendResult> {
	const {
		publicKey,
		message,
		txtType,
		pathRetries,
		floodRetries,
		forceFlood,
		resetPathOnFloodFallback,
		perAttemptTimeoutMs,
	} = opts;

	// Stable timestamp for the WHOLE logical send. With matching `(timestamp, attempt&3,
	// text)` across our retries, the receiver's firmware treats them as the same logical
	// message and does not produce duplicates in its UI.
	const senderTimestamp = Math.floor(Date.now() / 1000);

	const expectedAckCodes = new Set<number>();
	const phaseByAck = new Map<number, 'path' | 'flood'>();
	let confirmed: { ackCode: number; roundTrip: number } | null = null;
	let pendingResolve: ((c: { ackCode: number; roundTrip: number }) => void) | null = null;

	const unsubscribe = conn.subscribe(PushCodes.SendConfirmed, (raw) => {
		if (confirmed !== null) {
			return;
		}
		const payload = raw as { ackCode?: unknown; roundTrip?: unknown };
		const ackCode = Number(payload.ackCode);
		if (!Number.isFinite(ackCode) || !expectedAckCodes.has(ackCode)) {
			return;
		}
		confirmed = { ackCode, roundTrip: Number(payload.roundTrip) };
		if (pendingResolve) {
			const resolve = pendingResolve;
			pendingResolve = null;
			resolve(confirmed);
		}
	});

	const waitForAck = (timeoutMs: number) =>
		new Promise<{ ackCode: number; roundTrip: number } | null>((resolve) => {
			if (confirmed) {
				resolve(confirmed);
				return;
			}
			const timer = setTimeout(() => {
				pendingResolve = null;
				resolve(null);
			}, timeoutMs);
			pendingResolve = (c) => {
				clearTimeout(timer);
				resolve(c);
			};
		});

	let attempts = 0;
	let lastSent: SentResponse | null = null;
	// Monotonic attempt byte across the whole reliable send (firmware masks to 2 bits
	// internally; we keep counting for the on-air payload hash to stay unique).
	let attemptByte = 0;

	const finish = (phase: 'path' | 'flood' | null): ReliableSendResult => {
		if (confirmed) {
			return {
				delivered: true,
				ackCode: confirmed.ackCode,
				attempts,
				phase: phaseByAck.get(confirmed.ackCode) ?? phase,
				roundTrip: confirmed.roundTrip,
				lastSent,
			};
		}
		return { delivered: false, ackCode: null, attempts, phase: null, roundTrip: null, lastSent };
	};

	try {
		const tryPhase = async (phase: 'path' | 'flood', maxAttempts: number): Promise<boolean> => {
			for (let i = 0; i < maxAttempts; i++) {
				attempts++;
				lastSent = await sendTxtRaw(
					conn,
					txtType,
					attemptByte++,
					senderTimestamp,
					publicKey,
					message,
				);
				const ackCode = Number(lastSent.expectedAckCrc);
				if (Number.isFinite(ackCode)) {
					expectedAckCodes.add(ackCode);
					phaseByAck.set(ackCode, phase);
				}
				const result = await waitForAck(perAttemptTimeoutMs);
				if (result !== null) {
					return true;
				}
			}
			return false;
		};

		if (forceFlood) {
			await call(conn, 'resetPath', publicKey);
		} else if (pathRetries > 0) {
			if (await tryPhase('path', pathRetries)) {
				return finish('path');
			}
			// path phase exhausted: the cached route is stale or the contact is unreachable
			// along it. By default we clear it before falling back to flood — otherwise the
			// firmware keeps using the same dead route on subsequent sendCommandSendTxtMsg
			// calls and the flood phase isn't really "flood". Disabling this preserves the
			// route (flood-phase attempts then proceed along the same path).
			if (resetPathOnFloodFallback) {
				await call(conn, 'resetPath', publicKey);
			}
		}

		if (floodRetries > 0 && (await tryPhase('flood', floodRetries))) {
			return finish('flood');
		}

		return finish(null);
	} finally {
		unsubscribe();
	}
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
		const resetPathOnFloodFallback = ctx.getNodeParameter(
			'resetPathOnFloodFallback',
			i,
			true,
		) as boolean;

		const result = await reliableSend(conn, {
			publicKey,
			message: str(ctx, 'message', i),
			txtType,
			pathRetries,
			floodRetries,
			forceFlood,
			resetPathOnFloodFallback,
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
		const channelIdx = num(ctx, 'channelIdx', i);
		const text = str(ctx, 'message', i);
		const reliableDelivery = ctx.getNodeParameter('reliableDelivery', i, false) as boolean;

		if (!reliableDelivery) {
			await call(conn, 'sendChannelTextMessage', channelIdx, text);
			return OK;
		}

		// Resolve our own advName (firmware embeds "<advName>: <text>" inside the
		// group payload; we must match it byte-for-byte to compute the on-air hash)
		// and the channel's 16-byte symmetric secret (AES key + HMAC material).
		const self = (await call(conn, 'getSelfInfo', 10000)) as { name?: unknown };
		const advName = String((self?.name as string) ?? '');
		const channel = (await call(conn, 'getChannel', channelIdx)) as { secret?: unknown };
		const secretBytes = channel?.secret;
		if (!(secretBytes instanceof Uint8Array) && !Array.isArray(secretBytes)) {
			throw new NodeOperationError(
				ctx.getNode(),
				`MeshCore channel ${channelIdx} has no secret available; cannot compute on-air packet hash for reliable send`,
				{ itemIndex: i },
			);
		}
		const channelSecret = Buffer.from(secretBytes as Uint8Array);

		const retries = Math.max(1, Number(ctx.getNodeParameter('channelRetries', i, 3)));
		const perAttemptTimeoutMs =
			Number(ctx.getNodeParameter('channelEchoTimeoutMs', i, 8000)) || 8000;

		const result = await reliableChannelSend(conn, {
			channelIdx,
			text,
			channelSecret,
			advName,
			retries,
			perAttemptTimeoutMs,
		});

		if (!result.delivered) {
			throw new NodeOperationError(
				ctx.getNode(),
				`MeshCore channel broadcast not heard back after ${result.attempts} attempt(s)`,
				{
					itemIndex: i,
					description: `No neighbor retransmission of expected packet hash ${result.expectedHashHex} was heard within ${perAttemptTimeoutMs}ms per attempt. The mesh may be empty in range, or no node is configured to repeat on this channel.`,
				},
			);
		}

		// Resolve the relay's pubkey-prefix against the contact list. Done lazily
		// (only on success) so the happy path isn't paying for getContacts.
		const heard = result.firstHeard!;
		let relayCandidates: ReturnType<typeof resolveRelayCandidates> = [];
		if (heard.relayHashPrefixHex) {
			try {
				const contacts = ((await call(conn, 'getContacts')) ?? []) as unknown[];
				relayCandidates = resolveRelayCandidates(contacts, heard.relayHashPrefixHex);
			} catch {
				// non-fatal: still report the raw prefix below
			}
		}

		return {
			delivered: true,
			attempts: result.attempts,
			firstHeardSnr: heard.snr,
			firstHeardRssi: heard.rssi,
			firstHeardHops: heard.hops,
			firstHeardHashSize: heard.hashSize,
			// hex of the full on-air path: hops * hashSize bytes, each chunk a
			// publicKey prefix of one repeater along the route we just heard.
			firstHeardPath: heard.fullPathHex,
			// raw bytes of the LAST hop only (the immediate retransmitter we heard)
			firstRelayHashPrefix: heard.relayHashPrefixHex,
			// resolved contact(s) — empty if unknown to us, multiple if the short
			// hash prefix collides; ambiguous resolution is the workflow's call.
			firstRelayCandidates: relayCandidates,
			expectedPacketHash: result.expectedHashHex,
		};
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
				const resetPathOnFloodFallback = ctx.getNodeParameter(
					'resetPathOnFloodFallback',
					i,
					true,
				) as boolean;
				const send = await reliableSend(conn, {
					publicKey,
					message: str(ctx, 'message', i),
					txtType,
					pathRetries,
					floodRetries,
					forceFlood,
					resetPathOnFloodFallback,
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
		const payload = hexToBytes(str(ctx, 'payload', i));
		const dataType = num(ctx, 'dataType', i);
		let pathLen: number;
		let path: Buffer;
		if (str(ctx, 'routing', i) === 'direct') {
			// Direct: route bytes are 1-byte-hash hops (one hex byte = one hop, per the
			// Path field convention), so the packed path_len is just the hop count.
			path = optionalHex(str(ctx, 'path', i));
			pathLen = encodePathLen(path.length);
		} else {
			// Flood: the firmware needs OUT_PATH_UNKNOWN (0xFF), NOT path_len 0 — a 0 is a
			// valid zero-hop DIRECT send (Packet::isValidPathLen). With no scope set the
			// device floods plainly; otherwise it applies the current/default flood scope.
			path = Buffer.alloc(0);
			pathLen = OUT_PATH_UNKNOWN;
		}
		await call(conn, 'sendChannelData', num(ctx, 'channelIdx', i), pathLen, path, dataType, payload);
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
