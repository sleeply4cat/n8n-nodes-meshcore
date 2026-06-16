import { test } from 'node:test';
import assert from 'node:assert/strict';

import { hexToBytes, normalizeBytesDeep } from '../dist/nodes/shared/params.js';
import { PushCodes } from '../dist/nodes/shared/codes.js';
import { operations } from '../dist/nodes/MeshCore/operations.js';
import { startMessageStream } from '../dist/nodes/MeshCoreTrigger/messageStream.js';
import { startSubscriptions } from '../dist/nodes/MeshCoreTrigger/events.js';

function tick(): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, 0));
}

/** Minimal stand-in for SharedConnection: run() invokes the fn against a mock mesh. */
class FakeConn {
	private readonly subs = new Map<number, Set<(p: unknown) => void>>();
	private readonly mesh: Record<string, unknown>;

	constructor(mesh: Record<string, unknown>) {
		this.mesh = mesh;
	}

	async run<T>(fn: (c: unknown) => Promise<T>): Promise<T> {
		return fn(this.mesh);
	}

	subscribe(code: number, handler: (p: unknown) => void): () => void {
		let set = this.subs.get(code);
		if (!set) {
			set = new Set();
			this.subs.set(code, set);
		}
		set.add(handler);
		return () => set!.delete(handler);
	}

	fire(code: number, payload: unknown): void {
		for (const handler of [...(this.subs.get(code) ?? [])]) {
			handler(payload);
		}
	}

	subscriberCount(code: number): number {
		return this.subs.get(code)?.size ?? 0;
	}

	private readonly messageConsumers = new Set<(m: unknown) => void>();

	subscribeMessages(handler: (m: unknown) => void): () => void {
		this.messageConsumers.add(handler);
		return () => this.messageConsumers.delete(handler);
	}

	deliverMessage(message: unknown): void {
		for (const handler of [...this.messageConsumers]) {
			handler(message);
		}
	}

	messageConsumerCount(): number {
		return this.messageConsumers.size;
	}

	expectPush<T = unknown>(code: number): {
		match: (predicate: (p: T) => boolean, timeoutMs: number) => Promise<T | null>;
		cancel: () => void;
	} {
		const buffer: T[] = [];
		let predicate: ((p: T) => boolean) | null = null;
		let onMatch: ((p: T) => void) | null = null;
		const unsub = this.subscribe(code, (p) => {
			const v = p as T;
			if (predicate && onMatch) {
				if (predicate(v)) onMatch(v);
			} else {
				buffer.push(v);
			}
		});
		return {
			match: (pred, ms) =>
				new Promise<T | null>((resolve) => {
					let done = false;
					let t: ReturnType<typeof setTimeout>;
					const finish = (v: T | null) => {
						if (done) return;
						done = true;
						clearTimeout(t);
						unsub();
						resolve(v);
					};
					t = setTimeout(() => finish(null), ms);
					const b = buffer.find(pred);
					if (b !== undefined) return finish(b);
					predicate = pred;
					onMatch = (v) => finish(v);
				}),
			cancel: unsub,
		};
	}
}

function fakeCtx(params: Record<string, unknown>): any {
	return {
		getNodeParameter: (name: string, _i?: number, def?: unknown) => params[name] ?? def,
		// NodeOperationError needs a node-like object; the minimum n8n requires for the constructor.
		getNode: () => ({
			id: 'test-node',
			name: 'TestNode',
			type: 'meshCore',
			typeVersion: 1,
			position: [0, 0],
			parameters: {},
		}),
	};
}

test('hexToBytes parses valid hex and rejects invalid', () => {
	assert.deepEqual([...hexToBytes('a1b2c3')], [0xa1, 0xb2, 0xc3]);
	assert.deepEqual([...hexToBytes('0xA1B2')], [0xa1, 0xb2]);
	assert.throws(() => hexToBytes('xyz'), /Invalid hex/);
	assert.throws(() => hexToBytes('abc'), /Invalid hex/); // odd length
});

test('normalizeBytesDeep converts byte fields to hex, leaves the rest', () => {
	const out = normalizeBytesDeep({
		publicKey: Uint8Array.from([0xa1, 0xb2]),
		nested: { secret: Uint8Array.from([0x00, 0xff]) },
		list: [{ k: Uint8Array.from([0x01]) }],
		serialized: { type: 'Buffer', data: [0xde, 0xad] },
		count: 5,
		text: 'hi',
	}) as any;
	assert.equal(out.publicKey, 'a1b2');
	assert.equal(out.nested.secret, '00ff');
	assert.equal(out.list[0].k, '01');
	assert.equal(out.serialized, 'dead');
	assert.equal(out.count, 5);
	assert.equal(out.text, 'hi');
});

test('action output normalizes byte fields to hex (getContacts publicKey)', async () => {
	const mesh = {
		getContacts: async () => [{ advName: 'a', publicKey: Uint8Array.from([0xaa, 0xbb, 0xcc]) }],
	};
	const conn = new FakeConn(mesh) as any;
	const result = (await operations['contact:getAll'](conn, fakeCtx({}), 0)) as any[];
	assert.equal(result[0].publicKey, 'aabbcc');
	assert.equal(result[0].advName, 'a');
});

test('contact output truncates outPath to outPathLen', async () => {
	const outPath = new Uint8Array(64);
	outPath[0] = 0x0a;
	outPath[1] = 0x0b;
	const mesh = {
		getContactByKey: async () => ({ advName: 'r', outPathLen: 2, outPath, publicKey: Uint8Array.from([0x01]) }),
	};
	const conn = new FakeConn(mesh) as any;
	const r = (await operations['contact:getByKey'](conn, fakeCtx({ publicKey: 'aa' }), 0)) as any;
	assert.equal(r.outPath, '0a0b', 'outPath truncated to outPathLen and hex-encoded');
	assert.equal(r.publicKey, '01');
});

test('channel:getAll drops unconfigured (empty-name) channels', async () => {
	const mesh = {
		getChannels: async () => [
			{ channelIdx: 0, name: 'Public', secret: Uint8Array.from([1]) },
			{ channelIdx: 1, name: '', secret: new Uint8Array(16) },
			{ channelIdx: 2, name: '', secret: new Uint8Array(16) },
		],
	};
	const conn = new FakeConn(mesh) as any;
	const r = (await operations['channel:getAll'](conn, fakeCtx({}), 0)) as any[];
	assert.equal(r.length, 1, 'only configured channels returned');
	assert.equal(r[0].name, 'Public');
});

test('device:getSelfInfo calls getSelfInfo and returns its object', async () => {
	const mesh = {
		getSelfInfo: async (timeout: number) => ({ name: 'node1', timeout }),
	};
	const conn = new FakeConn(mesh) as unknown as Parameters<(typeof operations)['device:getSelfInfo']>[0];
	const result = await operations['device:getSelfInfo'](conn, fakeCtx({}), 0);
	assert.deepEqual(result, { name: 'node1', timeout: 10000 });
});

test('message:sendDirect parses pubkey hex and surfaces ackCode from expectedAckCrc', async () => {
	let captured: { pk: Uint8Array; text: string; type: number } | null = null;
	const mesh = {
		sendTextMessage: async (pk: Uint8Array, text: string, type: number) => {
			captured = { pk, text, type };
			return { expectedAckCrc: 42 };
		},
	};
	const conn = new FakeConn(mesh) as unknown as Parameters<(typeof operations)['message:sendDirect']>[0];
	const ctx = fakeCtx({ contactPublicKey: 'a1b2c3d4e5f6', message: 'hello' });

	const result = await operations['message:sendDirect'](conn, ctx, 0);

	assert.ok(captured, 'sendTextMessage was called');
	assert.equal(Buffer.from(captured!.pk).toString('hex'), 'a1b2c3d4e5f6');
	assert.equal(captured!.text, 'hello');
	assert.equal(captured!.type, 0); // TxtTypes.Plain
	assert.deepEqual(result, { expectedAckCrc: 42, ackCode: 42 });
});

test('startMessageStream routes only the selected message types (direct only)', () => {
	const conn = new FakeConn({});
	const events: Array<{ event: string; payload: unknown }> = [];

	const unsubscribe = startMessageStream(conn as any, ['directMessage'], (event, payload) =>
		events.push({ event, payload }),
	);

	conn.deliverMessage({ contactMessage: { text: 'dm' } });
	conn.deliverMessage({ channelMessage: { text: 'ch' } });
	assert.deepEqual(events, [{ event: 'directMessage', payload: { text: 'dm' } }], 'only direct emitted');

	assert.equal(conn.messageConsumerCount(), 1);
	unsubscribe();
	assert.equal(conn.messageConsumerCount(), 0, 'unsubscribe detaches the message consumer');
});

test('startMessageStream emits both direct and channel when both selected', () => {
	const conn = new FakeConn({});
	const events: Array<{ event: string; payload: unknown }> = [];

	startMessageStream(conn as any, ['directMessage', 'channelMessage'], (event, payload) =>
		events.push({ event, payload }),
	);
	conn.deliverMessage({ contactMessage: { text: 'dm' } });
	conn.deliverMessage({ channelMessage: { text: 'ch' } });

	assert.deepEqual(events, [
		{ event: 'directMessage', payload: { text: 'dm' } },
		// channel text has no "<nick>: " prefix here, so author is empty and text == rawText
		{ event: 'channelMessage', payload: { text: 'ch', author: '', rawText: 'ch' } },
	]);
});

test('startMessageStream decodes packed pathLen into via/hops/pathHashSize', () => {
	const conn = new FakeConn({});
	const events: Array<{ event: string; payload: any }> = [];
	startMessageStream(conn as any, ['directMessage', 'channelMessage'], (event, payload) =>
		events.push({ event, payload }),
	);

	// 0xFF sentinel → direct routing (no hops, no hash size)
	conn.deliverMessage({ contactMessage: { text: 'd1', pathLen: 0xff } });
	// pathLen=3 (low 6 bits) — 3 hops, 1-byte hashes
	conn.deliverMessage({ contactMessage: { text: 'd2', pathLen: 3 } });
	// pathLen=0x43 = 0b01000011 — 3 hops, 2-byte hashes (observed on live hw)
	conn.deliverMessage({ channelMessage: { text: 'Bob: ch', pathLen: 0x43 } });

	assert.equal(events[0].payload.via, 'direct');
	assert.equal(events[0].payload.hops, 0);
	assert.equal(events[0].payload.pathHashSize, undefined, 'no path-hash size on direct');
	assert.equal(events[1].payload.via, 'flood');
	assert.equal(events[1].payload.hops, 3);
	assert.equal(events[1].payload.pathHashSize, 1);
	assert.equal(events[2].payload.via, 'flood');
	assert.equal(events[2].payload.hops, 3, 'low 6 bits of 0x43');
	assert.equal(events[2].payload.pathHashSize, 2, 'high 2 bits of 0x43, plus 1');
});

test('channelMessage splits "<nick>: <text>" into author, text, rawText', () => {
	const conn = new FakeConn({});
	const events: Array<{ event: string; payload: any }> = [];

	startMessageStream(conn as any, ['channelMessage'], (event, payload) =>
		events.push({ event, payload }),
	);
	conn.deliverMessage({
		channelMessage: { channelIdx: 0, text: 'Alice: hello: world' },
	});

	assert.equal(events.length, 1);
	const { payload } = events[0];
	assert.equal(payload.author, 'Alice', 'nick taken before the first ": "');
	assert.equal(payload.text, 'hello: world', 'remaining text after the first ": "');
	assert.equal(payload.rawText, 'Alice: hello: world', 'full original kept as rawText');
	assert.equal(payload.channelIdx, 0, 'other fields preserved');
});

test('contact:getAll returns an array of contacts', async () => {
	const mesh = { getContacts: async () => [{ advName: 'a' }, { advName: 'b' }] };
	const conn = new FakeConn(mesh) as any;
	const result = await operations['contact:getAll'](conn, fakeCtx({}), 0);
	assert.ok(Array.isArray(result));
	assert.equal((result as unknown[]).length, 2);
});

test('channel:set parses secret hex and forwards name + index', async () => {
	let captured: { idx: number; name: string; secret: Uint8Array } | null = null;
	const mesh = {
		setChannel: async (idx: number, name: string, secret: Uint8Array) => {
			captured = { idx, name, secret };
		},
	};
	const conn = new FakeConn(mesh) as any;
	const ctx = fakeCtx({ channelIdx: 2, name: 'chan', secret: '00112233445566778899aabbccddeeff' });

	const result = await operations['channel:set'](conn, ctx, 0);

	assert.equal(captured!.idx, 2);
	assert.equal(captured!.name, 'chan');
	assert.equal(Buffer.from(captured!.secret).toString('hex'), '00112233445566778899aabbccddeeff');
	assert.deepEqual(result, { success: true });
});

test('contact:findByName returns found:false when not found', async () => {
	const mesh = { findContactByName: async () => undefined };
	const conn = new FakeConn(mesh) as any;
	const result = await operations['contact:findByName'](conn, fakeCtx({ name: 'nope' }), 0);
	assert.deepEqual(result, { found: false });
});

test('call() throws a clear error when meshcore.js lacks the method', async () => {
	const conn = new FakeConn({}) as any; // mesh has no getStatus
	await assert.rejects(
		operations['diagnostics:getStatus'](conn, fakeCtx({ contactPublicKey: 'aabb' }), 0),
		/does not implement "getStatus"/,
	);
});

test('contact:addOrUpdate forwards mapped fields with derived outPathLen', async () => {
	let args: unknown[] = [];
	const mesh = { addOrUpdateContact: async (...a: unknown[]) => { args = a; } };
	const conn = new FakeConn(mesh) as any;
	const ctx = fakeCtx({ publicKey: 'aabb', type: 2, flags: 1, outPath: '0102', name: 'Rep', lastAdvert: 123, latitude: 10, longitude: 20 });

	const result = await operations['contact:addOrUpdate'](conn, ctx, 0);

	assert.equal(Buffer.from(args[0] as Uint8Array).toString('hex'), 'aabb');
	assert.equal(args[1], 2); // type
	assert.equal(args[2], 1); // flags
	assert.equal(args[3], 2); // outPathLen derived from '0102' (2 bytes)
	assert.equal(Buffer.from(args[4] as Uint8Array).toString('hex'), '0102');
	assert.equal(args[5], 'Rep');
	assert.equal(args[6], 123);
	assert.equal(args[7], 10);
	assert.equal(args[8], 20);
	assert.deepEqual(result, { success: true });
});

test('repeater:sign returns a hex signature', async () => {
	const mesh = { sign: async () => new Uint8Array([0xde, 0xad, 0xbe, 0xef]) };
	const conn = new FakeConn(mesh) as any;
	const result = await operations['repeater:sign'](conn, fakeCtx({ data: '00' }), 0);
	assert.deepEqual(result, { signature: 'deadbeef' });
});

test('contact:setPath returns found:false when the contact is missing', async () => {
	const mesh = { findContactByPublicKeyPrefix: async () => undefined };
	const conn = new FakeConn(mesh) as any;
	const result = await operations['contact:setPath'](conn, fakeCtx({ publicKey: 'aabb', path: '0102' }), 0);
	assert.deepEqual(result, { found: false });
});

test('diagnostics:getNeighbours forwards pagination args', async () => {
	let args: unknown[] = [];
	const mesh = {
		getNeighbours: async (...a: unknown[]) => {
			args = a;
			return { total: 0, neighbours: [] };
		},
	};
	const conn = new FakeConn(mesh) as any;
	const ctx = fakeCtx({ contactPublicKey: 'aabb', count: 5, offset: 2, orderBy: 1, publicKeyPrefixLength: 4 });

	await operations['diagnostics:getNeighbours'](conn, ctx, 0);

	assert.equal(Buffer.from(args[0] as Uint8Array).toString('hex'), 'aabb');
	assert.deepEqual(args.slice(1), [5, 2, 1, 4]);
});

test('call() turns a bare (undefined) device-ERR rejection into a clear message', async () => {
	// meshcore.js rejects with no argument on a device ERR response
	const mesh = { getBatteryVoltage: () => Promise.reject(undefined) };
	const conn = new FakeConn(mesh) as any;
	await assert.rejects(
		operations['device:getBatteryVoltage'](conn, fakeCtx({}), 0),
		/returned an error or did not respond/,
	);
});

test('message:sendDirect (reliable) delivers on the first path attempt', async () => {
	const conn = new FakeConn({ sendTextMessage: async () => ({ expectedAckCrc: 111 }) });
	const p = operations['message:sendDirect'](
		conn as any,
		fakeCtx({
			contactPublicKey: 'aa',
			message: 'hi',
			reliableDelivery: true,
			ackTimeoutMs: 1000,
		}),
		0,
	);
	conn.fire(0x82, { ackCode: 111, roundTrip: 50 }); // buffered until match
	const r = (await p) as any;
	assert.equal(r.delivered, true);
	assert.equal(r.roundTrip, 50);
	assert.equal(r.ackCode, 111);
	assert.equal(r.phase, 'path');
	assert.equal(r.attempts, 1);
});

test('message:sendDirect (reliable) throws NodeOperationError after all retries exhausted', async () => {
	let sends = 0;
	let resets = 0;
	const conn = new FakeConn({
		sendTextMessage: async () => {
			sends++;
			return { expectedAckCrc: 999 };
		},
		resetPath: async () => {
			resets++;
		},
	});
	await assert.rejects(
		operations['message:sendDirect'](
			conn as any,
			fakeCtx({
				contactPublicKey: 'aa',
				message: 'hi',
				reliableDelivery: true,
				ackTimeoutMs: 5,
				pathRetries: 2,
				floodRetries: 1,
			}),
			0,
		),
		/delivery not confirmed/,
	);
	assert.equal(sends, 3, 'tries pathRetries + floodRetries sends');
	assert.equal(resets, 1, 'resets the path once between phases');
});

test('message:sendDirect (reliable) delivers on the flood phase after path attempts fail', async () => {
	let sends = 0;
	let conn: FakeConn;
	const mesh = {
		sendTextMessage: async () => {
			sends++;
			// path attempt: don't ack (will time out). flood attempt (#2): fire ack so the
			// expectPush armed inside reliableSend matches before its timeout fires.
			if (sends === 2) {
				setImmediate(() => conn.fire(0x82, { ackCode: 7, roundTrip: 12 }));
			}
			return { expectedAckCrc: 7 };
		},
		resetPath: async () => {},
	};
	conn = new FakeConn(mesh);
	const r = (await operations['message:sendDirect'](
		conn as any,
		fakeCtx({
			contactPublicKey: 'aa',
			message: 'hi',
			reliableDelivery: true,
			ackTimeoutMs: 50,
			pathRetries: 1,
			floodRetries: 2,
		}),
		0,
	)) as any;
	assert.equal(r.delivered, true);
	assert.equal(r.phase, 'flood', 'fell back to flood after path failed');
	assert.equal(r.attempts, 2, 'one path attempt + one flood attempt');
	assert.equal(sends, 2, 'sent twice (path miss + flood hit)');
});

test('message:sendDirect (reliable, forceFlood) resets path up front and skips path phase', async () => {
	let resets = 0;
	let conn: FakeConn;
	const mesh = {
		sendTextMessage: async () => {
			setImmediate(() => conn.fire(0x82, { ackCode: 5, roundTrip: 1 }));
			return { expectedAckCrc: 5 };
		},
		resetPath: async () => {
			resets++;
		},
	};
	conn = new FakeConn(mesh);
	const r = (await operations['message:sendDirect'](
		conn as any,
		fakeCtx({
			contactPublicKey: 'aa',
			message: 'hi',
			reliableDelivery: true,
			ackTimeoutMs: 100,
			pathRetries: 2,
			floodRetries: 1,
			forceFlood: true,
		}),
		0,
	)) as any;
	assert.equal(r.delivered, true);
	assert.equal(r.phase, 'flood', 'force flood skips path phase');
	assert.equal(resets, 1, 'one reset up front, none between phases');
});

test('message:awaitDelivery matches by ackCode', async () => {
	const conn = new FakeConn({});
	const p = operations['message:awaitDelivery'](conn as any, fakeCtx({ ackCode: 222, ackTimeoutMs: 1000 }), 0);
	conn.fire(0x82, { ackCode: 100, roundTrip: 1 }); // wrong code, ignored
	conn.fire(0x82, { ackCode: 222, roundTrip: 70 });
	const r = (await p) as any;
	assert.equal(r.delivered, true);
	assert.equal(r.roundTrip, 70);
});

test('diagnostics:discoverPath resolves the matching path response (renamed to publicKeyPrefix)', async () => {
	const conn = new FakeConn({ sendPathDiscoveryReq: async () => ({ result: 1 }) });
	const p = operations['diagnostics:discoverPath'](
		conn as any,
		fakeCtx({ contactPublicKey: 'aabbccddeeff00', resultTimeoutMs: 1000 }),
		0,
	);
	// vendor extension emits `pubKeyPrefix` as the meshcore.js short form;
	// the normalizer renames it to publicKeyPrefix on the output boundary.
	conn.fire(0x8d, { pubKeyPrefix: 'aabbccddeeff', outPath: '', inPath: '' });
	const r = (await p) as any;
	assert.equal(r.publicKeyPrefix, 'aabbccddeeff');
});

test('message:sendDirectAwaitReply resolves with the contact reply', async () => {
	const conn = new FakeConn({ sendTextMessage: async () => ({ expectedAckCrc: 1 }) });
	const p = operations['message:sendDirectAwaitReply'](
		conn as any,
		fakeCtx({ contactPublicKey: 'aabbccddeeff00', message: 'q', replyTimeoutMs: 1000 }),
		0,
	);
	conn.deliverMessage({ contactMessage: { pubKeyPrefix: Uint8Array.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), text: 'a' } });
	const r = (await p) as any;
	assert.equal(r.replied, true);
	assert.equal(r.reply.text, 'a');
});

test('repeater:sendCliCommand sends CLI data and returns the response', async () => {
	let sentType: number | null = null;
	const conn = new FakeConn({
		sendTextMessage: async (_pk: unknown, _t: unknown, type: number) => {
			sentType = type;
			return {};
		},
	});
	const p = operations['repeater:sendCliCommand'](
		conn as any,
		fakeCtx({ contactPublicKey: 'aabbccddeeff00', command: 'reboot', replyTimeoutMs: 1000 }),
		0,
	);
	conn.deliverMessage({ contactMessage: { pubKeyPrefix: Uint8Array.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), text: 'ok' } });
	const r = (await p) as any;
	assert.equal(sentType, 1, 'CLI data txt type');
	assert.equal(r.replied, true);
	assert.equal(r.response.text, 'ok');
});

test('diagnostics:awaitEvent waits for the chosen push code', async () => {
	const conn = new FakeConn({});
	const p = operations['diagnostics:awaitEvent'](conn as any, fakeCtx({ pushCode: 0x87, resultTimeoutMs: 1000 }), 0);
	conn.fire(0x87, { statusData: 'x' });
	const r = (await p) as any;
	assert.equal(r.statusData, 'x');
});

test('startSubscriptions wires direct push events and unsubscribes', async () => {
	const mesh = { getWaitingMessages: async () => [] };
	const conn = new FakeConn(mesh);
	const messages: unknown[] = [];
	const caught: Array<{ event: string; payload: unknown }> = [];

	const unsubs = startSubscriptions(conn as any, ['directMessage', 'advert', 'sendConfirmed'], (event, payload) =>
		caught.push({ event, payload }),
	);
	await tick();
	void messages;

	conn.fire(PushCodes.Advert, { name: 'n1' });
	conn.fire(PushCodes.SendConfirmed, { ack: 7 });
	conn.deliverMessage({ contactMessage: { text: 'dm' } });
	assert.deepEqual(caught, [
		{ event: 'advert', payload: { name: 'n1' } },
		{ event: 'sendConfirmed', payload: { ack: 7 } },
		{ event: 'directMessage', payload: { text: 'dm' } },
	]);

	// an event we did not subscribe to is ignored
	conn.fire(PushCodes.TraceData, { x: 1 });
	assert.equal(caught.length, 3);

	for (const unsubscribe of unsubs) {
		unsubscribe();
	}
	assert.equal(conn.subscriberCount(PushCodes.Advert), 0, 'unsubscribed');
	assert.equal(conn.subscriberCount(PushCodes.SendConfirmed), 0, 'unsubscribed');
	assert.equal(conn.messageConsumerCount(), 0, 'message stream unsubscribed');
});
