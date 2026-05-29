import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
	ConnectionManager,
	SharedConnection,
	type MeshConnection,
} from '../dist/nodes/shared/ConnectionManager.js';

function delay(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Mock that mimics the meshcore.js Connection API surface we depend on:
 * a custom EventEmitter keyed by string|number, connect()/close(), and a couple
 * of high-level command methods. emit() is synchronous here for deterministic tests.
 */
class MockMeshConnection implements MeshConnection {
	[method: string]: unknown;

	private readonly listeners = new Map<string | number, Array<(...a: unknown[]) => void>>();

	connectCalls = 0;
	closed = false;
	autoConnect = true;

	on(event: string | number, cb: (...a: unknown[]) => void): void {
		const list = this.listeners.get(event) ?? [];
		list.push(cb);
		this.listeners.set(event, list);
	}

	off(event: string | number, cb: (...a: unknown[]) => void): void {
		const list = this.listeners.get(event);
		if (list) {
			this.listeners.set(
				event,
				list.filter((fn) => fn !== cb),
			);
		}
	}

	once(event: string | number, cb: (...a: unknown[]) => void): void {
		const wrapper = (...a: unknown[]) => {
			this.off(event, wrapper);
			cb(...a);
		};
		this.on(event, wrapper);
	}

	emit(event: string | number, ...args: unknown[]): void {
		for (const cb of [...(this.listeners.get(event) ?? [])]) {
			cb(...args);
		}
	}

	connect(): void {
		this.connectCalls++;
		if (this.autoConnect) {
			this.emit('connected');
		}
	}

	close(): void {
		this.closed = true;
	}

	/** Simulate the device dropping the socket. */
	drop(): void {
		this.emit('disconnected');
	}

	async getSelfInfo(): Promise<{ ok: true }> {
		return { ok: true };
	}

	/** Queue drained by the message-hub; refilled by tests, emptied on each drain. */
	waiting: unknown[] = [];
	getWaitingMessagesCalls = 0;
	async getWaitingMessages(): Promise<unknown[]> {
		this.getWaitingMessagesCalls++;
		return this.waiting.splice(0);
	}
}

const baseConfig = {
	host: '10.0.0.1',
	port: 5000,
	connectTimeoutMs: 200,
	commandTimeoutMs: 500,
	reconnectBaseDelayMs: 5,
	reconnectMaxDelayMs: 20,
};

test('ref-counted: shares one connection across consumers, connects once', async () => {
	ConnectionManager._resetForTests();
	let created = 0;
	let last: MockMeshConnection | null = null;
	ConnectionManager.setFactory(() => {
		created++;
		last = new MockMeshConnection();
		return last;
	});

	const a = await ConnectionManager.acquire(baseConfig);
	const b = await ConnectionManager.acquire(baseConfig);

	assert.equal(created, 1, 'factory called once for two acquires of same device');
	assert.equal(a, b, 'same SharedConnection instance returned');
	assert.equal(a.consumers, 2);
	assert.equal(a.connected, true);
	assert.equal(last!.connectCalls, 1, 'underlying connect() called once');

	ConnectionManager.release(a);
	ConnectionManager.release(b);
});

test('teardown: closes underlying connection when last consumer releases', async () => {
	ConnectionManager._resetForTests();
	let last: MockMeshConnection | null = null;
	ConnectionManager.setFactory(() => {
		last = new MockMeshConnection();
		return last;
	});

	const a = await ConnectionManager.acquire(baseConfig);
	const b = await ConnectionManager.acquire(baseConfig);

	ConnectionManager.release(a);
	assert.equal(last!.closed, false, 'still open while one consumer remains');
	assert.equal(a.consumers, 1);

	ConnectionManager.release(b);
	assert.equal(last!.closed, true, 'closed after last consumer leaves');
	assert.equal(a.consumers, 0);

	// a fresh acquire creates a new connection (the old entry was dropped)
	const c = await ConnectionManager.acquire(baseConfig);
	assert.notEqual(c, a, 'a new SharedConnection is created after teardown');
	ConnectionManager.release(c);
});

test('command queue serializes concurrent run() calls', async () => {
	ConnectionManager._resetForTests();
	ConnectionManager.setFactory(() => new MockMeshConnection());
	const conn = await ConnectionManager.acquire(baseConfig);

	const order: string[] = [];
	const p1 = conn.run(async () => {
		order.push('a:start');
		await delay(30);
		order.push('a:end');
		return 'a';
	});
	const p2 = conn.run(async () => {
		order.push('b:start');
		await delay(1);
		order.push('b:end');
		return 'b';
	});

	const [r1, r2] = await Promise.all([p1, p2]);
	assert.equal(r1, 'a');
	assert.equal(r2, 'b');
	assert.deepEqual(
		order,
		['a:start', 'a:end', 'b:start', 'b:end'],
		'second command must not start until the first finishes',
	);

	ConnectionManager.release(conn);
});

test('queue continues after a failing command', async () => {
	ConnectionManager._resetForTests();
	ConnectionManager.setFactory(() => new MockMeshConnection());
	const conn = await ConnectionManager.acquire(baseConfig);

	await assert.rejects(
		conn.run(async () => {
			throw new Error('boom');
		}),
		/boom/,
	);
	const ok = await conn.run(async () => 'still-works');
	assert.equal(ok, 'still-works');

	ConnectionManager.release(conn);
});

test('push fan-out: multiple subscribers, unsubscribe, dispatcher lifecycle', async () => {
	ConnectionManager._resetForTests();
	let last: MockMeshConnection | null = null;
	ConnectionManager.setFactory(() => {
		last = new MockMeshConnection();
		return last;
	});
	const conn = await ConnectionManager.acquire(baseConfig);

	const received1: unknown[] = [];
	const received2: unknown[] = [];
	const code = 0x83; // PushCodes.MsgWaiting

	const unsub1 = conn.subscribe(code, (p) => received1.push(p));
	const unsub2 = conn.subscribe(code, (p) => received2.push(p));

	last!.emit(code, { n: 1 });
	assert.deepEqual(received1, [{ n: 1 }]);
	assert.deepEqual(received2, [{ n: 1 }]);

	unsub1();
	last!.emit(code, { n: 2 });
	assert.deepEqual(received1, [{ n: 1 }], 'unsubscribed handler stops receiving');
	assert.deepEqual(received2, [{ n: 1 }, { n: 2 }]);

	unsub2();
	last!.emit(code, { n: 3 });
	assert.deepEqual(received2, [{ n: 1 }, { n: 2 }], 'dispatcher detached after last unsub');

	ConnectionManager.release(conn);
});

test('reconnect: re-arms subscriptions after a disconnect', async () => {
	ConnectionManager._resetForTests();
	const created: MockMeshConnection[] = [];
	ConnectionManager.setFactory(() => {
		const c = new MockMeshConnection();
		created.push(c);
		return c;
	});
	const conn = await ConnectionManager.acquire(baseConfig);

	const received: unknown[] = [];
	conn.subscribe(0x83, (p) => received.push(p));

	// drop the socket; SharedConnection should reconnect on a new underlying conn
	created[0].drop();
	assert.equal(conn.connected, false);

	// wait for reconnect backoff to establish a fresh connection
	for (let i = 0; i < 50 && created.length < 2; i++) {
		await delay(5);
	}
	assert.ok(created.length >= 2, 'a new underlying connection was created');
	assert.equal(conn.connected, true, 'reconnected');

	// the subscription must be re-armed on the new connection
	created[created.length - 1].emit(0x83, { after: 'reconnect' });
	assert.deepEqual(received, [{ after: 'reconnect' }]);

	ConnectionManager.release(conn);
});

test('connect timeout: acquire rejects and registry entry is dropped', async () => {
	ConnectionManager._resetForTests();
	ConnectionManager.setFactory(() => {
		const c = new MockMeshConnection();
		c.autoConnect = false; // never emits "connected"
		return c;
	});

	await assert.rejects(
		ConnectionManager.acquire({ ...baseConfig, connectTimeoutMs: 30 }),
		/Timed out waiting/,
	);

	// a subsequent acquire should start fresh (entry was dropped), and succeed
	ConnectionManager.setFactory(() => new MockMeshConnection());
	const conn = await ConnectionManager.acquire(baseConfig);
	assert.equal(conn.connected, true);
	ConnectionManager.release(conn);
});

test('expectPush resolves on matching push (future + buffered) and times out', async () => {
	ConnectionManager._resetForTests();
	let last: MockMeshConnection | null = null;
	ConnectionManager.setFactory(() => {
		last = new MockMeshConnection();
		return last;
	});
	const conn = await ConnectionManager.acquire(baseConfig);

	// future match: arm match(), then push arrives
	const e1 = conn.expectPush<{ ackCode: number }>(0x82);
	const p1 = e1.match((p) => p.ackCode === 5, 200);
	last!.emit(0x82, { ackCode: 5 });
	assert.deepEqual(await p1, { ackCode: 5 });

	// buffered match: push arrives before match()
	const e2 = conn.expectPush<{ ackCode: number }>(0x82);
	last!.emit(0x82, { ackCode: 7 });
	assert.deepEqual(await e2.match((p) => p.ackCode === 7, 200), { ackCode: 7 });

	// timeout
	const e3 = conn.expectPush<{ ackCode: number }>(0x82);
	assert.equal(await e3.match((p) => p.ackCode === 999, 30), null);

	ConnectionManager.release(conn);
});

test('message-hub: a single drain fans out to all consumers (no race)', async () => {
	ConnectionManager._resetForTests();
	let last: MockMeshConnection | null = null;
	ConnectionManager.setFactory(() => {
		last = new MockMeshConnection();
		return last;
	});
	const conn = await ConnectionManager.acquire(baseConfig);

	const a: unknown[] = [];
	const b: unknown[] = [];
	const ua = conn.subscribeMessages((m) => a.push(m));
	const ub = conn.subscribeMessages((m) => b.push(m));
	await delay(5); // initial drain (empty)

	last!.waiting = [{ contactMessage: { text: 'x' } }];
	last!.emit(0x83); // MsgWaiting
	await delay(15);

	assert.deepEqual(a, [{ contactMessage: { text: 'x' } }]);
	assert.deepEqual(b, [{ contactMessage: { text: 'x' } }], 'both consumers received it — no race');
	assert.equal(last!.getWaitingMessagesCalls, 2, 'one drain on subscribe + one per signal, not per consumer');

	ua();
	ub();
	ConnectionManager.release(conn);
});

void SharedConnection;
