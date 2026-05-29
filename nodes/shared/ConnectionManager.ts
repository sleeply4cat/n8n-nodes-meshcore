/* eslint-disable @n8n/community-nodes/require-node-api-error --
 * This file is shared infrastructure, not an n8n node. The require-node-api-error
 * rule targets node execute() bodies (where a NodeApiError with this.getNode() is
 * expected); here we only re-throw caught errors after bookkeeping cleanup. */

/**
 * Shared TCP connection layer for the MeshCore nodes.
 *
 * The WiFi companion firmware accepts exactly ONE TCP client at a time and drops
 * any existing client when a new one connects. Every node (action + trigger) for a
 * given device must therefore funnel through a single shared connection. This module
 * provides a reference-counted registry of such connections keyed by "host:port".
 */

/**
 * The subset of the meshcore.js Connection API we rely on. meshcore.js ships no
 * types; its EventEmitter is a custom one keyed by string OR numeric code, with
 * listeners fired asynchronously (setTimeout 0). High-level command methods
 * (getSelfInfo, sendTextMessage, ...) are accessed dynamically via `run()`.
 */
export interface MeshConnection {
	on(event: string | number, callback: (...args: unknown[]) => void): void;
	off(event: string | number, callback: (...args: unknown[]) => void): void;
	once(event: string | number, callback: (...args: unknown[]) => void): void;
	emit(event: string | number, ...args: unknown[]): void;
	connect(): Promise<void> | void;
	close(): void;

	// High-level meshcore.js command methods we wrap (typed as optional because the
	// transport object is dynamic; missing ones throw via callMethod()).
	getSelfInfo?(timeoutMillis?: number): Promise<unknown>;
	getContacts?(): Promise<unknown[]>;
	findContactByName?(name: string): Promise<unknown>;
	sendTextMessage?(contactPublicKey: Uint8Array, text: string, type?: number): Promise<unknown>;
	sendChannelTextMessage?(channelIdx: number, text: string): Promise<unknown>;
	getWaitingMessages?(): Promise<unknown[]>;

	// any other command method is reachable dynamically
	[method: string]: unknown;
}

export type ConnectionFactory = (
	host: string,
	port: number,
) => Promise<MeshConnection> | MeshConnection;

export type PushHandler = (payload: unknown) => void;

export interface SharedConnectionConfig {
	host: string;
	port: number;
	/** Max time to wait for the "connected" event after initiating connect(). */
	connectTimeoutMs?: number;
	/** Max time a single queued command may run before it is considered failed. */
	commandTimeoutMs?: number;
	/** Base delay between reconnect attempts (exponential backoff up to a cap). */
	reconnectBaseDelayMs?: number;
	reconnectMaxDelayMs?: number;
}

const DEFAULTS = {
	connectTimeoutMs: 10000,
	commandTimeoutMs: 15000,
	reconnectBaseDelayMs: 1000,
	reconnectMaxDelayMs: 30000,
};

/**
 * Default factory: load the meshcore.js TCP transport that `scripts/bundle-vendor.mjs`
 * bundles into `dist/.../vendor/meshcore-tcp.js`. It is a local CommonJS module, so the
 * import resolves synchronously to a plain require() at runtime — no external runtime
 * dependency and no ESM-in-CJS interop hazard.
 */
const defaultFactory: ConnectionFactory = async (host, port) => {
	const { default: TCPConnection } = await import('./vendor/meshcore-tcp');
	return new TCPConnection(host, port);
};

function delay(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Wraps a single meshcore.js connection and provides:
 *  - a serialized command queue (responses are matched by event code, not request
 *    id, so concurrent commands would mismatch — serialization is mandatory),
 *  - push fan-out so multiple triggers can subscribe to the same device,
 *  - reconnect with subscription re-arm.
 */
export class SharedConnection {
	readonly key: string;

	private readonly config: Required<SharedConnectionConfig>;
	private readonly factory: ConnectionFactory;

	private connection: MeshConnection | null = null;
	private refCount = 0;
	private queue: Promise<unknown> = Promise.resolve();
	private connectPromise: Promise<void> | null = null;

	/** code -> set of subscriber handlers (our fan-out registry). */
	private readonly subscribers = new Map<number, Set<PushHandler>>();
	/** code -> the single dispatcher attached to the underlying connection. */
	private readonly dispatchers = new Map<number, (...args: unknown[]) => void>();

	/** Message-hub consumers: one shared MSG_WAITING drainer fans out to all of these. */
	private readonly messageConsumers = new Set<(message: unknown) => void>();
	private messageHubUnsub: (() => void) | null = null;
	private draining = false;

	private _connected = false;
	private closing = false;
	private reconnecting = false;

	constructor(config: SharedConnectionConfig, factory: ConnectionFactory = defaultFactory) {
		this.config = { ...DEFAULTS, ...config };
		this.factory = factory;
		this.key = `${config.host}:${config.port}`;
	}

	get connected(): boolean {
		return this._connected;
	}

	get consumers(): number {
		return this.refCount;
	}

	/** Increment ref-count; establish the connection on the first consumer. */
	async acquire(): Promise<void> {
		this.refCount++;
		this.closing = false;
		if (this._connected) {
			return;
		}
		// guard against concurrent acquires racing into multiple connectOnce() calls
		if (!this.connectPromise) {
			this.connectPromise = this.connectOnce().finally(() => {
				this.connectPromise = null;
			});
		}
		try {
			await this.connectPromise;
		} catch (error) {
			this.refCount = Math.max(0, this.refCount - 1);
			throw error;
		}
	}

	/** Decrement ref-count; tear the connection down when the last consumer leaves. */
	release(): void {
		this.refCount = Math.max(0, this.refCount - 1);
		if (this.refCount === 0) {
			this.teardown();
		}
	}

	/** Run a command against the connection, serialized behind all prior commands. */
	run<T>(fn: (connection: MeshConnection) => Promise<T>): Promise<T> {
		const result = this.queue.then(() => {
			if (!this.connection || !this._connected) {
				throw new Error(`MeshCore connection ${this.key} is not connected`);
			}
			return this.withTimeout(fn(this.connection), this.config.commandTimeoutMs);
		});
		// keep the chain alive regardless of this command's success/failure
		this.queue = result.then(
			() => undefined,
			() => undefined,
		);
		return result;
	}

	/** Subscribe a handler to a push/response code. Returns an unsubscribe function. */
	subscribe(code: number, handler: PushHandler): () => void {
		let handlers = this.subscribers.get(code);
		if (!handlers) {
			handlers = new Set();
			this.subscribers.set(code, handlers);
			this.attachDispatcher(code);
		}
		handlers.add(handler);

		return () => {
			const set = this.subscribers.get(code);
			if (!set) {
				return;
			}
			set.delete(handler);
			if (set.size === 0) {
				this.subscribers.delete(code);
				this.detachDispatcher(code);
			}
		};
	}

	/**
	 * Buffer pushes of `code`, then resolve with the first one matching a predicate
	 * (checked against the buffer and future pushes) within a timeout, else null. Arm this
	 * BEFORE sending the triggering command, then call `match()` once the correlation id
	 * (e.g. an ack CRC from the SENT response) is known — this avoids losing a fast push.
	 */
	expectPush<T = unknown>(code: number): {
		match: (predicate: (payload: T) => boolean, timeoutMs: number) => Promise<T | null>;
		cancel: () => void;
	} {
		const buffer: T[] = [];
		let predicate: ((payload: T) => boolean) | null = null;
		let onMatch: ((payload: T) => void) | null = null;
		const unsubscribe = this.subscribe(code, (payload) => {
			const value = payload as T;
			if (predicate && onMatch) {
				if (predicate(value)) {
					onMatch(value);
				}
			} else {
				buffer.push(value);
			}
		});
		return {
			match: (pred, timeoutMs) =>
				new Promise<T | null>((resolve) => {
					let done = false;
					const finish = (value: T | null) => {
						if (done) {
							return;
						}
						done = true;
						clearTimeout(timer);
						unsubscribe();
						resolve(value);
					};
					const timer = setTimeout(() => finish(null), timeoutMs);
					const buffered = buffer.find(pred);
					if (buffered !== undefined) {
						finish(buffered);
						return;
					}
					predicate = pred;
					onMatch = (value) => finish(value);
				}),
			cancel: unsubscribe,
		};
	}

	/**
	 * Register a consumer of incoming messages. A single shared MSG_WAITING drainer pulls
	 * the device queue once per signal and dispatches each parsed message to every consumer
	 * (so multiple triggers / await-reply waiters never race over the drain). Returns an
	 * unsubscribe function.
	 */
	subscribeMessages(handler: (message: unknown) => void): () => void {
		this.messageConsumers.add(handler);
		if (!this.messageHubUnsub) {
			// 0x83 = PushCodes.MsgWaiting
			this.messageHubUnsub = this.subscribe(0x83, () => void this.drainAndDispatch());
			void this.drainAndDispatch(); // drain anything already queued
		}
		return () => {
			this.messageConsumers.delete(handler);
			if (this.messageConsumers.size === 0 && this.messageHubUnsub) {
				this.messageHubUnsub();
				this.messageHubUnsub = null;
			}
		};
	}

	private async drainAndDispatch(): Promise<void> {
		if (this.draining) {
			return;
		}
		this.draining = true;
		try {
			const messages = await this.run((c) =>
				(c.getWaitingMessages as () => Promise<unknown[]>)(),
			);
			for (const message of messages) {
				for (const consumer of [...this.messageConsumers]) {
					try {
						consumer(message);
					} catch {
						// a misbehaving consumer must not break fan-out for the others
					}
				}
			}
		} catch {
			// transient drain failure — the next MSG_WAITING retries
		} finally {
			this.draining = false;
		}
	}

	// --- internals -----------------------------------------------------------

	private attachDispatcher(code: number): void {
		if (this.dispatchers.has(code) || !this.connection) {
			return;
		}
		const dispatcher = (payload: unknown) => {
			const handlers = this.subscribers.get(code);
			if (!handlers) {
				return;
			}
			for (const handler of handlers) {
				try {
					handler(payload);
				} catch {
					// a misbehaving subscriber must not break fan-out for the others
				}
			}
		};
		this.dispatchers.set(code, dispatcher);
		this.connection.on(code, dispatcher);
	}

	private detachDispatcher(code: number): void {
		const dispatcher = this.dispatchers.get(code);
		if (dispatcher && this.connection) {
			this.connection.off(code, dispatcher);
		}
		this.dispatchers.delete(code);
	}

	/** Re-attach all dispatchers to a freshly (re)connected underlying connection. */
	private rearmDispatchers(): void {
		this.dispatchers.clear();
		for (const code of this.subscribers.keys()) {
			this.attachDispatcher(code);
		}
	}

	private async connectOnce(): Promise<void> {
		const connection = await this.factory(this.config.host, this.config.port);
		this.connection = connection;

		connection.on('disconnected', () => this.onDisconnected());

		const connectedPromise = this.waitForConnected(connection);
		await connection.connect();
		await connectedPromise;

		this._connected = true;
		this.rearmDispatchers();

		// after a (re)connect, drain anything queued during downtime
		if (this.messageConsumers.size > 0) {
			void this.drainAndDispatch();
		}
	}

	private waitForConnected(connection: MeshConnection): Promise<void> {
		return new Promise<void>((resolve, reject) => {
			let settled = false;
			const onConnected = () => {
				if (settled) {
					return;
				}
				settled = true;
				clearTimeout(timer);
				resolve();
			};
			const timer = setTimeout(() => {
				if (settled) {
					return;
				}
				settled = true;
				connection.off('connected', onConnected);
				reject(
					new Error(
						`Timed out waiting for MeshCore device ${this.key} to connect after ${this.config.connectTimeoutMs}ms`,
					),
				);
			}, this.config.connectTimeoutMs);
			connection.once('connected', onConnected);
		});
	}

	private onDisconnected(): void {
		this._connected = false;
		if (this.closing || this.refCount === 0) {
			return;
		}
		void this.reconnect();
	}

	private async reconnect(): Promise<void> {
		if (this.reconnecting) {
			return;
		}
		this.reconnecting = true;
		let attempt = 0;
		while (!this.closing && this.refCount > 0 && !this._connected) {
			const wait = Math.min(
				this.config.reconnectBaseDelayMs * 2 ** attempt,
				this.config.reconnectMaxDelayMs,
			);
			await delay(wait);
			if (this.closing || this.refCount === 0) {
				break;
			}
			try {
				await this.connectOnce();
				// re-announce the app to the device after a reconnect (AppStart -> SelfInfo)
				if (typeof this.connection?.getSelfInfo === 'function') {
					await this.run((c) => (c.getSelfInfo as () => Promise<unknown>)()).catch(() => undefined);
				}
			} catch {
				attempt++;
			}
		}
		this.reconnecting = false;
	}

	private teardown(): void {
		this.closing = true;
		this._connected = false;
		for (const code of [...this.dispatchers.keys()]) {
			this.detachDispatcher(code);
		}
		this.subscribers.clear();
		this.messageConsumers.clear();
		this.messageHubUnsub = null;
		try {
			this.connection?.close();
		} catch {
			// ignore close errors
		}
		this.connection = null;
	}

	private withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
		return new Promise<T>((resolve, reject) => {
			const timer = setTimeout(() => {
				reject(new Error(`MeshCore command on ${this.key} timed out after ${ms}ms`));
			}, ms);
			promise.then(
				(value) => {
					clearTimeout(timer);
					resolve(value);
				},
				(error) => {
					clearTimeout(timer);
					reject(error as Error);
				},
			);
		});
	}
}

/** Module-level singleton registry of shared connections, keyed by "host:port". */
export class ConnectionManager {
	private static readonly connections = new Map<string, SharedConnection>();
	private static factory: ConnectionFactory = defaultFactory;

	/** Override the connection factory (used by tests to inject a mock). */
	static setFactory(factory: ConnectionFactory): void {
		ConnectionManager.factory = factory;
	}

	/** Acquire (creating if needed) the shared connection for a device. */
	static async acquire(config: SharedConnectionConfig): Promise<SharedConnection> {
		const key = `${config.host}:${config.port}`;
		let shared = ConnectionManager.connections.get(key);
		if (!shared) {
			shared = new SharedConnection(config, ConnectionManager.factory);
			ConnectionManager.connections.set(key, shared);
		}
		try {
			await shared.acquire();
		} catch (error) {
			// failed first connect: drop the now-unreferenced entry from the registry
			if (shared.consumers === 0) {
				ConnectionManager.connections.delete(key);
			}
			throw error;
		}
		return shared;
	}

	/** Release a previously acquired shared connection. */
	static release(shared: SharedConnection): void {
		shared.release();
		if (shared.consumers === 0) {
			ConnectionManager.connections.delete(shared.key);
		}
	}

	/** Test helper: drop all tracked connections without releasing (no teardown). */
	static _resetForTests(): void {
		ConnectionManager.connections.clear();
		ConnectionManager.factory = defaultFactory;
	}
}
