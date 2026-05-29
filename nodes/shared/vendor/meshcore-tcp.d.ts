/**
 * Type surface for the bundled meshcore.js TCP transport.
 *
 * The implementation (`meshcore-tcp.js`) is generated into `dist/` at build time by
 * `scripts/bundle-vendor.mjs` and is intentionally absent from source — only this
 * declaration exists here so the dynamic `import()` in ConnectionManager type-checks.
 */
declare class TCPConnection {
	constructor(host: string, port: number);
	on(event: string | number, callback: (...args: unknown[]) => void): void;
	off(event: string | number, callback: (...args: unknown[]) => void): void;
	once(event: string | number, callback: (...args: unknown[]) => void): void;
	emit(event: string | number, ...args: unknown[]): void;
	connect(): Promise<void> | void;
	close(): void;
	[method: string]: unknown;
}

export default TCPConnection;
