/**
 * Type surface for the bundled meshcore.js TCP transport.
 *
 * The implementation (`meshcore-tcp.js`) is generated into `dist/` at build time by
 * `scripts/bundle-vendor.mjs` and is intentionally absent from source — only this
 * declaration exists here so the dynamic `import()`s type-check.
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

/** Parsed app-data of an advert (name, location, node type). */
export interface AdvertAppData {
	type: string | null;
	lat: number | null;
	lon: number | null;
	name: string | null;
	feat1: number | null;
	feat2: number | null;
}

export declare class Advert {
	publicKey: Uint8Array;
	timestamp: number;
	signature: Uint8Array;
	appData: Uint8Array;
	parsed: AdvertAppData;
	static fromBytes(bytes: Uint8Array): Advert;
	/** Ed25519 verification over publicKey || timestamp || appData. */
	isVerified(): Promise<boolean>;
	getTypeString(): string | null;
	parseAppData(): AdvertAppData;
}

/**
 * An on-air MeshCore frame. Header, optional transport codes, packed path length, path
 * hashes and the payload — see `Packet::readFrom` in the firmware.
 */
export declare class Packet {
	static readonly ROUTE_TYPE_TRANSPORT_FLOOD: number;
	static readonly ROUTE_TYPE_FLOOD: number;
	static readonly ROUTE_TYPE_DIRECT: number;
	static readonly ROUTE_TYPE_TRANSPORT_DIRECT: number;
	static readonly PAYLOAD_TYPE_REQ: number;
	static readonly PAYLOAD_TYPE_RESPONSE: number;
	static readonly PAYLOAD_TYPE_TXT_MSG: number;
	static readonly PAYLOAD_TYPE_ACK: number;
	static readonly PAYLOAD_TYPE_ADVERT: number;
	static readonly PAYLOAD_TYPE_GRP_TXT: number;
	static readonly PAYLOAD_TYPE_GRP_DATA: number;
	static readonly PAYLOAD_TYPE_ANON_REQ: number;
	static readonly PAYLOAD_TYPE_PATH: number;
	static readonly PAYLOAD_TYPE_TRACE: number;
	static readonly PAYLOAD_TYPE_RAW_CUSTOM: number;

	header: number;
	pathLen: number;
	path: Uint8Array;
	payload: Uint8Array;
	transportCode1: number | null;
	transportCode2: number | null;
	route_type: number;
	route_type_string: string | null;
	payload_type: number;
	payload_type_string: string | null;
	payload_version: number;
	is_marked_do_not_retransmit: boolean;

	static fromBytes(bytes: Uint8Array): Packet;
	static extractPathHashSize(pathLen: number): number;
	static extractPathHashCount(pathLen: number): number;
	getPathHashSize(): number;
	getPathHashCount(): number;
	getPathHashes(): Uint8Array[];
	parsePayload(): Record<string, unknown> | null;
}

export declare class CayenneLpp {
	static decode(bytes: Uint8Array): unknown;
}

/** Convert an Ed25519 public key to its Montgomery (X25519) form. */
export declare function edwardsToMontgomeryPub(publicKey: Uint8Array): Uint8Array;

export declare const x25519: {
	getSharedSecret(privateScalar: Uint8Array, publicKey: Uint8Array): Uint8Array;
};

/** Just enough of @noble's ed25519 to sign from an expanded (scalar || prefix) key. */
export declare const ed25519: {
	CURVE: { n: bigint };
	Point: {
		BASE: { multiply(scalar: bigint): { toBytes(): Uint8Array } };
	};
};

export default TCPConnection;
