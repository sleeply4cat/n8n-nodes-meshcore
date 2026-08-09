/**
 * Decode and build MeshCore on-air packets, independently of any device.
 *
 * The frame layout and the payload parsing come from meshcore.js's own `Packet` and
 * `Advert`, which are already inside our vendor bundle (`connection.js` imports them),
 * so using them here adds nothing to the published package. What this module adds on top
 * is the part meshcore.js does not do: decrypting payloads.
 *
 * Crypto mirrors the firmware (`Utils::encryptThenMAC` / `MACThenDecrypt`):
 *   ciphertext = AES-128-ECB(secret[0..15], zero-padded plaintext)
 *   mac        = HMAC-SHA256(secret padded to 32, ciphertext)[0..1]
 *   blob       = mac || ciphertext
 * Group traffic keys that with the channel secret; direct traffic keys it with an ECDH
 * shared secret (`LocalIdentity::calcSharedSecret` -> `ed25519_key_exchange`), which is
 * X25519 between our private scalar and the peer's public key converted to Montgomery
 * form.
 *
 * The MAC doubles as key identification: a wrong key simply fails the check, so trying a
 * list of candidate keys is both correct and cheap.
 */
import { createDecipheriv, createHash, createHmac } from 'node:crypto';

import { computePacketHash, encryptThenMac } from './channelHash';
import { normalizeBytesDeep } from './params';

/**
 * Payload types meshcore.js's `getPayloadTypeString` does not name. Its table predates
 * these two, so without them the decoder reports a null type for real traffic — CONTROL
 * shows up on any mesh using path discovery.
 */
const EXTRA_PAYLOAD_TYPE_NAMES: Record<number, string> = {
	0x0a: 'MULTIPART',
	0x0b: 'CONTROL',
};

import type {
	Advert as AdvertClass,
	Packet as PacketClass,
	ed25519 as Ed25519,
	edwardsToMontgomeryPub as EdwardsToMontgomeryPub,
	x25519 as X25519,
} from './vendor/meshcore-tcp';

const CIPHER_KEY_SIZE = 16;
const CIPHER_MAC_SIZE = 2;
const CIPHER_BLOCK_SIZE = 16;
/** `Utils::encryptThenMAC` keys the HMAC with PUB_KEY_SIZE bytes. */
const SECRET_FIELD_SIZE = 32;
/** The device exports `prv_key` as scalar(32) || prefix(32) — orlp's ed25519 layout. */
export const PRIVATE_KEY_SIZE = 64;
export const PUBLIC_KEY_SIZE = 32;

type VendorModule = {
	Packet: typeof PacketClass;
	Advert: typeof AdvertClass;
	edwardsToMontgomeryPub: typeof EdwardsToMontgomeryPub;
	x25519: typeof X25519;
	ed25519: typeof Ed25519;
};

let vendorPromise: Promise<VendorModule> | null = null;

/** Load the bundled meshcore.js pieces once. */
export async function loadVendor(): Promise<VendorModule> {
	if (!vendorPromise) {
		vendorPromise = import('./vendor/meshcore-tcp') as unknown as Promise<VendorModule>;
	}
	return vendorPromise;
}

/** Test seam: inject the vendor module instead of loading the built bundle. */
export function _setVendorForTests(module: VendorModule | null): void {
	vendorPromise = module ? Promise.resolve(module) : null;
}

/**
 * Clamp a 32-byte scalar the way `lib/ed25519/key_exchange.c` does before using it, and
 * the way X25519 requires. A key created on a device is already clamped, so this is a
 * no-op there — but reading the scalar raw in one place and clamped in another (x25519
 * clamps internally) makes the derived public key disagree with the shared secret for any
 * key that is not, which is a silent wrong answer rather than an error.
 */
function clampScalar(scalar: Buffer): Buffer {
	const e = Buffer.from(scalar.subarray(0, 32));
	e[0] &= 248;
	e[31] &= 63;
	e[31] |= 64;
	return e;
}

function scalarToBigInt(scalar: Buffer): bigint {
	let n = 0n;
	for (let i = scalar.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(scalar[i]);
	return n;
}

function secretField(secret: Buffer): Buffer {
	const field = Buffer.alloc(SECRET_FIELD_SIZE);
	secret.copy(field, 0, 0, Math.min(secret.length, SECRET_FIELD_SIZE));
	return field;
}

/**
 * Inverse of `Utils::encryptThenMAC`. Returns null when the MAC does not match, which is
 * also how "this key is not the right one" is reported.
 */
export function macThenDecrypt(secret: Buffer, blob: Buffer): Buffer | null {
	if (blob.length <= CIPHER_MAC_SIZE) return null;
	const ciphertext = blob.subarray(CIPHER_MAC_SIZE);
	if (ciphertext.length === 0 || ciphertext.length % CIPHER_BLOCK_SIZE !== 0) return null;

	const field = secretField(secret);
	const expected = createHmac('sha256', field)
		.update(ciphertext)
		.digest()
		.subarray(0, CIPHER_MAC_SIZE);
	if (!expected.equals(blob.subarray(0, CIPHER_MAC_SIZE))) return null;

	const decipher = createDecipheriv('aes-128-ecb', field.subarray(0, CIPHER_KEY_SIZE), null);
	decipher.setAutoPadding(false); // the firmware zero-pads; PKCS#7 would mangle the tail
	return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * X25519 between our private scalar and a peer's Ed25519 public key — the JS equivalent
 * of `LocalIdentity::calcSharedSecret`. Uses the @noble/curves code already in the bundle.
 */
export async function calcSharedSecret(privateKey: Buffer, peerPublicKey: Buffer): Promise<Buffer> {
	if (privateKey.length < PUBLIC_KEY_SIZE) {
		throw new Error(
			`Private key must be at least ${PUBLIC_KEY_SIZE} bytes (the device exports ${PRIVATE_KEY_SIZE}); got ${privateKey.length}`,
		);
	}
	if (peerPublicKey.length !== PUBLIC_KEY_SIZE) {
		throw new Error(`Public key must be ${PUBLIC_KEY_SIZE} bytes, got ${peerPublicKey.length}`);
	}
	const { edwardsToMontgomeryPub, x25519 } = await loadVendor();
	const montgomeryPub = edwardsToMontgomeryPub(Uint8Array.from(peerPublicKey));
	// The exported key already holds the clamped scalar in its first 32 bytes.
	const scalar = Uint8Array.from(privateKey.subarray(0, PUBLIC_KEY_SIZE));
	return Buffer.from(x25519.getSharedSecret(scalar, montgomeryPub));
}

/** Plaintext shape shared by group text and direct text messages. */
export interface DecodedText {
	timestamp: number;
	txtType: number;
	text: string;
}

/** Split the plaintext the firmware builds: timestamp(4 LE) | txt_type(1) | text | NUL. */
export function parseTextPlaintext(plaintext: Buffer): DecodedText | null {
	if (plaintext.length < 5) return null;
	const body = plaintext.subarray(5);
	const nul = body.indexOf(0);
	return {
		timestamp: plaintext.readUInt32LE(0),
		txtType: plaintext[4],
		text: body.subarray(0, nul === -1 ? body.length : nul).toString('utf8'),
	};
}

/**
 * The decrypted body of a PATH packet, per `Mesh::onRecvPacket`'s PATH branch:
 * packed path_len (1) | path (hops * hashSize) | extra_type (low 4 bits) | extra.
 * The tail may be zero-padded by the cipher, so `extra` is best-effort.
 */
export function parsePathPlaintext(plaintext: Buffer): Record<string, unknown> {
	if (plaintext.length < 1) return {};
	const pathLen = plaintext[0];
	const hashSize = (pathLen >> 6) + 1;
	const hops = pathLen & 0x3f;
	const pathBytes = hops * hashSize;
	if (1 + pathBytes > plaintext.length) return { pathLen, hops, pathHashSize: hashSize };
	const path = plaintext.subarray(1, 1 + pathBytes);
	const rest = plaintext.subarray(1 + pathBytes);
	return {
		pathLen,
		hops,
		pathHashSize: hashSize,
		returnPath: path.toString('hex'),
		extraType: rest.length > 0 ? rest[0] & 0x0f : null,
		extra: rest.length > 1 ? rest.subarray(1).toString('hex') : '',
	};
}

/** Split "<sender>: <text>" the way the trigger already splits received channel messages. */
export function splitAuthor(raw: string): { author: string; text: string } {
	const at = raw.indexOf(': ');
	return at === -1
		? { author: '', text: raw }
		: { author: raw.slice(0, at), text: raw.slice(at + 2) };
}

export interface ChannelKey {
	name: string;
	secret: Buffer;
}

export interface Identity {
	name: string;
	privateKey: Buffer;
}

export interface PeerKey {
	name: string;
	publicKey: Buffer;
}

export interface DecodeOptions {
	channels?: ChannelKey[];
	identities?: Identity[];
	peers?: PeerKey[];
	/** Verify advert signatures (Ed25519). Off by default: it costs a curve operation. */
	verifyAdverts?: boolean;
}

export interface DecodedPacket {
	routeType: number;
	routeTypeName: string | null;
	payloadType: number;
	payloadTypeName: string | null;
	payloadVersion: number;
	transportCode1: number | null;
	transportCode2: number | null;
	pathLen: number;
	hops: number;
	pathHashSize: number;
	path: string;
	pathHashes: string[];
	payload: string;
	packetHash: string;
	/** Whatever could be read without a key: advert fields, ack code, dest/src hashes. */
	parsed: Record<string, unknown> | null;
	/** Present when a key decrypted the payload. */
	decrypted?: Record<string, unknown>;
	/** Why no plaintext is present, when a payload is encrypted but no key matched. */
	undecryptedReason?: string;
}

const hex = (b: Uint8Array | Buffer): string => Buffer.from(b).toString('hex');

/**
 * Decrypt a group payload: channel hash (1) then the MAC+ciphertext blob. The MAC check
 * identifies the channel, so the leading hash byte is only a hint.
 */
async function decryptGroup(
	payload: Buffer,
	channels: ChannelKey[],
	isText: boolean,
): Promise<Record<string, unknown> | null> {
	if (payload.length < 2) return null;
	const blob = payload.subarray(1);
	for (const channel of channels) {
		const plaintext = macThenDecrypt(channel.secret, blob);
		if (!plaintext) continue;
		const base: Record<string, unknown> = { channelName: channel.name };
		if (!isText) {
			return { ...base, data: hex(plaintext) };
		}
		const parsedText = parseTextPlaintext(plaintext);
		if (!parsedText) return { ...base, data: hex(plaintext) };
		const { author, text } = splitAuthor(parsedText.text);
		return {
			...base,
			timestamp: parsedText.timestamp,
			txtType: parsedText.txtType,
			author,
			text,
			rawText: parsedText.text,
		};
	}
	return null;
}

/**
 * Decrypt a direct payload: dest hash (1), src hash (1), then MAC+ciphertext. The hashes
 * are one byte each, so they only narrow the candidates — the MAC decides.
 */
async function decryptDirect(
	payload: Buffer,
	identities: Identity[],
	peers: PeerKey[],
	isText: boolean,
): Promise<Record<string, unknown> | null> {
	if (payload.length < 4) return null;
	const destHash = payload[0];
	const srcHash = payload[1];
	const blob = payload.subarray(2);

	for (const identity of identities) {
		for (const peer of peers) {
			// cheap pre-filter: the src hash is the first byte of the sender's public key
			if (peer.publicKey[0] !== srcHash && peer.publicKey[0] !== destHash) continue;
			let shared: Buffer;
			try {
				shared = await calcSharedSecret(identity.privateKey, peer.publicKey);
			} catch {
				continue; // malformed key pair; other candidates may still work
			}
			const plaintext = macThenDecrypt(shared, blob);
			if (!plaintext) continue;
			const base: Record<string, unknown> = {
				identityName: identity.name,
				peerName: peer.name,
				peerPublicKey: hex(peer.publicKey),
				destHash: destHash.toString(16).padStart(2, '0'),
				srcHash: srcHash.toString(16).padStart(2, '0'),
			};
			if (!isText) {
				return { ...base, data: hex(plaintext) };
			}
			const parsedText = parseTextPlaintext(plaintext);
			return parsedText ? { ...base, ...parsedText } : { ...base, data: hex(plaintext) };
		}
	}
	return null;
}

/** Decode one on-air frame, decrypting whatever the supplied keys can open. */
export async function decodePacket(
	bytes: Buffer,
	options: DecodeOptions = {},
): Promise<DecodedPacket> {
	const { Packet, Advert } = await loadVendor();
	const packet = Packet.fromBytes(Uint8Array.from(bytes));
	const payload = Buffer.from(packet.payload);

	const out: DecodedPacket = {
		routeType: packet.route_type,
		routeTypeName: packet.route_type_string,
		payloadType: packet.payload_type,
		payloadTypeName:
			packet.payload_type_string ?? EXTRA_PAYLOAD_TYPE_NAMES[packet.payload_type] ?? null,
		payloadVersion: packet.payload_version,
		transportCode1: packet.transportCode1,
		transportCode2: packet.transportCode2,
		pathLen: packet.pathLen,
		hops: packet.getPathHashCount(),
		pathHashSize: packet.getPathHashSize(),
		path: hex(packet.path),
		pathHashes: packet.getPathHashes().map(hex),
		payload: hex(payload),
		// the mesh's dedup key, so a decoded frame can be correlated with a sent one
		packetHash: hex(computePacketHash(packet.payload_type, payload)),
		parsed: null,
	};

	const channels = options.channels ?? [];
	const identities = options.identities ?? [];
	const peers = options.peers ?? [];

	if (packet.payload_type === Packet.PAYLOAD_TYPE_ADVERT) {
		const advert = Advert.fromBytes(packet.payload);
		out.parsed = {
			publicKey: hex(advert.publicKey),
			timestamp: advert.timestamp,
			...advert.parsed,
		};
		if (options.verifyAdverts) {
			try {
				(out.parsed as Record<string, unknown>).signatureValid = await advert.isVerified();
			} catch {
				(out.parsed as Record<string, unknown>).signatureValid = null;
			}
		}
		return out;
	}

	// everything meshcore.js can read without a key (ack code, dest/src hashes, …).
	// Its parsers hand back raw Uint8Arrays, which would serialise as {"0":1,"1":2,…};
	// normalise them to hex so the output is usable in a workflow.
	try {
		out.parsed = normalizeBytesDeep(packet.parsePayload()) as Record<string, unknown> | null;
	} catch {
		out.parsed = null;
	}

	const isGroup =
		packet.payload_type === Packet.PAYLOAD_TYPE_GRP_TXT ||
		packet.payload_type === Packet.PAYLOAD_TYPE_GRP_DATA;
	// `Mesh::onRecvPacket` handles PATH in the same branch as TXT_MSG/REQ/RESPONSE: the
	// same dest/src hash prefix, the same shared-secret key, the same MAC.
	const isDirect =
		packet.payload_type === Packet.PAYLOAD_TYPE_TXT_MSG ||
		packet.payload_type === Packet.PAYLOAD_TYPE_REQ ||
		packet.payload_type === Packet.PAYLOAD_TYPE_RESPONSE ||
		packet.payload_type === Packet.PAYLOAD_TYPE_PATH;

	if (isGroup) {
		const decrypted = await decryptGroup(
			payload,
			channels,
			packet.payload_type === Packet.PAYLOAD_TYPE_GRP_TXT,
		);
		if (decrypted) {
			out.decrypted = decrypted;
		} else {
			out.undecryptedReason = channels.length
				? 'no supplied channel secret matched this payload'
				: 'no channel secrets supplied';
		}
	} else if (isDirect) {
		const decrypted = await decryptDirect(
			payload,
			identities,
			peers,
			packet.payload_type === Packet.PAYLOAD_TYPE_TXT_MSG,
		);
		if (decrypted) {
			out.decrypted =
				packet.payload_type === Packet.PAYLOAD_TYPE_PATH
					? { ...decrypted, ...parsePathPlaintext(Buffer.from(String(decrypted.data), 'hex')) }
					: decrypted;
		} else if (!identities.length) {
			out.undecryptedReason = 'no private keys supplied';
		} else if (!peers.length) {
			out.undecryptedReason =
				'no peer public keys supplied — a direct payload carries only a 1-byte sender hash, so the sender key has to be known up front';
		} else {
			out.undecryptedReason = 'no supplied key pair matched this payload';
		}
	}

	return out;
}

// --- encode ------------------------------------------------------------------

const PH_TYPE_SHIFT = 2;
export const ROUTE_TYPE_TRANSPORT_FLOOD = 0x00;
export const ROUTE_TYPE_FLOOD = 0x01;
export const ROUTE_TYPE_DIRECT = 0x02;
export const ROUTE_TYPE_TRANSPORT_DIRECT = 0x03;
/** MAX_GROUP_DATA_LENGTH in the firmware; the 3-byte header is on top of it. */
export const MAX_GROUP_DATA_LENGTH = 184;

export interface FrameParts {
	routeType: number;
	payloadType: number;
	payloadVersion?: number;
	/** Bytes per hop in the path, 1-3; goes into the packed path-length byte. */
	pathHashSize?: number;
	/** Path hashes, `hops * pathHashSize` bytes. */
	path?: Buffer;
	payload: Buffer;
	/** Only for the TRANSPORT route types, which carry two 16-bit codes. */
	transportCodes?: [number, number];
}

/**
 * Assemble an on-air frame per `Packet::writeTo`: header, optional transport codes, the
 * packed path-length byte, the path, then the payload.
 *
 * The path-length byte is what every repeater reads to size the hash it appends, so
 * `pathHashSize` has to match the mesh's `path_hash_mode + 1`.
 */
export function buildFrame(parts: FrameParts): Buffer {
	const {
		routeType,
		payloadType,
		payloadVersion = 0,
		pathHashSize = 1,
		path = Buffer.alloc(0),
		payload,
		transportCodes,
	} = parts;

	if (routeType < 0 || routeType > 3) {
		throw new Error(`Route type must be 0-3 (got ${routeType})`);
	}
	if (payloadType < 0 || payloadType > 0x0f) {
		throw new Error(`Payload type must be 0-15 (got ${payloadType})`);
	}
	if (!Number.isInteger(pathHashSize) || pathHashSize < 1 || pathHashSize > 3) {
		throw new Error(
			`Path hash size must be 1, 2 or 3 (got ${pathHashSize}); the packed byte holds size - 1 in two bits and the firmware treats 4 as reserved`,
		);
	}
	if (path.length % pathHashSize !== 0) {
		throw new Error(
			`Path is ${path.length} bytes, which is not a whole number of ${pathHashSize}-byte hops`,
		);
	}
	const hops = path.length / pathHashSize;
	if (hops > 63) {
		throw new Error(`Path has ${hops} hops; the packed byte only holds 63`);
	}

	const needsTransportCodes =
		routeType === ROUTE_TYPE_TRANSPORT_FLOOD || routeType === ROUTE_TYPE_TRANSPORT_DIRECT;
	if (needsTransportCodes && !transportCodes) {
		throw new Error('The transport route types require two transport codes');
	}

	const header = ((payloadVersion & 0x03) << 6) | ((payloadType & 0x0f) << PH_TYPE_SHIFT) | routeType;
	const chunks: Buffer[] = [Buffer.from([header])];
	if (needsTransportCodes && transportCodes) {
		const codes = Buffer.alloc(4);
		codes.writeUInt16LE(transportCodes[0] & 0xffff, 0);
		codes.writeUInt16LE(transportCodes[1] & 0xffff, 2);
		chunks.push(codes);
	}
	chunks.push(Buffer.from([((pathHashSize - 1) << 6) | hops]), path, payload);
	return Buffer.concat(chunks);
}

// --- adverts -----------------------------------------------------------------

export const PAYLOAD_TYPE_ADVERT = 0x04;
/** MAX_ADVERT_DATA_SIZE in the firmware. */
export const MAX_ADVERT_DATA_SIZE = 96;
const ADV_LATLON_MASK = 0x10;
const ADV_FEAT1_MASK = 0x20;
const ADV_FEAT2_MASK = 0x40;
const ADV_NAME_MASK = 0x80;

export interface AdvertFields {
	/** ADV_TYPE_*: 1 chat, 2 repeater, 3 room, 4 sensor. */
	type: number;
	/** Required — `onAdvertRecv` drops an advert whose app data carries no name. */
	name: string;
	latitude?: number;
	longitude?: number;
	feat1?: number;
	feat2?: number;
}

/** `AdvertDataBuilder::encodeTo` — flags byte, then location, feats, name, in that order. */
export function encodeAdvertAppData(fields: AdvertFields): Buffer {
	const { type, name, latitude, longitude, feat1 = 0, feat2 = 0 } = fields;
	if (!name) {
		throw new Error('Advert name is required: the firmware drops an advert without one');
	}
	let flags = type & 0x0f;
	const parts: Buffer[] = [];

	if (latitude !== undefined && longitude !== undefined) {
		flags |= ADV_LATLON_MASK;
		const loc = Buffer.alloc(8);
		loc.writeInt32LE(Math.round(latitude * 1e6), 0);
		loc.writeInt32LE(Math.round(longitude * 1e6), 4);
		parts.push(loc);
	}
	// the firmware only emits a feat field when it is non-zero, so zero means "absent"
	if (feat1) {
		flags |= ADV_FEAT1_MASK;
		const b = Buffer.alloc(2);
		b.writeUInt16LE(feat1 & 0xffff, 0);
		parts.push(b);
	}
	if (feat2) {
		flags |= ADV_FEAT2_MASK;
		const b = Buffer.alloc(2);
		b.writeUInt16LE(feat2 & 0xffff, 0);
		parts.push(b);
	}
	flags |= ADV_NAME_MASK;
	parts.push(Buffer.from(name, 'utf8'));

	const appData = Buffer.concat([Buffer.from([flags]), ...parts]);
	if (appData.length > MAX_ADVERT_DATA_SIZE) {
		throw new Error(
			`Advert app data is ${appData.length} bytes; the firmware caps it at ${MAX_ADVERT_DATA_SIZE}`,
		);
	}
	return appData;
}

/**
 * Ed25519 signature from an EXPANDED private key, mirroring `lib/ed25519/sign.c`:
 *   r    = SHA512(prefix || msg) mod L
 *   R    = r·B
 *   hram = SHA512(R || A || msg) mod L
 *   S    = (hram·a + r) mod L
 *
 * This is hand-rolled because the device exports `scalar || prefix` (orlp's expanded
 * layout) while @noble's `ed25519.sign` takes the 32-byte SEED and expands it itself. The
 * seed is never exported and cannot be recovered from the expanded key, so the standard
 * API cannot be used at all here.
 */
export async function signWithExpandedKey(privateKey: Buffer, message: Buffer): Promise<Buffer> {
	if (privateKey.length !== PRIVATE_KEY_SIZE) {
		throw new Error(
			`Signing needs the full ${PRIVATE_KEY_SIZE}-byte private key (scalar and prefix); got ${privateKey.length}`,
		);
	}
	const { ed25519 } = await loadVendor();
	const L: bigint = ed25519.CURVE.n;

	const leToBig = (b: Buffer): bigint => {
		let n = 0n;
		for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
		return n;
	};
	const bigToLe = (n: bigint, length: number): Buffer => {
		const out = Buffer.alloc(length);
		let v = n;
		for (let i = 0; i < length; i++) {
			out[i] = Number(v & 0xffn);
			v >>= 8n;
		}
		return out;
	};
	const sha512 = (...parts: Buffer[]): Buffer => {
		const h = createHash('sha512');
		for (const p of parts) h.update(p);
		return h.digest();
	};

	const prefix = privateKey.subarray(32, 64);
	// A clamped scalar is larger than the group order; B has order L, so reducing first
	// gives the same point and keeps the scalar in the range multiply() accepts. Reducing
	// is equally harmless in S, which is computed mod L anyway.
	const a = scalarToBigInt(clampScalar(privateKey)) % L;
	const publicKey = Buffer.from(ed25519.Point.BASE.multiply(a).toBytes());

	const r = leToBig(sha512(prefix, message)) % L;
	const R = Buffer.from(ed25519.Point.BASE.multiply(r).toBytes());
	const hram = leToBig(sha512(R, publicKey, message)) % L;
	const S = (hram * a + r) % L;

	return Buffer.concat([R, bigToLe(S, 32)]);
}

/** Derive the Ed25519 public key from an expanded private key's scalar. */
export async function publicKeyFromPrivate(privateKey: Buffer): Promise<Buffer> {
	const { ed25519 } = await loadVendor();
	const a = scalarToBigInt(clampScalar(privateKey)) % ed25519.CURVE.n;
	return Buffer.from(ed25519.Point.BASE.multiply(a).toBytes());
}

/**
 * Build a signed advert packet: publicKey | timestamp | signature | app data, signed over
 * publicKey || timestamp || app data (`Mesh::createAdvert`).
 *
 * Receivers drop an advert whose timestamp is not NEWER than the last one they stored for
 * that key (`BaseChatMesh::onAdvertRecv` calls that a replay attack), so callers have to
 * keep the timestamp moving forward.
 */
export async function buildAdvertPacket(options: {
	privateKey: Buffer;
	fields: AdvertFields;
	timestamp: number;
	routeType?: number;
	pathHashSize?: number;
}): Promise<{ frame: Buffer; publicKey: Buffer; appData: Buffer; signature: Buffer }> {
	const { privateKey, fields, timestamp, routeType = ROUTE_TYPE_FLOOD, pathHashSize = 1 } = options;
	const publicKey = await publicKeyFromPrivate(privateKey);
	const appData = encodeAdvertAppData(fields);

	const stamp = Buffer.alloc(4);
	stamp.writeUInt32LE(timestamp >>> 0, 0);
	const signed = Buffer.concat([publicKey, stamp, appData]);
	const signature = await signWithExpandedKey(privateKey, signed);

	const payload = Buffer.concat([publicKey, stamp, signature, appData]);
	const frame = buildFrame({
		routeType,
		payloadType: PAYLOAD_TYPE_ADVERT,
		pathHashSize,
		payload,
	});
	return { frame, publicKey, appData, signature };
}

// --- the rest of the packet types --------------------------------------------

export const PAYLOAD_TYPE_REQ = 0x00;
export const PAYLOAD_TYPE_RESPONSE = 0x01;
export const PAYLOAD_TYPE_TXT_MSG = 0x02;
export const PAYLOAD_TYPE_ACK = 0x03;
export const PAYLOAD_TYPE_ANON_REQ = 0x07;
export const PAYLOAD_TYPE_PATH = 0x08;
export const PAYLOAD_TYPE_TRACE = 0x09;
export const PAYLOAD_TYPE_MULTIPART = 0x0a;
export const PAYLOAD_TYPE_CONTROL = 0x0b;

export const TXT_TYPE_PLAIN = 0x00;
export const TXT_TYPE_CLI_DATA = 0x01;
export const TXT_TYPE_SIGNED_PLAIN = 0x02;

/** MAX_TEXT_LEN in the firmware. */
export const MAX_DIRECT_TEXT_LEN = 160;

/**
 * `Mesh::createDatagram` — the shape shared by TXT_MSG, REQ and RESPONSE:
 * dest hash (1) | src hash (1) | encryptThenMAC(shared secret, plaintext).
 *
 * Both hashes are the first byte of the respective public key
 * (`Identity::copyHashTo` with PATH_HASH_SIZE = 1).
 */
export function composeDirectPayload(
	sharedSecret: Buffer,
	destPublicKey: Buffer,
	srcPublicKey: Buffer,
	plaintext: Buffer,
): Buffer {
	return Buffer.concat([
		Buffer.from([destPublicKey[0], srcPublicKey[0]]),
		encryptThenMac(sharedSecret, plaintext),
	]);
}

/**
 * `BaseChatMesh::composeMsgPacket` — timestamp (4 LE), a byte packing the retry attempt
 * in its low 2 bits and the text type above them, then the text. The trailing NUL the
 * firmware writes is NOT counted in the length, so it is not sent.
 */
export function composeDirectTextPlaintext(
	text: string,
	timestamp: number,
	txtType = TXT_TYPE_PLAIN,
	attempt = 0,
): Buffer {
	const body = Buffer.from(text, 'utf8');
	if (body.length > MAX_DIRECT_TEXT_LEN) {
		throw new Error(
			`Message is ${body.length} bytes; the firmware caps direct text at ${MAX_DIRECT_TEXT_LEN}`,
		);
	}
	const head = Buffer.alloc(5);
	head.writeUInt32LE(timestamp >>> 0, 0);
	head[4] = (attempt & 0x03) | ((txtType & 0x3f) << 2);
	return Buffer.concat([head, body]);
}

/**
 * The ACK the recipient will send back for a direct text message:
 * `sha256(plaintext || senderPublicKey)` truncated to 4 bytes
 * (`BaseChatMesh::composeMsgPacket`). Returning it lets a workflow wait for delivery.
 */
export function expectedAckCode(plaintext: Buffer, senderPublicKey: Buffer): Buffer {
	return createHash('sha256').update(plaintext).update(senderPublicKey).digest().subarray(0, 4);
}

/**
 * `Mesh::createAnonDatagram` — dest hash (1), the sender's FULL public key (32), then the
 * encrypted blob. The full key is there because the recipient does not know the sender
 * yet and needs it to derive the same shared secret.
 */
export function composeAnonPayload(
	sharedSecret: Buffer,
	destPublicKey: Buffer,
	senderPublicKey: Buffer,
	plaintext: Buffer,
): Buffer {
	return Buffer.concat([
		Buffer.from([destPublicKey[0]]),
		senderPublicKey,
		encryptThenMac(sharedSecret, plaintext),
	]);
}

/**
 * `Mesh::createPathReturn`'s encrypted body: the packed path-length byte, the path bytes,
 * then either an extra field or the firmware's filler. With no extra it writes a dummy
 * type 0xFF plus four random bytes purely to keep the packet hash unique; we take those
 * four bytes from the caller so the frame stays reproducible.
 */
export function composePathPlaintext(
	pathLen: number,
	path: Buffer,
	extraType: number | null,
	extra: Buffer,
	filler?: Buffer,
): Buffer {
	const hashSize = (pathLen >> 6) + 1;
	const hops = pathLen & 0x3f;
	if (path.length !== hops * hashSize) {
		throw new Error(
			`Path is ${path.length} bytes but the packed length byte says ${hops} hops of ${hashSize}`,
		);
	}
	if (extraType !== null && extra.length > 0) {
		return Buffer.concat([Buffer.from([pathLen]), path, Buffer.from([extraType & 0xff]), extra]);
	}
	const blob = filler && filler.length === 4 ? filler : Buffer.alloc(4);
	return Buffer.concat([Buffer.from([pathLen]), path, Buffer.from([0xff]), blob]);
}

/**
 * `Mesh::createTrace` plus the TRACE branch of `Mesh::sendDirect`: the payload is
 * tag (4 LE), auth code (4 LE), flags (1), and then the route is appended to the PAYLOAD
 * rather than the path field — which is why the frame's own path length stays 0.
 * `flags & 3` is the hop size as a SHIFT, so only 1, 2, 4 and 8 are expressible.
 */
export function composeTracePayload(
	tag: number,
	authCode: number,
	path: Buffer,
	hashSize = 1,
): Buffer {
	const pathSz = [1, 2, 4, 8].indexOf(hashSize);
	if (pathSz === -1) {
		throw new Error(`Trace hop size must be 1, 2, 4 or 8 bytes (got ${hashSize})`);
	}
	if (path.length % hashSize !== 0) {
		throw new Error(
			`Trace route is ${path.length} bytes, which is not a whole number of ${hashSize}-byte hops`,
		);
	}
	const head = Buffer.alloc(9);
	head.writeUInt32LE(tag >>> 0, 0);
	head.writeUInt32LE(authCode >>> 0, 4);
	head[8] = pathSz;
	return Buffer.concat([head, path]);
}

/**
 * `Mesh::createMultiAck` generalised: the first byte packs how many packets of the set are
 * still to come in its high nibble and the wrapped payload type in its low nibble, then
 * the wrapped payload follows.
 */
export function composeMultipartPayload(
	innerType: number,
	remaining: number,
	innerPayload: Buffer,
): Buffer {
	if (remaining < 0 || remaining > 15) {
		throw new Error(`Remaining must be 0-15 (got ${remaining}); it is packed into a nibble`);
	}
	return Buffer.concat([Buffer.from([((remaining & 0x0f) << 4) | (innerType & 0x0f)]), innerPayload]);
}

/** The plaintext of a group datagram: data_type (LE16), length, then the bytes. */
export function composeGroupDataPlaintext(dataType: number, data: Buffer): Buffer {
	if (data.length > MAX_GROUP_DATA_LENGTH) {
		throw new Error(`Group data is ${data.length} bytes; the firmware caps it at ${MAX_GROUP_DATA_LENGTH}`);
	}
	const head = Buffer.alloc(3);
	head.writeUInt16LE(dataType & 0xffff, 0);
	head[2] = data.length;
	return Buffer.concat([head, data]);
}
