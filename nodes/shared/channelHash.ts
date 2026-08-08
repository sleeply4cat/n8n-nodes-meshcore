/**
 * Compute the on-air packet hash for a MeshCore group (channel) text message, and
 * parse arbitrary frames received via `PUSH_CODE_LOG_RX_DATA` so we can detect when
 * a neighbor retransmitted our own broadcast.
 *
 * Crypto matches `BaseChatMesh::sendGroupMessage` + `Mesh::createGroupDatagram` +
 * `Utils::encrypt`/`encryptThenMAC`/`Packet::calculatePacketHash` in the firmware:
 *   plaintext = ts(4 LE) || txtType(1=0) || "<advName>: <text>"
 *   key       = secret[0..16]  (AES-128 ECB)
 *   ciphertext= AES-128-ECB(key, zero-pad(plaintext, 16))
 *   mac       = HMAC-SHA256(secret_padded_to_32, ciphertext)[:2]
 *   chanHash  = SHA256(secret[0..16])[:1]
 *   payload   = chanHash || mac || ciphertext
 *   pktHash   = SHA256(PAYLOAD_TYPE_GRP_TXT(0x05) || payload)[:8]
 *
 * That hash is constant across retries when (timestamp, advName, text, secret) are
 * stable: the receiver's mesh dedupes by this hash AND the workflow gets an
 * "actually propagated" signal as soon as any neighbor retransmits — without us
 * needing a per-recipient ACK that the channel protocol doesn't have.
 */
import { createCipheriv, createHash, createHmac } from 'node:crypto';

export const PAYLOAD_TYPE_GRP_TXT = 0x05;
const TXT_TYPE_PLAIN = 0x00;
const AES_BLOCK = 16;
const MAC_SIZE = 2;
const CHANNEL_HASH_SIZE = 1;
const PACKET_HASH_SIZE = 8;
const PH_ROUTE_MASK = 0x03;
const PH_TYPE_SHIFT = 2;
const PH_TYPE_MASK = 0x0f;
const ROUTE_TYPE_TRANSPORT_FLOOD = 0x00;
const ROUTE_TYPE_TRANSPORT_DIRECT = 0x03;

function zeroPad16(bytes: Buffer): Buffer {
	const remainder = bytes.length % AES_BLOCK;
	if (remainder === 0) {
		// firmware pads only the partial trailing block; full block goes as-is
		return bytes;
	}
	const padded = Buffer.alloc(bytes.length + (AES_BLOCK - remainder));
	bytes.copy(padded);
	return padded;
}

function aes128EcbEncrypt(key16: Buffer, padded: Buffer): Buffer {
	// Node's `aes-128-ecb` cipher auto-applies PKCS padding by default; we want
	// raw ECB on our already-zero-padded plaintext, so disable padding explicitly.
	const cipher = createCipheriv('aes-128-ecb', key16, null);
	cipher.setAutoPadding(false);
	return Buffer.concat([cipher.update(padded), cipher.final()]);
}

/** Build the plaintext buffer the firmware would feed into `encryptThenMAC`. */
export function composeGroupTextPlaintext(
	timestamp: number,
	advName: string,
	text: string,
): Buffer {
	const prefix = Buffer.from(`${advName}: `, 'utf8');
	const body = Buffer.from(text, 'utf8');
	const buf = Buffer.alloc(5 + prefix.length + body.length);
	buf.writeUInt32LE(timestamp >>> 0, 0);
	buf[4] = TXT_TYPE_PLAIN;
	prefix.copy(buf, 5);
	body.copy(buf, 5 + prefix.length);
	return buf;
}

/** SHA256(payloadTypeByte || payload)[:8] — the on-air dedup key. */
export function computePacketHash(payloadType: number, payload: Buffer): Buffer {
	const h = createHash('sha256');
	h.update(Buffer.from([payloadType]));
	h.update(payload);
	return h.digest().subarray(0, PACKET_HASH_SIZE);
}

/**
 * The full pipeline for a GRP_TXT broadcast: plaintext → cipher+MAC → wrapped
 * payload → packet hash. Returns both the hash (for matching incoming LogRxData)
 * and the assembled payload (useful for tests / debug).
 */
export function computeGroupTextPacketHash(
	secret16: Buffer,
	advName: string,
	text: string,
	timestamp: number,
): { hash: Buffer; payload: Buffer } {
	if (secret16.length < 16) {
		throw new Error(`channel secret must be at least 16 bytes (got ${secret16.length})`);
	}
	const key = secret16.subarray(0, 16);

	// AES-128-ECB with zero padding (firmware behavior, see Utils::encrypt)
	const plaintext = composeGroupTextPlaintext(timestamp, advName, text);
	const padded = zeroPad16(plaintext);
	const ciphertext = aes128EcbEncrypt(key, padded);

	// HMAC key is 32 bytes in firmware (PUB_KEY_SIZE). For 128-bit channels the
	// upper 16 bytes are zero — pad accordingly.
	const hmacKey = Buffer.alloc(32);
	secret16.subarray(0, 16).copy(hmacKey);
	const mac = createHmac('sha256', hmacKey).update(ciphertext).digest().subarray(0, MAC_SIZE);

	const chanHash = createHash('sha256').update(key).digest().subarray(0, CHANNEL_HASH_SIZE);

	const payload = Buffer.concat([chanHash, mac, ciphertext]);
	return { hash: computePacketHash(PAYLOAD_TYPE_GRP_TXT, payload), payload };
}

/** MAX_TEXT_LEN in the firmware; the "<sender>: " prefix counts against it. */
export const MAX_TEXT_LEN = 160;
const ROUTE_TYPE_FLOOD = 0x01;

/**
 * Assemble a complete on-air GRP_TXT packet for `CMD_SEND_RAW_PACKET`, so the message can
 * carry ANY sender name. The device's own `CMD_SEND_CHANNEL_TXT_MSG` writes the name from
 * its `_prefs.node_name` (`BaseChatMesh::sendGroupMessage`), which the host cannot override
 * — building the packet here is the only way to choose it per message.
 *
 * The payload is exactly what `computeGroupTextPacketHash` already produces (that is the
 * same `Mesh::createGroupDatagram` output whose hash we match against retransmissions), so
 * this only has to prepend `Packet::writeTo`'s header and path length. Flood-routed with an
 * empty path, which is how the firmware sends channel traffic.
 *
 * `hashSize` goes into the packed path-length byte and is what every repeater along the
 * way uses when it appends its own hash (`Mesh.cpp` sizes that write by
 * `packet->getPathHashSize()`, read back out of this very byte). The device would use
 * `path_hash_mode + 1` here (`MyMesh::sendFloodScoped`), so pass the mesh's size or the
 * accumulated return path ends up narrower than the rest of the mesh's traffic.
 *
 * Returns the frame plus the packet hash, which is the same dedup key the mesh uses — a
 * caller can watch for it in LogRxData to confirm a neighbor repeated the broadcast.
 */
export function buildGroupTextPacket(
	secret16: Buffer,
	senderName: string,
	text: string,
	timestamp: number,
	hashSize = 1,
): { frame: Buffer; hash: Buffer; truncated: boolean } {
	if (!Number.isInteger(hashSize) || hashSize < 1 || hashSize > 3) {
		throw new Error(
			`Path hash size must be 1, 2 or 3 bytes (got ${hashSize}) — the packed path-length byte holds size - 1 in two bits, and the firmware rejects a size of 4 as reserved`,
		);
	}
	const prefixLength = Buffer.byteLength(`${senderName}: `, 'utf8');
	const budget = MAX_TEXT_LEN - prefixLength;
	if (budget <= 0) {
		throw new Error(
			`Sender name is too long: "${senderName}: " already fills the ${MAX_TEXT_LEN}-byte text limit`,
		);
	}
	// The firmware truncates the TEXT once the prefix is accounted for; mirror that rather
	// than emit a packet the device would have trimmed to something else.
	const body = Buffer.from(text, 'utf8');
	const truncated = body.length > budget;
	const fitted = truncated ? body.subarray(0, budget).toString('utf8') : text;

	const { hash, payload } = computeGroupTextPacketHash(secret16, senderName, fitted, timestamp);
	const header = (PAYLOAD_TYPE_GRP_TXT << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD;
	// Packet::setPathHashSizeAndCount(size, 0): high 2 bits hold size - 1, low 6 the hop count
	const pathLen = ((hashSize - 1) << 6) | 0;
	return { frame: Buffer.concat([Buffer.from([header, pathLen]), payload]), hash, truncated };
}

/**
 * Parse a raw radio frame (as it arrives in PUSH_CODE_LOG_RX_DATA after the
 * SNR/RSSI prefix has been stripped by meshcore.js) into its payloadType and
 * payload bytes. Returns null if the frame is malformed or shorter than
 * minimum (header + path_len + 0 payload).
 *
 * Frame on-air = header(1) || [transport_codes(4) iff route ∈ {0,3}] ||
 *                pathLen(1, packed) || path(pathBytes) || payload
 */
export function parseRxFrame(
	raw: Uint8Array | Buffer,
): {
	routeType: number;
	payloadType: number;
	pathLen: number;
	hops: number;
	hashSize: number;
	path: Buffer;
	payload: Buffer;
} | null {
	const b = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
	if (b.length < 2) return null;

	const header = b[0];
	const routeType = header & PH_ROUTE_MASK;
	const payloadType = (header >> PH_TYPE_SHIFT) & PH_TYPE_MASK;
	const hasTransportCodes =
		routeType === ROUTE_TYPE_TRANSPORT_FLOOD || routeType === ROUTE_TYPE_TRANSPORT_DIRECT;
	let i = 1 + (hasTransportCodes ? 4 : 0);
	if (i >= b.length) return null;

	const pathLenPacked = b[i++];
	const hops = pathLenPacked & 0x3f;
	const hashSize = (pathLenPacked >> 6) + 1;
	const pathBytes = hops * hashSize;
	if (i + pathBytes > b.length) return null;
	const path = b.subarray(i, i + pathBytes);
	i += pathBytes;

	const payload = b.subarray(i);
	return { routeType, payloadType, pathLen: pathLenPacked, hops, hashSize, path, payload };
}

export function buffersEqual(a: Buffer | Uint8Array, b: Buffer | Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}
