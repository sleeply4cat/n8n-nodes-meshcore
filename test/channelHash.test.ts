import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createHash, createHmac } from 'node:crypto';

import {
	MAX_TEXT_LEN,
	PAYLOAD_TYPE_GRP_TXT,
	buffersEqual,
	buildGroupTextPacket,
	composeGroupTextPlaintext,
	computeGroupTextPacketHash,
	computePacketHash,
	parseRxFrame,
} from '../dist/nodes/shared/channelHash.js';

const SECRET_PUBLIC: Buffer = Buffer.alloc(16, 0); // canonical "all zeros" 128-bit test key
SECRET_PUBLIC[0] = 0x8b;
SECRET_PUBLIC[1] = 0x2d;
SECRET_PUBLIC[2] = 0x18;
SECRET_PUBLIC[3] = 0xc9;
// (the rest stays 0; we don't need a real channel key for unit tests)

test('composeGroupTextPlaintext lays out ts(4 LE) || 0 || "<advName>: <text>"', () => {
	const buf = composeGroupTextPlaintext(0x11223344, 'Alice', 'hi');
	// timestamp LE
	assert.equal(buf.readUInt32LE(0), 0x11223344);
	assert.equal(buf[4], 0, 'txt_type byte = TXT_TYPE_PLAIN');
	assert.equal(buf.subarray(5).toString('utf8'), 'Alice: hi');
});

test('computePacketHash is SHA256(payloadType || payload)[:8]', () => {
	const payload = Buffer.from('abc', 'utf8');
	const expected = createHash('sha256')
		.update(Buffer.from([0x05]))
		.update(payload)
		.digest()
		.subarray(0, 8);
	assert.deepEqual(computePacketHash(0x05, payload), expected);
});

test('computeGroupTextPacketHash composes payload = chanHash || mac || ciphertext and hashes it', () => {
	// independent re-implementation of the firmware path — if it ever diverges from
	// the operations.ts code, this test catches it.
	const advName = 'TestNode';
	const text = 'hello world';
	const ts = 0x65000000;

	const plaintext = composeGroupTextPlaintext(ts, advName, text);
	const padded = Buffer.alloc(plaintext.length + ((16 - (plaintext.length % 16)) % 16));
	plaintext.copy(padded);
	const cipher = createCipheriv('aes-128-ecb', SECRET_PUBLIC, null);
	cipher.setAutoPadding(false);
	const ciphertext = Buffer.concat([cipher.update(padded), cipher.final()]);

	const hmacKey = Buffer.alloc(32);
	SECRET_PUBLIC.copy(hmacKey);
	const mac = createHmac('sha256', hmacKey).update(ciphertext).digest().subarray(0, 2);
	const chanHash = createHash('sha256').update(SECRET_PUBLIC).digest().subarray(0, 1);
	const expectedPayload = Buffer.concat([chanHash, mac, ciphertext]);
	const expectedHash = createHash('sha256')
		.update(Buffer.from([0x05]))
		.update(expectedPayload)
		.digest()
		.subarray(0, 8);

	const { hash, payload } = computeGroupTextPacketHash(SECRET_PUBLIC, advName, text, ts);
	assert.deepEqual(payload, expectedPayload, 'payload bytes match the firmware composition');
	assert.deepEqual(hash, expectedHash, 'packet hash is SHA256(0x05 || payload)[:8]');
});

test('computeGroupTextPacketHash is identical for identical inputs (retries dedupe trick)', () => {
	const a = computeGroupTextPacketHash(SECRET_PUBLIC, 'X', 'ping', 1000);
	const b = computeGroupTextPacketHash(SECRET_PUBLIC, 'X', 'ping', 1000);
	assert.ok(buffersEqual(a.hash, b.hash));
});

test('computeGroupTextPacketHash differs across timestamps and texts', () => {
	const a = computeGroupTextPacketHash(SECRET_PUBLIC, 'X', 'ping', 1000);
	const b = computeGroupTextPacketHash(SECRET_PUBLIC, 'X', 'ping', 1001);
	const c = computeGroupTextPacketHash(SECRET_PUBLIC, 'X', 'pong', 1000);
	assert.ok(!buffersEqual(a.hash, b.hash), 'different timestamp → different hash');
	assert.ok(!buffersEqual(a.hash, c.hash), 'different text → different hash');
});

test('parseRxFrame extracts payload after FLOOD header + path_len(packed) + path bytes', () => {
	// header: route=FLOOD(1), payloadType=GRP_TXT(5) → byte = (5 << 2) | 1 = 0x15
	// pathLen packed = 0x43 (3 hops, 2-byte hashes) → 6 bytes path
	const header = (PAYLOAD_TYPE_GRP_TXT << 2) | 0x01;
	const pathBytes = Buffer.from([1, 2, 3, 4, 5, 6]);
	const payload = Buffer.from('payload-bytes', 'utf8');
	const frame = Buffer.concat([Buffer.from([header, 0x43]), pathBytes, payload]);
	const r = parseRxFrame(frame);
	assert.ok(r);
	assert.equal(r!.payloadType, PAYLOAD_TYPE_GRP_TXT);
	assert.equal(r!.routeType, 1);
	assert.equal(r!.pathLen, 0x43);
	assert.equal(r!.payload.toString('utf8'), 'payload-bytes');
});

test('parseRxFrame handles TRANSPORT_FLOOD (4 extra transport_codes bytes)', () => {
	const header = (PAYLOAD_TYPE_GRP_TXT << 2) | 0x00; // route=TRANSPORT_FLOOD
	const transportCodes = Buffer.from([0x10, 0x11, 0x12, 0x13]);
	const pathLenPacked = 0; // no hops
	const payload = Buffer.from([0xde, 0xad]);
	const frame = Buffer.concat([Buffer.from([header]), transportCodes, Buffer.from([pathLenPacked]), payload]);
	const r = parseRxFrame(frame);
	assert.ok(r);
	assert.equal(r!.routeType, 0);
	assert.deepEqual(r!.payload, payload);
});

test('parseRxFrame returns null on truncated frame', () => {
	assert.equal(parseRxFrame(Buffer.from([0x15])), null, 'no pathLen');
	const header = (PAYLOAD_TYPE_GRP_TXT << 2) | 0x01;
	assert.equal(parseRxFrame(Buffer.from([header, 0x43, 1, 2])), null, 'path bytes truncated');
});

test('round trip: compose a frame from a known hash, parse + match', () => {
	const { hash, payload } = computeGroupTextPacketHash(SECRET_PUBLIC, 'Self', 'echo me', 12345);
	// build a wire frame that a neighbor would retransmit:
	// header: FLOOD + GRP_TXT, path with one hop appended (1-byte hash)
	const header = (PAYLOAD_TYPE_GRP_TXT << 2) | 0x01;
	const frame = Buffer.concat([Buffer.from([header, 0x01, 0xaa]), payload]);
	const parsed = parseRxFrame(frame);
	assert.ok(parsed);
	const computed = computePacketHash(parsed!.payloadType, parsed!.payload);
	assert.ok(buffersEqual(computed, hash), 'hash unchanged by appended path on retransmission');
});

test('buildGroupTextPacket produces a flood GRP_TXT frame that parses back to its payload', () => {
	const { frame, hash, truncated } = buildGroupTextPacket(SECRET_PUBLIC, 'BotName', 'hello', 1000);

	assert.equal(truncated, false);
	assert.equal(frame[0] & 0x03, 1, 'route type is flood');
	assert.equal((frame[0] >> 2) & 0x0f, PAYLOAD_TYPE_GRP_TXT, 'payload type is GRP_TXT');
	assert.equal(frame[1], 0, 'packed path length is zero hops');

	const parsed = parseRxFrame(frame);
	assert.ok(parsed);
	assert.equal(parsed!.payloadType, PAYLOAD_TYPE_GRP_TXT);
	assert.ok(
		buffersEqual(computePacketHash(parsed!.payloadType, parsed!.payload), hash),
		'the returned hash is the on-air dedup key for this very frame',
	);
});

test('buildGroupTextPacket payload matches what the hash pipeline already produced', () => {
	// The send path must be byte-identical to the pipeline that was validated on hardware
	// by matching neighbour retransmissions — otherwise the packet would not decrypt.
	const { payload } = computeGroupTextPacketHash(SECRET_PUBLIC, 'BotName', 'hello', 1000);
	const { frame } = buildGroupTextPacket(SECRET_PUBLIC, 'BotName', 'hello', 1000);
	assert.equal(frame.subarray(2).toString('hex'), payload.toString('hex'));
});

test('buildGroupTextPacket truncates the text, not the name, to the firmware limit', () => {
	const name = 'Bot';
	const budget = MAX_TEXT_LEN - Buffer.byteLength(`${name}: `, 'utf8');
	const { truncated } = buildGroupTextPacket(SECRET_PUBLIC, name, 'x'.repeat(budget + 20), 1000);
	assert.equal(truncated, true);

	const expected = computeGroupTextPacketHash(SECRET_PUBLIC, name, 'x'.repeat(budget), 1000);
	const { frame } = buildGroupTextPacket(SECRET_PUBLIC, name, 'x'.repeat(budget + 20), 1000);
	assert.equal(frame.subarray(2).toString('hex'), expected.payload.toString('hex'));

	const short = buildGroupTextPacket(SECRET_PUBLIC, name, 'x'.repeat(budget), 1000);
	assert.equal(short.truncated, false);
});

test('buildGroupTextPacket rejects a sender name that leaves no room for text', () => {
	assert.throws(
		() => buildGroupTextPacket(SECRET_PUBLIC, 'n'.repeat(MAX_TEXT_LEN), 'hi', 1000),
		/Sender name is too long/,
	);
});

test('buildGroupTextPacket encodes the hop hash size in the packed path-length byte', () => {
	for (const [size, expected] of [[1, 0x00], [2, 0x40], [3, 0x80]] as const) {
		const { frame } = buildGroupTextPacket(SECRET_PUBLIC, 'Bot', 'hi', 1000, size);
		assert.equal(frame[1], expected, `hash size ${size} packs to 0x${expected.toString(16)}`);
		const parsed = parseRxFrame(frame);
		assert.equal(parsed!.hashSize, size, 'the byte reads back as the size we asked for');
		assert.equal(parsed!.hops, 0, 'still zero hops');
	}
});

test('buildGroupTextPacket rejects a hash size the packed byte cannot carry', () => {
	// 4 would encode as path mode 3, which tryParsePacket refuses as reserved
	assert.throws(() => buildGroupTextPacket(SECRET_PUBLIC, 'Bot', 'hi', 1000, 4), /must be 1, 2 or 3/);
	assert.throws(() => buildGroupTextPacket(SECRET_PUBLIC, 'Bot', 'hi', 1000, 0), /must be 1, 2 or 3/);
});

test('the hop hash size does not disturb the encrypted payload', () => {
	const a = buildGroupTextPacket(SECRET_PUBLIC, 'Bot', 'hi', 1000, 1);
	const b = buildGroupTextPacket(SECRET_PUBLIC, 'Bot', 'hi', 1000, 2);
	assert.equal(a.frame.subarray(2).toString('hex'), b.frame.subarray(2).toString('hex'));
	assert.ok(buffersEqual(a.hash, b.hash), 'the dedup hash covers the payload, not the path byte');
});
