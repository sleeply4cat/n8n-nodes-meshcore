import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
	buildAdvertPacket,
	buildFrame,
	calcSharedSecret,
	composeAnonPayload,
	composeDirectPayload,
	composeDirectTextPlaintext,
	composeGroupDataPlaintext,
	composeMultipartPayload,
	composePathPlaintext,
	composeTracePayload,
	decodePacket,
	encodeAdvertAppData,
	expectedAckCode,
	macThenDecrypt,
	parsePathPlaintext,
	parseTextPlaintext,
	publicKeyFromPrivate,
	ROUTE_TYPE_DIRECT,
	ROUTE_TYPE_FLOOD,
	ROUTE_TYPE_TRANSPORT_FLOOD,
	signWithExpandedKey,
	splitAuthor,
} from '../dist/nodes/shared/packetCodec.js';
import {
	buildGroupTextPacket,
	encryptThenMac,
	composeGroupPayload,
} from '../dist/nodes/shared/channelHash.js';

const SECRET: Buffer = Buffer.from('8b2d18c9000000000000000000000000', 'hex');
const OTHER_SECRET: Buffer = Buffer.from('ffeeddccbbaa99887766554433221100', 'hex');

// The known-good client keypair from the firmware's own LocalIdentity::validatePrivateKey.
const FW_TEST_PRV: Buffer = Buffer.from(
	'7065e18fd9fabb70c1ed90dca19907de698c88b709ea146eafd93d9b830c7b60' +
		'c4681193c79bbc39945ba8064104bb618f8fd7a84a0af6f57033d6e8ddcd6471',
	'hex',
);
const FW_TEST_PUB: Buffer = Buffer.from(
	'1ec77175b0918ed206f9ae04ec136d6d5d4315bb26305427f645b492e9350c10',
	'hex',
);

test('macThenDecrypt is the inverse of encryptThenMac', () => {
	const plaintext = Buffer.from('the quick brown fox', 'utf8');
	const blob = encryptThenMac(SECRET, plaintext);
	const back = macThenDecrypt(SECRET, blob);
	assert.ok(back);
	// the firmware zero-pads, so the recovered buffer is padded up to a block
	assert.equal(back!.subarray(0, plaintext.length).toString('utf8'), plaintext.toString('utf8'));
	assert.equal(back!.length % 16, 0);
});

test('macThenDecrypt rejects a wrong key instead of returning garbage', () => {
	const blob = encryptThenMac(SECRET, Buffer.from('secret text', 'utf8'));
	assert.equal(macThenDecrypt(OTHER_SECRET, blob), null);
});

test('macThenDecrypt rejects malformed blobs', () => {
	assert.equal(macThenDecrypt(SECRET, Buffer.alloc(0)), null);
	assert.equal(macThenDecrypt(SECRET, Buffer.alloc(2)), null, 'MAC only, no ciphertext');
	assert.equal(macThenDecrypt(SECRET, Buffer.alloc(9)), null, 'ciphertext not a block multiple');
});

test('calcSharedSecret matches the firmware test vector and is symmetric', async () => {
	const ss = await calcSharedSecret(FW_TEST_PRV, FW_TEST_PUB);
	assert.equal(ss.toString('hex'), 'b981cf37cd88bb0728e3a30f51bd12d26ba27df6e2ba06179fd8bca83efe286d');
	assert.ok(
		!ss.every((b: number) => b === 0),
		'the firmware rejects an all-zero shared secret, so ours must not be one',
	);
});

test('calcSharedSecret rejects wrongly sized keys', async () => {
	await assert.rejects(() => calcSharedSecret(Buffer.alloc(8), FW_TEST_PUB), /Private key must be/);
	await assert.rejects(() => calcSharedSecret(FW_TEST_PRV, Buffer.alloc(8)), /Public key must be/);
});

test('buildFrame packs the header and path-length byte per Packet::writeTo', () => {
	const frame = buildFrame({
		routeType: ROUTE_TYPE_FLOOD,
		payloadType: 0x05,
		pathHashSize: 2,
		path: Buffer.from('aabbccdd', 'hex'),
		payload: Buffer.from('deadbeef', 'hex'),
	});
	assert.equal(frame[0] & 0x03, ROUTE_TYPE_FLOOD);
	assert.equal((frame[0] >> 2) & 0x0f, 0x05);
	assert.equal(frame[0] >> 6, 0, 'payload version 0');
	assert.equal(frame[1], (1 << 6) | 2, '2-byte hashes, 2 hops');
	assert.equal(frame.subarray(2).toString('hex'), 'aabbccdd' + 'deadbeef');
});

test('buildFrame writes transport codes only for the transport route types', () => {
	const frame = buildFrame({
		routeType: ROUTE_TYPE_TRANSPORT_FLOOD,
		payloadType: 0x05,
		payload: Buffer.from('01', 'hex'),
		transportCodes: [0x1234, 0x5678],
	});
	assert.equal(frame.length, 1 + 4 + 1 + 1);
	assert.equal(frame.readUInt16LE(1), 0x1234);
	assert.equal(frame.readUInt16LE(3), 0x5678);

	const plain = buildFrame({
		routeType: ROUTE_TYPE_DIRECT,
		payloadType: 0x05,
		payload: Buffer.from('01', 'hex'),
	});
	assert.equal(plain.length, 1 + 1 + 1, 'no transport codes on a plain route');
});

test('buildFrame refuses inputs the firmware could not parse', () => {
	const base = { routeType: ROUTE_TYPE_FLOOD, payloadType: 0x05, payload: Buffer.alloc(4) };
	assert.throws(() => buildFrame({ ...base, pathHashSize: 4 }), /must be 1, 2 or 3/);
	assert.throws(
		() => buildFrame({ ...base, pathHashSize: 2, path: Buffer.alloc(3) }),
		/not a whole number of 2-byte hops/,
	);
	assert.throws(() => buildFrame({ ...base, payloadType: 16 }), /Payload type must be 0-15/);
	assert.throws(
		() => buildFrame({ ...base, routeType: ROUTE_TYPE_TRANSPORT_FLOOD }),
		/require two transport codes/,
	);
});

test('composeGroupDataPlaintext lays out data_type (LE16), length, data', () => {
	const pt = composeGroupDataPlaintext(0x1234, Buffer.from('aabb', 'hex'));
	assert.equal(pt.readUInt16LE(0), 0x1234);
	assert.equal(pt[2], 2);
	assert.equal(pt.subarray(3).toString('hex'), 'aabb');
});

test('parseTextPlaintext and splitAuthor recover the firmware text layout', () => {
	const pt = Buffer.concat([
		Buffer.from([0x10, 0x00, 0x00, 0x00, 0x00]),
		Buffer.from('Bot: hello there', 'utf8'),
		Buffer.alloc(3),
	]);
	const parsed = parseTextPlaintext(pt);
	assert.ok(parsed);
	assert.equal(parsed!.timestamp, 0x10);
	assert.equal(parsed!.txtType, 0);
	assert.equal(parsed!.text, 'Bot: hello there', 'zero padding is cut at the terminator');
	assert.deepEqual(splitAuthor(parsed!.text), { author: 'Bot', text: 'hello there' });
});

test('parsePathPlaintext decodes the returned route', () => {
	// packed path_len 0x42 -> 2-byte hashes, 2 hops -> 4 path bytes, then extra_type + extra
	const pt = Buffer.from('42aabbccdd07ff', 'hex');
	assert.deepEqual(parsePathPlaintext(pt), {
		pathLen: 0x42,
		hops: 2,
		pathHashSize: 2,
		returnPath: 'aabbccdd',
		extraType: 7,
		extra: 'ff',
	});
});

test('decodePacket reads a group text frame and decrypts it with the right secret', async () => {
	const { frame, hash } = buildGroupTextPacket(SECRET, 'Bot', 'hello', 1000, 2);

	const decoded = await decodePacket(frame, { channels: [{ name: 'HOME', secret: SECRET }] });
	assert.equal(decoded.payloadTypeName, 'GRP_TXT');
	assert.equal(decoded.routeTypeName, 'FLOOD');
	assert.equal(decoded.pathHashSize, 2);
	assert.equal(decoded.hops, 0);
	assert.equal(decoded.packetHash, hash.toString('hex'), 'hash matches the builder');
	assert.deepEqual(decoded.decrypted, {
		channelName: 'HOME',
		timestamp: 1000,
		txtType: 0,
		author: 'Bot',
		text: 'hello',
		rawText: 'Bot: hello',
	});
});

test('decodePacket explains why a group frame stayed encrypted', async () => {
	const { frame } = buildGroupTextPacket(SECRET, 'Bot', 'hello', 1000, 1);

	const none = await decodePacket(frame);
	assert.equal(none.decrypted, undefined);
	assert.match(none.undecryptedReason!, /no channel secrets supplied/);

	const wrong = await decodePacket(frame, { channels: [{ name: 'other', secret: OTHER_SECRET }] });
	assert.equal(wrong.decrypted, undefined);
	assert.match(wrong.undecryptedReason!, /no supplied channel secret matched/);
});

test('decodePacket names the payload types meshcore.js does not know', async () => {
	for (const [type, name] of [
		[0x0a, 'MULTIPART'],
		[0x0b, 'CONTROL'],
	] as const) {
		const frame = buildFrame({
			routeType: ROUTE_TYPE_FLOOD,
			payloadType: type,
			payload: Buffer.from('00', 'hex'),
		});
		const decoded = await decodePacket(frame);
		assert.equal(decoded.payloadTypeName, name);
	}
});

test('decodePacket reports a direct frame as needing keys, naming what is missing', async () => {
	const payload = Buffer.concat([
		Buffer.from([0xab, 0xcd]), // dest hash, src hash
		encryptThenMac(SECRET, Buffer.from('0000000000hi', 'utf8')),
	]);
	const frame = buildFrame({
		routeType: ROUTE_TYPE_DIRECT,
		payloadType: 0x02, // TXT_MSG
		payload,
	});

	const noKeys = await decodePacket(frame);
	assert.match(noKeys.undecryptedReason!, /no private keys supplied/);

	const noPeers = await decodePacket(frame, {
		identities: [{ name: 'me', privateKey: FW_TEST_PRV }],
	});
	assert.match(noPeers.undecryptedReason!, /no peer public keys supplied/);
	assert.match(noPeers.undecryptedReason!, /1-byte sender hash/);
});

test('decodePacket exposes group payloads built by composeGroupPayload', async () => {
	const plaintext = composeGroupDataPlaintext(0xffff, Buffer.from('c0ffee', 'hex'));
	const frame = buildFrame({
		routeType: ROUTE_TYPE_FLOOD,
		payloadType: 0x06, // GRP_DATA
		payload: composeGroupPayload(SECRET, plaintext),
	});
	const decoded = await decodePacket(frame, { channels: [{ name: 'HOME', secret: SECRET }] });
	assert.equal(decoded.payloadTypeName, 'GRP_DATA');
	assert.equal((decoded.decrypted as Record<string, unknown>).channelName, 'HOME');
	const data = (decoded.decrypted as Record<string, string>).data;
	assert.ok(data.startsWith('ffff03c0ffee'), `group datagram plaintext round trips, got ${data}`);
});

test('publicKeyFromPrivate agrees with the firmware test vector keypair', async () => {
	const derived = await publicKeyFromPrivate(FW_TEST_PRV);
	assert.equal(derived.toString('hex'), FW_TEST_PUB.toString('hex'));
});

test('encodeAdvertAppData follows AdvertDataBuilder::encodeTo', () => {
	const nameOnly = encodeAdvertAppData({ type: 1, name: 'KOT' });
	assert.equal(nameOnly[0], 0x80 | 1, 'name flag plus the type nibble');
	assert.equal(nameOnly.subarray(1).toString('utf8'), 'KOT');

	const full = encodeAdvertAppData({
		type: 2,
		name: 'Rep',
		latitude: 1.5,
		longitude: -2.25,
		feat1: 0x1234,
	});
	assert.equal(full[0], 0x80 | 0x20 | 0x10 | 2, 'name, feat1 and latlon flags');
	assert.equal(full.readInt32LE(1), 1_500_000, 'latitude is micro-degrees');
	assert.equal(full.readInt32LE(5), -2_250_000);
	assert.equal(full.readUInt16LE(9), 0x1234);
	assert.equal(full.subarray(11).toString('utf8'), 'Rep');
});

test('encodeAdvertAppData omits a zero feat, as the firmware does', () => {
	const app = encodeAdvertAppData({ type: 1, name: 'X', feat1: 0, feat2: 0 });
	assert.equal(app[0] & 0x20, 0);
	assert.equal(app[0] & 0x40, 0);
	assert.equal(app.length, 2, 'flags byte plus the one-character name');
});

test('encodeAdvertAppData requires a name, which the firmware silently demands', () => {
	assert.throws(() => encodeAdvertAppData({ type: 1, name: '' }), /name is required/);
});

test('signWithExpandedKey is deterministic and needs the full 64-byte key', async () => {
	const msg = Buffer.from('advert bytes', 'utf8');
	const a = await signWithExpandedKey(FW_TEST_PRV, msg);
	const b = await signWithExpandedKey(FW_TEST_PRV, msg);
	assert.equal(a.length, 64);
	assert.equal(a.toString('hex'), b.toString('hex'), 'Ed25519 signatures are deterministic');

	await assert.rejects(
		() => signWithExpandedKey(FW_TEST_PRV.subarray(0, 32), msg),
		/full 64-byte private key/,
	);
});

test('buildAdvertPacket lays out the payload and verifies against its own signature', async () => {
	const { frame, publicKey, appData, signature } = await buildAdvertPacket({
		privateKey: FW_TEST_PRV,
		fields: { type: 1, name: 'alt-identity' },
		timestamp: 1_700_000_000,
	});

	assert.equal(publicKey.toString('hex'), FW_TEST_PUB.toString('hex'));

	const decoded = await decodePacket(frame, { verifyAdverts: true });
	assert.equal(decoded.payloadTypeName, 'ADVERT');
	assert.equal(decoded.parsed!.publicKey, FW_TEST_PUB.toString('hex'));
	assert.equal(decoded.parsed!.timestamp, 1_700_000_000);
	assert.equal(decoded.parsed!.name, 'alt-identity');
	assert.equal(decoded.parsed!.signatureValid, true, 'the signature we made must verify');

	// payload = publicKey(32) | timestamp(4) | signature(64) | appData
	const payload = Buffer.from(decoded.payload, 'hex');
	assert.equal(payload.subarray(36, 100).toString('hex'), signature.toString('hex'));
	assert.equal(payload.subarray(100).toString('hex'), appData.toString('hex'));
});

test('a tampered advert fails verification', async () => {
	const { frame } = await buildAdvertPacket({
		privateKey: FW_TEST_PRV,
		fields: { type: 1, name: 'alt-identity' },
		timestamp: 1_700_000_000,
	});
	const tampered = Buffer.from(frame);
	tampered[tampered.length - 1] ^= 0xff; // flip a byte of the name
	const decoded = await decodePacket(tampered, { verifyAdverts: true });
	assert.equal(decoded.parsed!.signatureValid, false);
});

// A second identity, so the direct-traffic tests have two sides.
const PEER_PRV: Buffer = Buffer.from(
	'11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff' +
		'ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544332211ff',
	'hex',
);

test('composeDirectTextPlaintext packs attempt and text type into one byte', () => {
	const plain = composeDirectTextPlaintext('hi', 0x2211, 0, 0);
	assert.equal(plain.readUInt32LE(0), 0x2211);
	assert.equal(plain[4], 0);
	assert.equal(plain.subarray(5).toString('utf8'), 'hi', 'the trailing NUL is not sent');

	// attempt in the low 2 bits, text type above them
	assert.equal(composeDirectTextPlaintext('x', 0, 1, 2)[4], 2 | (1 << 2));
	assert.equal(composeDirectTextPlaintext('x', 0, 2, 3)[4], 3 | (2 << 2));
});

test('composeDirectTextPlaintext enforces the firmware text limit', () => {
	assert.throws(() => composeDirectTextPlaintext('x'.repeat(161), 0), /caps direct text at 160/);
});

test('expectedAckCode is sha256(plaintext || sender public key) truncated to 4 bytes', () => {
	const plaintext = composeDirectTextPlaintext('ping', 1000);
	const expected = createHash('sha256')
		.update(plaintext)
		.update(FW_TEST_PUB)
		.digest()
		.subarray(0, 4);
	assert.equal(expectedAckCode(plaintext, FW_TEST_PUB).toString('hex'), expected.toString('hex'));
});

test('a direct message encoded for a peer decodes back with that peer key', async () => {
	const senderPub = await publicKeyFromPrivate(FW_TEST_PRV);
	const peerPub = await publicKeyFromPrivate(PEER_PRV);
	const shared = await calcSharedSecret(FW_TEST_PRV, peerPub);

	const plaintext = composeDirectTextPlaintext('hello over the air', 1234);
	const payload = composeDirectPayload(shared, peerPub, senderPub, plaintext);
	const frame = buildFrame({
		routeType: ROUTE_TYPE_DIRECT,
		payloadType: 0x02,
		payload,
	});

	// the recipient decodes with THEIR private key and the sender's public key
	const decoded = await decodePacket(frame, {
		identities: [{ name: 'peer', privateKey: PEER_PRV }],
		peers: [{ name: 'sender', publicKey: senderPub }],
	});
	assert.equal(decoded.payloadTypeName, 'TXT_MSG');
	assert.equal((decoded.decrypted as Record<string, unknown>).text, 'hello over the air');
	assert.equal((decoded.decrypted as Record<string, unknown>).timestamp, 1234);
	assert.equal((decoded.decrypted as Record<string, unknown>).peerName, 'sender');
});

test('a direct message stays sealed for the wrong private key', async () => {
	const senderPub = await publicKeyFromPrivate(FW_TEST_PRV);
	const peerPub = await publicKeyFromPrivate(PEER_PRV);
	const shared = await calcSharedSecret(FW_TEST_PRV, peerPub);
	const payload = composeDirectPayload(
		shared,
		peerPub,
		senderPub,
		composeDirectTextPlaintext('secret', 1),
	);
	const frame = buildFrame({ routeType: ROUTE_TYPE_DIRECT, payloadType: 0x02, payload });

	const decoded = await decodePacket(frame, {
		identities: [{ name: 'stranger', privateKey: FW_TEST_PRV }],
		peers: [{ name: 'sender', publicKey: senderPub }],
	});
	assert.equal(decoded.decrypted, undefined);
	assert.match(decoded.undecryptedReason!, /no supplied key pair matched/);
});

test('composeAnonPayload carries the full sender key so a stranger can reply', async () => {
	const senderPub = await publicKeyFromPrivate(FW_TEST_PRV);
	const peerPub = await publicKeyFromPrivate(PEER_PRV);
	const shared = await calcSharedSecret(FW_TEST_PRV, peerPub);
	const payload = composeAnonPayload(shared, peerPub, senderPub, Buffer.from('01020304', 'hex'));

	assert.equal(payload[0], peerPub[0], 'dest hash is the first byte of the recipient key');
	assert.equal(payload.subarray(1, 33).toString('hex'), senderPub.toString('hex'));
	assert.ok(macThenDecrypt(shared, payload.subarray(33)), 'the tail is the encrypted blob');
});

test('composeTracePayload puts the route in the payload and the hop size in the flags', () => {
	const payload = composeTracePayload(0x11223344, 0, Buffer.from('1be2dddd', 'hex'), 2);
	assert.equal(payload.readUInt32LE(0), 0x11223344, 'tag');
	assert.equal(payload.readUInt32LE(4), 0, 'auth code');
	assert.equal(payload[8], 1, 'flags carry the hop size as a shift: 1 << 1 = 2 bytes');
	assert.equal(payload.subarray(9).toString('hex'), '1be2dddd');

	assert.throws(() => composeTracePayload(1, 0, Buffer.alloc(4), 3), /must be 1, 2, 4 or 8/);
	assert.throws(() => composeTracePayload(1, 0, Buffer.alloc(3), 2), /not a whole number/);
});

test('composeMultipartPayload packs remaining and inner type into one byte', () => {
	const payload = composeMultipartPayload(0x03, 2, Buffer.from('aabbccdd', 'hex'));
	assert.equal(payload[0], (2 << 4) | 0x03);
	assert.equal(payload.subarray(1).toString('hex'), 'aabbccdd');
	assert.throws(() => composeMultipartPayload(3, 16, Buffer.alloc(1)), /Remaining must be 0-15/);
});

test('composePathPlaintext round trips through parsePathPlaintext', () => {
	const pathLen = (1 << 6) | 2; // 2 hops of 2 bytes
	const plaintext = composePathPlaintext(
		pathLen,
		Buffer.from('aabbccdd', 'hex'),
		7,
		Buffer.from('ff', 'hex'),
	);
	assert.deepEqual(parsePathPlaintext(plaintext), {
		pathLen,
		hops: 2,
		pathHashSize: 2,
		returnPath: 'aabbccdd',
		extraType: 7,
		extra: 'ff',
	});
});

test('composePathPlaintext uses the firmware filler when there is no extra', () => {
	const plaintext = composePathPlaintext(0, Buffer.alloc(0), null, Buffer.alloc(0));
	assert.equal(plaintext[0], 0, 'no hops');
	assert.equal(plaintext[1], 0xff, 'the dummy payload type the firmware writes');
	assert.equal(plaintext.length, 6, 'plus four filler bytes');
});

test('composePathPlaintext rejects a path that contradicts its length byte', () => {
	assert.throws(
		() => composePathPlaintext((1 << 6) | 2, Buffer.alloc(3), null, Buffer.alloc(0)),
		/says 2 hops of 2/,
	);
});
