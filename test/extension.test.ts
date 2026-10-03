import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

// The extended connection is a bundled CommonJS artifact; load it via require.
const require = createRequire(import.meta.url);
const ExtendedTCPConnection = require('../dist/nodes/shared/vendor/meshcore-tcp.js').default;

function tick(): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, 0));
}

function le32(n: number): number[] {
	return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}

test('hasConnection encodes [CMD_HAS_CONNECTION, pubKey] and resolves on OK', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let captured: Uint8Array | null = null;
	conn.sendToRadioFrame = async (bytes: Uint8Array) => {
		captured = bytes;
	};

	const pubKey = Buffer.alloc(32, 0xaa);
	const promise = conn.hasConnection(pubKey);

	assert.ok(captured, 'frame was sent');
	assert.equal(captured![0], 28, 'opcode is CMD_HAS_CONNECTION');
	assert.equal(captured!.length, 1 + 32);
	assert.equal(Buffer.from(captured!.slice(1)).toString('hex'), 'aa'.repeat(32));

	conn.emit(0); // RESP_CODE_OK
	const result = await promise;
	assert.deepEqual(result, { connected: true });
});

test('hasConnection resolves {connected:false} on ERR', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	conn.sendToRadioFrame = async () => {};
	const promise = conn.hasConnection(Buffer.alloc(32));
	conn.emit(1); // RESP_CODE_ERR
	assert.deepEqual(await promise, { connected: false });
});

test('onFrameReceived parses TUNING_PARAMS (code 23)', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(23, (p: unknown) => { payload = p; });

	conn.onFrameReceived(Uint8Array.from([23, ...le32(5000), ...le32(1500)]));
	await tick();

	assert.deepEqual(payload, { rxDelayBase: 5, airtimeFactor: 1.5 });
});

test('onFrameReceived parses CUSTOM_VARS (code 21) into a vars object', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(21, (p: unknown) => { payload = p; });

	const body = Buffer.from('gps:1,name:node-a', 'utf8');
	conn.onFrameReceived(Uint8Array.from([21, ...body]));
	await tick();

	assert.deepEqual(payload.vars, { gps: '1', name: 'node-a' });
});

test('onFrameReceived parses CONTACT_DELETED push (0x8f)', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(0x8f, (p: unknown) => { payload = p; });

	conn.onFrameReceived(Uint8Array.from([0x8f, ...Array(32).fill(0xbb)]));
	await tick();

	assert.deepEqual(payload, { publicKey: 'bb'.repeat(32) });
});

test('onFrameReceived parses CONTROL_DATA push (0x8e) with signed snr/rssi + decoded hops (no hashSize — frame has no path bytes)', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(0x8e, (p: unknown) => { payload = p; });

	// snr=-4 (0xFC) -> -1.0 after /4 ; rssi=-50 (0xCE) ; pathLen=0x43 (packed: 3 hops, 2-byte hash) ; payload=de ad
	conn.onFrameReceived(Uint8Array.from([0x8e, 0xfc, 0xce, 0x43, 0xde, 0xad]));
	await tick();

	assert.equal(payload.snr, -1);
	assert.equal(payload.rssi, -50);
	assert.equal('pathLen' in payload, false, 'the packed byte is not surfaced');
	assert.equal(payload.hops, 3);
	assert.equal(payload.hashSize, undefined, 'no path bytes in this frame → hashSize would be meaningless');
	assert.equal(payload.payload, 'dead');
});

test('onFrameReceived parses ADVERT_PATH (22) honoring packed pathLen byte count', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(22, (p: unknown) => { payload = p; });
	// recvTimestamp = 0x11223344 LE ; pathLen = 0x43 (3 hops, 2-byte hash → 6 real bytes)
	const ts = [0x44, 0x33, 0x22, 0x11];
	const path = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
	conn.onFrameReceived(Uint8Array.from([22, ...ts, 0x43, ...path]));
	await tick();
	assert.equal(payload.recvTimestamp, 0x11223344);
	assert.equal('pathLen' in payload, false, 'the packed byte is not surfaced');
	assert.equal(payload.hops, 3);
	assert.equal(payload.hashSize, 2);
	assert.equal(payload.path, 'aabbccddeeff');
});

test('onFrameReceived parses PATH_DISCOVERY_RESPONSE (0x8d) with both packed path fields', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(0x8d, (p: unknown) => { payload = p; });
	const prefix = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
	// outPath: pathLen=0x02 (2 hops × 1 byte = 2 real bytes), inPath: pathLen=0x41 (1 hop × 2 bytes = 2 real bytes)
	conn.onFrameReceived(
		Uint8Array.from([0x8d, 0x00, ...prefix, 0x02, 0xaa, 0xbb, 0x41, 0xcc, 0xdd]),
	);
	await tick();
	assert.equal(payload.pubKeyPrefix, '010203040506');
	assert.equal(payload.outPath, 'aabb');
	assert.equal(payload.outPathHops, 2);
	assert.equal(payload.outPathHashSize, 1);
	assert.equal(payload.inPath, 'ccdd');
	assert.equal(payload.inPathHops, 1);
	assert.equal(payload.inPathHashSize, 2);
	assert.equal('outPathLen' in payload || 'inPathLen' in payload, false, 'packed bytes not surfaced');
});

test('getChannel encodes [CMD 31, idx] and resolves only on the matching channelIdx', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let captured: Uint8Array | null = null;
	conn.sendToRadioFrame = async (bytes: Uint8Array) => { captured = bytes; };

	const promise = conn.getChannel(2);
	assert.equal(captured![0], 31, 'opcode is CMD_GET_CHANNEL');
	assert.equal(captured![1], 2);

	// a stale reply for another channel must NOT satisfy this lookup
	conn.emit(18, { channelIdx: 0, name: 'PUBLIC', secret: new Uint8Array(16) });
	conn.emit(18, { channelIdx: 2, name: 'HOME', secret: new Uint8Array(16) });

	const result = await promise;
	assert.equal(result.channelIdx, 2);
	assert.equal(result.name, 'HOME', 'resolved with the requested channel, not the first frame seen');
});

test('getChannel stays unresolved while only mismatched frames arrive', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	conn.sendToRadioFrame = async () => {};

	let settled = false;
	const promise = conn.getChannel(3).then(
		() => { settled = true; },
		() => { settled = true; },
	);

	conn.emit(18, { channelIdx: 1, name: 'OTHER', secret: new Uint8Array(16) });
	await tick();
	await tick();
	assert.equal(settled, false, 'a frame for a different channel is ignored, not accepted');

	conn.emit(18, { channelIdx: 3, name: 'RIGHT', secret: new Uint8Array(16) });
	await promise;
	assert.equal(settled, true);
});

test('getChannels walks slots and stops at the first ERR', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	const asked: number[] = [];
	conn.sendToRadioFrame = async (bytes: Uint8Array) => {
		const idx = bytes[1];
		asked.push(idx);
		// two configured slots, then "not found"
		setTimeout(() => {
			if (idx < 2) {
				conn.emit(18, { channelIdx: idx, name: `CH${idx}`, secret: new Uint8Array(16) });
			} else {
				conn.emit(1, { errCode: 2 }); // ERR_CODE_NOT_FOUND
			}
		}, 0);
	};

	const channels = await conn.getChannels();
	assert.deepEqual(asked, [0, 1, 2], 'stopped asking after the error');
	assert.deepEqual(channels.map((c: any) => c.name), ['CH0', 'CH1']);
});

test('sendRawPacket encodes [CMD 65, priority, packet] verbatim', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let captured: Uint8Array | null = null;
	conn.sendToRadioFrame = async (bytes: Uint8Array) => { captured = bytes; };

	// header 0x12, packed path_len 0x00 (zero hop), 4-byte payload
	const packet = Buffer.from('1200deadbeef', 'hex');
	const promise = conn.sendRawPacket(packet, 5);

	assert.equal(captured![0], 65, 'opcode is CMD_SEND_RAW_PACKET');
	assert.equal(captured![1], 5, 'priority');
	assert.equal(Buffer.from(captured!.slice(2)).toString('hex'), '1200deadbeef', 'packet is untouched');

	conn.emit(0); // RESP_CODE_OK
	assert.deepEqual(await promise, { success: true });
});

test('sendRawPacket defaults priority to 0 and rejects a packet too short to parse', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let captured: Uint8Array | null = null;
	conn.sendToRadioFrame = async (bytes: Uint8Array) => { captured = bytes; };

	const promise = conn.sendRawPacket(Buffer.from('1200deadbeef', 'hex'));
	assert.equal(captured![1], 0);
	conn.emit(0);
	await promise;

	await assert.rejects(conn.sendRawPacket(Buffer.from([0x12])), (e: unknown) => {
		assert.match((e as Error).message, /at least 2 bytes/);
		return true;
	});
});

test('sendRawData encodes [CMD 25, path length, path, payload]', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let captured: Uint8Array | null = null;
	conn.sendToRadioFrame = async (bytes: Uint8Array) => { captured = bytes; };

	const promise = conn.sendRawData(Buffer.from('dd4c', 'hex'), Buffer.from('deadbeef', 'hex'));

	assert.equal(captured![0], 25, 'opcode is CMD_SEND_RAW_DATA');
	assert.equal(captured![1], 2, 'path length is the byte count the firmware advances by');
	assert.equal(Buffer.from(captured!.slice(2)).toString('hex'), 'dd4cdeadbeef');

	conn.emit(0);
	assert.deepEqual(await promise, { success: true });
});

test('sendRawData enforces the firmware minimum payload of 4 bytes', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let sent = false;
	conn.sendToRadioFrame = async () => { sent = true; };

	await assert.rejects(conn.sendRawData(Buffer.alloc(0), Buffer.from('dead', 'hex')), (e: unknown) => {
		assert.match((e as Error).message, /at least 4 bytes \(got 2\)/);
		return true;
	});
	assert.equal(sent, false);
});

test('onFrameReceived parses DEVICE_INFO (13) including the v9+/v10+ tail flags', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(13, (p: unknown) => { payload = p; });

	const pad = (s: string, n: number) => {
		const b = Buffer.alloc(n);
		b.write(s, 'utf8');
		return [...b];
	};
	conn.onFrameReceived(
		Uint8Array.from([
			13,
			13, // firmware ver code (protocol)
			50, // MAX_CONTACTS / 2
			8, // max channels
			...le32(123456), // ble pin
			...pad('20 Mar 2026', 12),
			...pad('Heltec CT62', 40),
			...pad('v1.16.0', 20),
			0, // client_repeat (v9+)
			1, // path_hash_mode (v10+)
		]),
	);
	await tick();

	assert.equal(payload.firmwareVer, 13);
	assert.equal(payload.maxContacts, 100, 'firmware sends MAX_CONTACTS / 2');
	assert.equal(payload.maxChannels, 8);
	assert.equal(payload.blePin, 123456);
	assert.equal(payload.firmwareBuildDate, '20 Mar 2026');
	assert.equal(payload.manufacturerName, 'Heltec CT62');
	assert.equal(payload.firmwareVersion, 'v1.16.0');
	assert.equal(payload.clientRepeat, false);
	assert.equal(payload.pathHashMode, 1);
	assert.equal(payload.pathHashSize, 2, 'hash bytes per hop is mode + 1');
});

test('onFrameReceived parses DEVICE_INFO from firmware without the tail flags', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(13, (p: unknown) => { payload = p; });

	conn.onFrameReceived(Uint8Array.from([13, 8, 50, 8, ...le32(0), ...Array(12 + 40 + 20).fill(0)]));
	await tick();

	assert.equal(payload.clientRepeat, null, 'absent flag reads as unknown, not as false');
	assert.equal(payload.pathHashMode, null);
	assert.equal(payload.pathHashSize, null);
});

test('tracePath encodes the hop size as a shift in the flags byte', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let captured: Uint8Array | null = null;
	conn.sendToRadioFrame = async (bytes: Uint8Array) => { captured = bytes; };

	// 3 hops of 2 bytes: 1be2 -> dddd -> 1be2
	const promise = conn.tracePath(Buffer.from('1be2dddd1be2', 'hex'), 0, 2);
	await tick();

	assert.equal(captured![9], 1, 'flags path_sz = 1, i.e. 1 << 1 = 2 bytes per hop');
	assert.equal(captured!.length, 10 + 6);

	const tag = Buffer.from(captured!.slice(1, 5)).readUInt32LE(0);
	conn.emit(6, { result: 0, expectedAckCrc: tag, estTimeout: 5000 });
	conn.emit(0x89, { tag, pathHashes: '1be2dddd1be2', hops: 3 });
	assert.equal((await promise).hops, 3);
});

test('tracePath rejects a hop size the trace flags cannot encode', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let sent = false;
	conn.sendToRadioFrame = async () => { sent = true; };

	// the mesh path-hash mode allows 3 bytes per hop; the trace encoding (1 << path_sz) does not
	await assert.rejects(conn.tracePath(Buffer.from('1be2dddd1be2', 'hex'), 0, 3), (e: unknown) => {
		assert.match((e as Error).message, /must be 1, 2, 4 or 8 bytes/);
		return true;
	});
	assert.equal(sent, false);
});

test('tracePath rejects a route that is not a whole number of hops', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let sent = false;
	conn.sendToRadioFrame = async () => { sent = true; };

	await assert.rejects(conn.tracePath(Buffer.from('1be2dd', 'hex'), 0, 2), (e: unknown) => {
		assert.match((e as Error).message, /3 bytes, which is not a whole number of 2-byte hops/);
		return true;
	});
	assert.equal(sent, false);
});

test('setRadioParams encodes wire units and always sends the client-repeat byte', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let captured: Uint8Array | null = null;
	conn.sendToRadioFrame = async (bytes: Uint8Array) => { captured = bytes; };

	// 869.525 MHz -> 869525 kHz ; 250 kHz -> 250000 Hz
	const promise = conn.setRadioParams(869525, 250000, 11, 5, true);

	assert.ok(captured, 'frame was sent');
	assert.equal(captured![0], 11, 'opcode is CMD_SET_RADIO_PARAMS');
	assert.equal(captured!.length, 12, '1 + 4 + 4 + 1 + 1 + 1 (repeat byte is never omitted)');
	const frame = Buffer.from(captured!);
	assert.equal(frame.readUInt32LE(1), 869525);
	assert.equal(frame.readUInt32LE(5), 250000);
	assert.equal(frame[9], 11, 'spreading factor');
	assert.equal(frame[10], 5, 'coding rate');
	assert.equal(frame[11], 1, 'client repeat');

	conn.emit(0); // RESP_CODE_OK
	assert.deepEqual(await promise, { success: true });
});

test('setRadioParams sends client repeat 0 when not asked for, rather than omitting it', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let captured: Uint8Array | null = null;
	conn.sendToRadioFrame = async (bytes: Uint8Array) => { captured = bytes; };

	const promise = conn.setRadioParams(869525, 250000, 11, 5);
	assert.equal(captured!.length, 12);
	assert.equal(captured![11], 0);

	conn.emit(0);
	await promise;
});

test('setRadioParams rejects a device ERR by name', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	conn.sendToRadioFrame = async () => {};
	const promise = conn.setRadioParams(869525, 250000, 11, 5);
	conn.emit(1, { errCode: 6 }); // ERR_CODE_ILLEGAL_ARG

	await assert.rejects(promise, (e: unknown) => {
		assert.match((e as Error).message, /illegal argument \(code 6\)/);
		return true;
	});
});

test('setTuningParams encodes both fields as milli-units', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let captured: Uint8Array | null = null;
	conn.sendToRadioFrame = async (bytes: Uint8Array) => { captured = bytes; };

	const promise = conn.setTuningParams(2.5, 1.25);

	assert.equal(captured![0], 21, 'opcode is CMD_SET_TUNING_PARAMS');
	assert.equal(captured!.length, 9);
	const frame = Buffer.from(captured!);
	assert.equal(frame.readUInt32LE(1), 2500, 'rx delay base × 1000');
	assert.equal(frame.readUInt32LE(5), 1250, 'airtime factor × 1000');

	conn.emit(0);
	assert.deepEqual(await promise, { success: true });
});

test('onFrameReceived parses STATUS_RESPONSE (0x87) into RepeaterStats fields', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(0x87, (p: unknown) => { payload = p; });

	// captured from a live repeater: 60 bytes, i.e. 4 past the struct we know
	const stats =
		'640f000099fffaffe1d90000c4230000c50e000079730500bd210000070200002ba500009534000000002f0009043283a94d00008c20000000000000';
	conn.onFrameReceived(
		Uint8Array.from([0x87, 0x00, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0x5e, ...Buffer.from(stats, 'hex')]),
	);
	await tick();

	assert.equal(payload.publicKeyPrefix, 'dddddddddd5e');
	assert.equal(payload.batteryMilliVolts, 3940);
	assert.equal(payload.noiseFloor, -103);
	assert.equal(payload.lastRssi, -6);
	assert.equal(payload.packetsReceived, 55777);
	assert.equal(payload.uptimeSecs, 357241);
	assert.equal(payload.lastSnr, 11.75, 'SNR is stored times four');
	assert.equal(payload.floodDuplicates, 33586);
	assert.equal(payload.receiveErrors, 8332);
	assert.equal(payload.trailingBytes, '00000000', 'bytes past the known struct are surfaced');
	assert.equal(payload.statusData, stats, 'raw bytes are kept alongside');
});

test('STATUS_RESPONSE leaves later fields null when the struct is short', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(0x87, (p: unknown) => { payload = p; });

	// only the first four 16-bit fields present
	conn.onFrameReceived(
		Uint8Array.from([0x87, 0x00, 1, 2, 3, 4, 5, 6, ...Buffer.from('640f000099fffaff', 'hex')]),
	);
	await tick();

	assert.equal(payload.batteryMilliVolts, 3940);
	assert.equal(payload.packetsReceived, null, 'absent field reads as unknown, not garbage');
	assert.equal(payload.trailingBytes, '');
});

test('onFrameReceived parses TELEMETRY_RESPONSE (0x8b) and decodes the LPP payload', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(0x8b, (p: unknown) => { payload = p; });

	// channel 1, type 116 (LPP_VOLTAGE), value 0 — as the device itself reports on USB
	conn.onFrameReceived(
		Uint8Array.from([0x8b, 0x00, 0xd8, 0x83, 0xd5, 0x84, 0x84, 0x9e, 0x01, 0x74, 0x00, 0x00]),
	);
	await tick();

	assert.equal(payload.publicKeyPrefix, 'd883d584849e');
	assert.equal(payload.lppSensorData, '01740000');
	assert.deepEqual(payload.telemetry, [{ channel: 1, type: 116, value: 0 }]);
	assert.equal(payload.pubKeyPrefix, undefined, 'no duplicate of the prefix under a second name');
});

test('onFrameReceived parses SELF_INFO, naming the bytes meshcore.js calls reserved', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(5, (p: unknown) => { payload = p; });

	conn.onFrameReceived(
		Uint8Array.from([
			5,
			1, // adv type
			20, // tx power
			22, // max tx power
			...Array(32).fill(0xab), // public key
			...le32(0), ...le32(0), // lat, lon
			2, // multi_acks
			1, // advert_loc_policy
			(3 << 4) | (2 << 2) | 1, // telemetry modes: env, loc, base
			1, // manual_add_contacts
			...le32(869525), ...le32(250000), // freq kHz, bw Hz
			11, 5, // sf, cr
			...Buffer.from('KOT', 'utf8'),
		]),
	);
	await tick();

	assert.equal(payload.multiAcks, 2);
	assert.equal(payload.advertLocPolicy, 1);
	assert.equal(payload.telemetryModeBase, 1);
	assert.equal(payload.telemetryModeLoc, 2);
	assert.equal(payload.telemetryModeEnv, 3);
	assert.equal(payload.manualAddContacts, 1);
	assert.equal(payload.radioFreq, 869525);
	assert.equal(payload.radioSf, 11);
	assert.equal(payload.name, 'KOT');
	assert.equal(payload.reserved, undefined, 'the three bytes are named, not lumped together');
});

test('getSelfTelemetry sends the short 4-byte frame the firmware needs', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let captured: Uint8Array | null = null;
	conn.sendToRadioFrame = async (bytes: Uint8Array) => { captured = bytes; };

	const promise = conn.getSelfTelemetry();
	assert.equal(captured!.length, 4, 'no public key: that is what selects self telemetry');
	assert.equal(captured![0], 39, 'opcode is CMD_SEND_TELEMETRY_REQ');

	conn.emit(0x8b, { publicKeyPrefix: 'aabbccddeeff', telemetry: [], lppSensorData: '' });
	assert.equal((await promise).publicKeyPrefix, 'aabbccddeeff');
});

test('getTelemetry ignores a reply for a different node and names a timeout', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	conn.sendToRadioFrame = async () => {};
	const key = Buffer.alloc(32, 0xab);

	const promise = conn.getTelemetry(key, 30);
	await tick();
	conn.emit(6, { result: 0, expectedAckCrc: 0, estTimeout: 20 });
	conn.emit(0x8b, { publicKeyPrefix: '112233445566', telemetry: [] }); // someone else's

	await assert.rejects(promise, (e: unknown) => {
		assert.ok(e instanceof Error, 'a real Error, not the bare string meshcore.js throws');
		assert.match((e as Error).message, /telemetry request was sent but no reply arrived within 50ms/);
		return true;
	});
});

test('onFrameReceived parses TRACE_DATA (0x89) with path_sz-sized SNR list', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(0x89, (p: unknown) => { payload = p; });

	// pathLen = 4 REAL hash bytes, flags = 1 -> path_sz 1 -> 2-byte hashes -> 2 hops,
	// so the firmware writes 2 SNR bytes (not 4) followed by the final SNR.
	conn.onFrameReceived(
		Uint8Array.from([
			0x89, 0x00, 0x04, 0x01,
			...le32(0xcafebabe), ...le32(0),
			0xaa, 0xbb, 0xcc, 0xdd, // path hashes
			0x08, 0xfc, // per-hop snrs: 2.0 and -1.0
			0x10, // final snr: 4.0
		]),
	);
	await tick();

	assert.equal(payload.hops, 2);
	assert.equal(payload.hashSize, 2);
	assert.equal(payload.tag, 0xcafebabe);
	assert.equal(payload.pathHashes, 'aabbccdd');
	assert.deepEqual(payload.pathSnrs, [2, -1]);
	assert.equal(payload.lastSnr, 4, 'final SNR is not swallowed by an over-long SNR read');
});

test('tracePath rejects an empty path with an explanatory Error, sending nothing', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let sent = false;
	conn.sendToRadioFrame = async () => { sent = true; };

	await assert.rejects(conn.tracePath(Buffer.alloc(0), 0), (e: unknown) => {
		assert.ok(e instanceof Error, 'rejects with a real Error, not a bare value');
		assert.match((e as Error).message, /at least one path byte/);
		return true;
	});
	assert.equal(sent, false, 'a frame the firmware would refuse is never put on the wire');
});

test('tracePath encodes [CMD 36, tag, auth, flags, path] and resolves on a tag-matched push', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let captured: Uint8Array | null = null;
	conn.sendToRadioFrame = async (bytes: Uint8Array) => { captured = bytes; };

	const promise = conn.tracePath(Buffer.from([0xdd, 0x4c]), 0);
	await tick();

	assert.ok(captured, 'frame was sent');
	assert.equal(captured![0], 36, 'opcode is CMD_SEND_TRACE_PATH');
	assert.equal(captured!.length, 10 + 2, '10-byte header + path (firmware requires len > 10)');
	assert.equal(captured![9], 0, 'flags byte');
	const tag = Buffer.from(captured!.slice(1, 5)).readUInt32LE(0);

	conn.emit(6, { result: 0, expectedAckCrc: tag, estTimeout: 5000 }); // RESP_CODE_SENT
	conn.emit(0x89, { tag: tag ^ 0xff, pathHashes: 'ffff' }); // a different trace: ignored
	conn.emit(0x89, { tag, pathHashes: 'dd4c', pathSnrs: [1, 2], lastSnr: 3 });

	const result = await promise;
	assert.equal(result.pathHashes, 'dd4c');
});

test('tracePath rejects a device ERR by name instead of a bare undefined', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	conn.sendToRadioFrame = async () => {};

	const promise = conn.tracePath(Buffer.from([0xdd]), 0);
	await tick();
	conn.emit(1, { errCode: 6 }); // RESP_CODE_ERR / ERR_CODE_ILLEGAL_ARG

	await assert.rejects(promise, (e: unknown) => {
		assert.ok(e instanceof Error);
		assert.match((e as Error).message, /illegal argument \(code 6\)/);
		return true;
	});
});

test('tracePath reports a reply timeout as a timeout, naming the budget it waited', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	conn.sendToRadioFrame = async () => {};

	const promise = conn.tracePath(Buffer.from([0xdd]), 30);
	await tick();
	conn.emit(6, { result: 0, expectedAckCrc: 0, estTimeout: 20 }); // SENT, tiny estimate

	await assert.rejects(promise, (e: unknown) => {
		assert.ok(e instanceof Error);
		assert.match((e as Error).message, /sent but no reply arrived within 50ms/);
		assert.match((e as Error).message, /device estimate 20ms \+ extra timeout 30ms/);
		return true;
	});
});

test('onFrameReceived delegates unknown/base codes to the base class', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let selfInfo: unknown = null;
	conn.on(5, (p: unknown) => { selfInfo = p; }); // RESP_CODE_SELF_INFO handled by base parser
	// minimal-ish self info frame is complex; just assert no throw and base path runs
	assert.doesNotThrow(() => conn.onFrameReceived(Uint8Array.from([0]))); // OK frame -> base
	await tick();
	assert.equal(selfInfo, null);
});
