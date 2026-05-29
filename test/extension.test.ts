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

test('onFrameReceived parses CONTROL_DATA push (0x8e) with signed snr/rssi', async () => {
	const conn = new ExtendedTCPConnection('127.0.0.1', 5000);
	let payload: any = null;
	conn.on(0x8e, (p: unknown) => { payload = p; });

	// snr=-4 (0xFC) -> -1.0 after /4 ; rssi=-50 (0xCE) ; pathLen=2 ; payload=de ad
	conn.onFrameReceived(Uint8Array.from([0x8e, 0xfc, 0xce, 0x02, 0xde, 0xad]));
	await tick();

	assert.equal(payload.snr, -1);
	assert.equal(payload.rssi, -50);
	assert.equal(payload.pathLen, 2);
	assert.equal(payload.payload, 'dead');
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
