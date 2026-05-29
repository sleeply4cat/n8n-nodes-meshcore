/**
 * One-off READ-ONLY device check. Connects to a MeshCore device and runs only
 * commands that neither change settings, transmit over the radio, nor drain the
 * message queue. Loads the built bundle (the extended TCP connection).
 *
 * Usage: node scripts/device-readonly-test.mjs <host> <port>
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ExtendedTCPConnection = require('../dist/nodes/shared/vendor/meshcore-tcp.js').default;

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);

function hexReplacer(_key, value) {
	if (value && value.type === 'Buffer' && Array.isArray(value.data)) {
		return Buffer.from(value.data).toString('hex');
	}
	if (value instanceof Uint8Array) {
		return Buffer.from(value).toString('hex');
	}
	return value;
}

function withTimeout(promise, ms, label) {
	return Promise.race([
		Promise.resolve(promise),
		new Promise((_, reject) => setTimeout(() => reject(new Error(`timeout after ${ms}ms`)), ms)),
	]).catch((e) => {
		throw new Error(`${label}: ${e.message}`);
	});
}

function waitForConnected(conn, ms) {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error(`connect timeout after ${ms}ms`)), ms);
		conn.once('connected', () => {
			clearTimeout(timer);
			resolve();
		});
	});
}

async function run() {
	console.log(`Connecting to ${host}:${port} ...`);
	const conn = new ExtendedTCPConnection(host, port);
	const connected = waitForConnected(conn, 12000);
	await conn.connect();
	await connected;
	console.log('Connected.\n');

	const steps = [
		['getSelfInfo', () => conn.getSelfInfo(10000)],
		['getDeviceTime', () => conn.getDeviceTime()],
		['getBatteryVoltage', () => conn.getBatteryVoltage()],
		['getStats(core)', () => conn.getStats(0)],
		['getStats(radio)', () => conn.getStats(1)],
		['getStats(packets)', () => conn.getStats(2)],
		['getContacts', () => conn.getContacts()],
		['getChannels', () => conn.getChannels()],
		['getCustomVars', () => conn.getCustomVars()],
		['getTuningParams', () => conn.getTuningParams()],
		['getAutoAddConfig', () => conn.getAutoAddConfig()],
		['getAllowedRepeatFreq', () => conn.getAllowedRepeatFreq()],
		['getDefaultFloodScope', () => conn.getDefaultFloodScope()],
	];

	let firstContactKey = null;
	for (const [label, fn] of steps) {
		try {
			const result = await withTimeout(fn(), 12000, label);
			if (label === 'getContacts' && Array.isArray(result) && result.length > 0) {
				firstContactKey = result[0].publicKey;
				console.log(`OK  ${label}: ${result.length} contact(s)`);
			} else {
				console.log(`OK  ${label}: ${JSON.stringify(result, hexReplacer)}`);
			}
		} catch (e) {
			console.log(`ERR ${label}: ${e.message}`);
		}
	}

	// gap commands that need a contact public key
	if (firstContactKey) {
		for (const [label, fn] of [
			['getContactByKey', () => conn.getContactByKey(firstContactKey)],
			['getAdvertPath', () => conn.getAdvertPath(firstContactKey)],
		]) {
			try {
				const result = await withTimeout(fn(), 12000, label);
				console.log(`OK  ${label}: ${JSON.stringify(result, hexReplacer)}`);
			} catch (e) {
				console.log(`ERR ${label}: ${e.message}`);
			}
		}
	} else {
		console.log('(no contacts on device — skipping getContactByKey / getAdvertPath)');
	}

	conn.close();
	console.log('\nDone (connection closed).');
}

run().then(
	() => process.exit(0),
	(e) => {
		console.error('FATAL:', e.message);
		process.exit(1);
	},
);
