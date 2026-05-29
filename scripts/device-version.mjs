/** READ-ONLY: query the device firmware/protocol info. */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ExtendedTCPConnection = require('../dist/nodes/shared/vendor/meshcore-tcp.js').default;

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);

function hexReplacer(_k, v) {
	if (v && v.type === 'Buffer' && Array.isArray(v.data)) return Buffer.from(v.data).toString('hex');
	if (v instanceof Uint8Array) return Buffer.from(v).toString('hex');
	return v;
}

function waitForConnected(conn, ms) {
	return new Promise((resolve, reject) => {
		const t = setTimeout(() => reject(new Error('connect timeout')), ms);
		conn.once('connected', () => { clearTimeout(t); resolve(); });
	});
}

function withTimeout(p, ms, label) {
	return Promise.race([
		Promise.resolve(p),
		new Promise((_, rej) => setTimeout(() => rej(new Error(`${label}: timeout`)), ms)),
	]);
}

const conn = new ExtendedTCPConnection(host, port);
const connected = waitForConnected(conn, 12000);
await conn.connect();
await connected;

try {
	const info = await withTimeout(conn.deviceQuery(1), 12000, 'deviceQuery');
	console.log('deviceQuery (DEVICE_INFO):', JSON.stringify(info, hexReplacer));
} catch (e) {
	console.log('ERR deviceQuery:', e.message);
}

conn.close();
process.exit(0);
