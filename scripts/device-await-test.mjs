/** Authorized: validate await-operations end-to-end via the node handlers. */
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');
const { operations } = require('../dist/nodes/MeshCore/operations.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const hex = (u) => Buffer.from(u).toString('hex');
const ctxOf = (params) => ({ getNodeParameter: (name, _i, def) => params[name] ?? def });

const conn = await ConnectionManager.acquire({ host, port });
const carName = process.argv[4] ?? 'MyContact';
const repName = process.argv[5] ?? 'MyRepeater';
const car = await conn.run((c) => c.findContactByName(carName));
const rep = await conn.run((c) => c.findContactByName(repName));

if (car) {
	console.log('--- sendDirectAwaitDelivery -> Car ---');
	const r = await operations['message:sendDirectAwaitDelivery'](
		conn,
		ctxOf({ contactPublicKey: hex(car.publicKey), message: `n8n await ${Date.now() % 100000}`, ackTimeoutMs: 15000 }),
		0,
	);
	console.log(JSON.stringify(r));
} else {
	console.log(`${carName} not found`);
}

if (rep) {
	console.log('--- discoverPath -> MyRepeater ---');
	const r = await operations['diagnostics:discoverPath'](
		conn,
		ctxOf({ contactPublicKey: hex(rep.publicKey), resultTimeoutMs: 30000 }),
		0,
	);
	console.log(JSON.stringify(r));
} else {
	console.log(`${repName} not found`);
}

ConnectionManager.release(conn);
process.exit(0);
