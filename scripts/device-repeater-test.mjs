/**
 * Non-destructive repeater test (authorized) against contact "MyRepeater" (a type-2
 * repeater with open guest access). Validates the repeater-response push parsers:
 * StatusResponse(0x87), TelemetryResponse(0x8B), BinaryResponse(0x8C, via getNeighbours),
 * TraceData(0x89), PathDiscoveryResponse(0x8D), LoginSuccess(0x85), plus the gap commands
 * hasConnection / logout. No settings changed; guest login only.
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const REPEATER = process.argv[4] ?? 'MyRepeater';

function hexReplacer(_k, v) {
	if (v && v.type === 'Buffer' && Array.isArray(v.data)) return Buffer.from(v.data).toString('hex');
	if (v instanceof Uint8Array) return Buffer.from(v).toString('hex');
	return v;
}
const show = (o) => JSON.stringify(o, hexReplacer);
const withTimeout = (p, ms, label) =>
	Promise.race([
		Promise.resolve(p),
		new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout ${ms}ms`)), ms)),
	]).catch((e) => {
		throw new Error(`${label}: ${e?.message ?? 'device error / no response'}`);
	});

async function step(conn, label, fn, ms = 25000) {
	try {
		const r = await withTimeout(conn.run(fn), ms, label);
		console.log(`OK  ${label}: ${show(r)}`);
		return r;
	} catch (e) {
		console.log(`ERR ${label}: ${e?.message ?? e}`);
		return null;
	}
}

async function main() {
	const conn = await ConnectionManager.acquire({ host, port });
	console.log('Connected.\n');

	const pushes = { 0x85: 'LoginSuccess', 0x86: 'LoginFail', 0x87: 'StatusResponse', 0x89: 'TraceData', 0x8b: 'TelemetryResponse', 0x8c: 'BinaryResponse', 0x8d: 'PathDiscoveryResponse' };
	const unsubs = Object.entries(pushes).map(([code, name]) =>
		conn.subscribe(Number(code), (p) => console.log(`<< push ${name}: ${show(p)}`)),
	);

	const rep = await conn.run((c) => c.findContactByName(REPEATER));
	if (!rep) {
		console.log(`ERR "${REPEATER}" not found`);
		ConnectionManager.release(conn);
		return;
	}
	console.log(`Repeater: type=${rep.type} outPathLen=${rep.outPathLen} key=${show(rep.publicKey).slice(0, 12)}…\n`);
	const key = rep.publicKey;

	await step(conn, 'getStatus', (c) => c.getStatus(key));
	await step(conn, 'getTelemetry', (c) => c.getTelemetry(key));
	await step(conn, 'getNeighbours', (c) => c.getNeighbours(key, 10, 0, 0, 8));

	// trace along the known out path, if any
	if (rep.outPathLen > 0 && rep.outPath) {
		const path = Buffer.from(rep.outPath).slice(0, rep.outPathLen);
		await step(conn, 'tracePath', (c) => c.tracePath(path, 2000));
	} else {
		console.log('(no stored out path for repeater — skipping tracePath)');
	}

	await step(conn, 'sendPathDiscoveryReq', (c) => c.sendPathDiscoveryReq(key));

	// guest login session
	await step(conn, 'login(guest)', (c) => c.login(key, ''));
	await step(conn, 'hasConnection', (c) => c.hasConnection(key));

	console.log('\nListening 25s for async pushes (path-discovery, login)...\n');
	await new Promise((r) => setTimeout(r, 25000));

	await step(conn, 'logout', (c) => c.logout(key));

	for (const u of unsubs) u();
	ConnectionManager.release(conn);
	console.log('\nDone.');
}

main().then(
	() => process.exit(0),
	(e) => {
		console.error('FATAL:', e?.message ?? e);
		process.exit(1);
	},
);
