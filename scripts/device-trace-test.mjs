/**
 * Non-destructive: trace the path to the repeater's discovered neighbour, several times
 * (the link is flaky). Validates the TraceData (0x89) push parser. The trace path is the
 * per-hop path-hash bytes (first byte of each node's public key):
 * KOT -> repeater(0xdd..) -> neighbour(0x4c..).
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const RUNS = Number(process.argv[4] ?? 5);
const REPEATER = process.argv[5] ?? 'MyRepeater';

function hexReplacer(_k, v) {
	if (v && v.type === 'Buffer' && Array.isArray(v.data)) return Buffer.from(v.data).toString('hex');
	if (v instanceof Uint8Array) return Buffer.from(v).toString('hex');
	return v;
}
const show = (o) => JSON.stringify(o, hexReplacer);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
	const conn = await ConnectionManager.acquire({ host, port });
	console.log('Connected.');

	conn.subscribe(0x89, (p) => console.log(`   << TraceData push: ${show(p)}`));

	const rep = await conn.run((c) => c.findContactByName(REPEATER));
	if (!rep) {
		console.log(`ERR "${REPEATER}" not found`);
		ConnectionManager.release(conn);
		return;
	}
	const repByte = Buffer.from(rep.publicKey)[0];

	const neigh = await conn.run((c) => c.getNeighbours(rep.publicKey, 10, 0, 0, 8));
	const first = neigh?.neighbours?.[0];
	if (!first) {
		console.log('ERR no neighbours reported by repeater');
		ConnectionManager.release(conn);
		return;
	}
	const neighByte = Buffer.from(first.publicKeyPrefix, 'hex')[0];
	const path = Buffer.from([repByte, neighByte]);
	console.log(`Neighbour: ${first.publicKeyPrefix} (snr ${first.snr}). Trace path = ${path.toString('hex')}\n`);

	let ok = 0;
	for (let i = 1; i <= RUNS; i++) {
		try {
			const r = await conn.run((c) => c.tracePath(path, 5000));
			ok++;
			console.log(`#${i} OK  tracePath: ${show(r)}`);
		} catch (e) {
			console.log(`#${i} ERR tracePath: ${e?.message ?? 'device error / timeout'}`);
		}
		await sleep(1500);
	}

	console.log(`\n${ok}/${RUNS} traces succeeded.`);
	ConnectionManager.release(conn);
}

main().then(
	() => process.exit(0),
	(e) => {
		console.error('FATAL:', e?.message ?? e);
		process.exit(1);
	},
);
