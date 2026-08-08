/**
 * Trace an explicit route and print the reply. Reads the device's path-hash mode from
 * DEVICE_INFO and uses it as the trace hash size, so the route is interpreted the same way
 * the mesh interprets it.
 *
 * Usage: node scripts/device-trace-path.mjs <host> <port> <pathHex> [runs] [extraTimeoutMs]
 *   e.g. node scripts/device-trace-path.mjs meshproxy.lan 5000 1be2dddd1be2 3
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const pathHex = (process.argv[4] ?? '').replace(/[^0-9a-fA-F]/g, '');
const RUNS = Number(process.argv[5] ?? 3);
const EXTRA_MS = Number(process.argv[6] ?? 5000);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
	if (!pathHex) {
		console.error('give a route as hex, e.g. 1be2dddd1be2');
		process.exit(2);
	}
	const conn = await ConnectionManager.acquire({ host, port });

	const info = await conn.run((c) => c.deviceQuery());
	const hashSize = info.pathHashSize ?? 1;
	console.log(
		`Device: ${info.manufacturerName} ${info.firmwareVersion} (protocol v${info.firmwareVer}), ` +
			`pathHashMode=${info.pathHashMode} -> ${hashSize} byte(s) per hop, clientRepeat=${info.clientRepeat}`,
	);

	const route = Buffer.from(pathHex, 'hex');
	const hops = [];
	for (let i = 0; i < route.length; i += hashSize) {
		hops.push(route.subarray(i, i + hashSize).toString('hex'));
	}
	console.log(`Route: ${route.toString('hex')} = ${hops.length} hop(s): ${hops.join(' -> ')}\n`);

	let ok = 0;
	for (let i = 1; i <= RUNS; i++) {
		const started = Date.now();
		try {
			const r = await conn.run(
				(c) => c.tracePath(route, EXTRA_MS, hashSize),
				60000, // queue ceiling well above the trace's own budget
			);
			ok++;
			console.log(
				`#${i} OK (${Date.now() - started}ms)  hops=${r.hops} hashSize=${r.hashSize} ` +
					`path=${r.pathHashes} snrs=[${r.pathSnrs.join(', ')}] lastSnr=${r.lastSnr}`,
			);
		} catch (e) {
			console.log(`#${i} ERR (${Date.now() - started}ms) ${e?.message ?? e}`);
		}
		if (i < RUNS) await sleep(2000);
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
