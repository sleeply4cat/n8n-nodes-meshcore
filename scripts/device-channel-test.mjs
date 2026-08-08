/**
 * READ-ONLY regression check for channel lookups.
 *
 * The base meshcore.js `getChannel` resolves on the first ChannelInfo frame regardless of
 * which channel it describes, so one late reply shifts every later lookup by one and a
 * workflow that resolves a channel by name then sends to that index starts hitting the
 * wrong channel. This walks the slots repeatedly and asserts every reply carries the index
 * that was asked for, which is what makes that desync impossible.
 *
 * Usage: node scripts/device-channel-test.mjs <host> <port> [rounds]
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const ROUNDS = Number(process.argv[4] ?? 5);

async function main() {
	const conn = await ConnectionManager.acquire({ host, port });

	const channels = await conn.run((c) => c.getChannels());
	console.log(`${channels.length} slot(s):`);
	for (const ch of channels) {
		console.log(`  [${ch.channelIdx}] ${JSON.stringify(ch.name)}`);
	}

	// Every slot, asked for individually, must answer with its own index. Interleave the
	// order so a stream that answers "the previous request" would show up immediately.
	const order = [...channels.map((c) => c.channelIdx)].reverse();
	let mismatches = 0;
	let lookups = 0;
	for (let round = 1; round <= ROUNDS; round++) {
		for (const idx of order) {
			const got = await conn.run((c) => c.getChannel(idx));
			lookups++;
			if (got.channelIdx !== idx) {
				mismatches++;
				console.log(`  MISMATCH round ${round}: asked ${idx}, got ${got.channelIdx} (${got.name})`);
			}
		}
	}
	console.log(`\n${lookups - mismatches}/${lookups} lookups returned the channel that was asked for.`);

	// findChannelByName must report an index that really belongs to that name. Unconfigured
	// slots all share the empty name, and the lookup returns the first match by contract, so
	// compare against that first match rather than against each duplicate slot.
	const named = channels.filter((c) => c.name.length > 0);
	for (const ch of named) {
		const expected = channels.find((c) => c.name === ch.name).channelIdx;
		const found = await conn.run((c) => c.findChannelByName(ch.name));
		const ok = found && found.channelIdx === expected;
		console.log(`findChannelByName(${JSON.stringify(ch.name)}) -> idx ${found?.channelIdx} ${ok ? 'OK' : `WRONG (expected ${expected})`}`);
	}
	console.log(`(${channels.length - named.length} unconfigured slot(s) skipped — they share the empty name)`);

	ConnectionManager.release(conn);
}

main().then(
	() => process.exit(0),
	(e) => {
		console.error('FATAL:', e?.message ?? e);
		process.exit(1);
	},
);
