/**
 * Authorized read-only test: listen for incoming channel (group) messages and print
 * how the trigger now splits them into { author, text, rawText }. No settings changed.
 *
 * Usage: node scripts/device-listen-channel.mjs <host> <port>
 * Then, from ANOTHER node on the mesh, post a channel message like "Alice: hello".
 * Ctrl-C to stop.
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');
const { startMessageStream } = require('../dist/nodes/MeshCoreTrigger/messageStream.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);

async function main() {
	console.log(`Connecting to ${host}:${port} ...`);
	const conn = await ConnectionManager.acquire({ host, port });
	console.log('Connected. Listening for channel messages (Ctrl-C to stop).');

	const unsubscribe = startMessageStream(conn, ['channelMessage'], (event, payload) => {
		console.log(`\n[${event}]`);
		console.log(`  author : ${JSON.stringify(payload.author)}`);
		console.log(`  text   : ${JSON.stringify(payload.text)}`);
		console.log(`  rawText: ${JSON.stringify(payload.rawText)}`);
		console.log(`  channelIdx=${payload.channelIdx} senderTimestamp=${payload.senderTimestamp}`);
	});

	const stop = () => {
		unsubscribe();
		ConnectionManager.release(conn);
		process.exit(0);
	};
	process.on('SIGINT', stop);
	process.on('SIGTERM', stop);
}

main().catch((e) => {
	console.error('FATAL:', e?.message ?? e);
	process.exit(1);
});
