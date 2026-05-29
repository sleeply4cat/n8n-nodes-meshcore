/** Authorized: send one channel message. No settings changed. */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const channelIdx = Number(process.argv[4] ?? 1);

async function main() {
	const conn = await ConnectionManager.acquire({ host, port });
	const channel = await conn.run((c) => c.getChannel(channelIdx));
	console.log(`Channel ${channelIdx}: name="${channel?.name}" secret=${channel?.secret ? Buffer.from(channel.secret).toString('hex') : '?'}`);

	const text = `n8n test ${new Date().toISOString().slice(11, 19)}`;
	console.log(`Sending to channel ${channelIdx}: "${text}"`);
	await conn.run((c) => c.sendChannelTextMessage(channelIdx, text));
	console.log('OK  sendChannelTextMessage -> OK');

	ConnectionManager.release(conn);
}

main().then(
	() => process.exit(0),
	(e) => {
		console.error('FATAL:', e?.message ?? e);
		process.exit(1);
	},
);
