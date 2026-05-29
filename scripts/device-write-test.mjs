/**
 * Controlled write + receive test (authorized): sends one DM to a contact and one
 * message to a channel, then listens for inbound messages for 60s. Goes through the real
 * ConnectionManager (serialized queue + push fan-out), exercising the same path the nodes
 * use. Does NOT change device settings.
 *
 * Usage: node scripts/device-write-test.mjs <host> <port> <contactName> <channelIdx>
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const CONTACT = process.argv[4] ?? 'MyContact';
const CHANNEL_IDX = Number(process.argv[5] ?? 1);
const LISTEN_MS = 60000;
const MSG_WAITING = 0x83;

function hexReplacer(_k, v) {
	if (v && v.type === 'Buffer' && Array.isArray(v.data)) return Buffer.from(v.data).toString('hex');
	if (v instanceof Uint8Array) return Buffer.from(v).toString('hex');
	return v;
}
const show = (o) => JSON.stringify(o, hexReplacer);
const stamp = () => new Date().toISOString().slice(11, 19);

async function main() {
	console.log(`Connecting to ${host}:${port} via ConnectionManager ...`);
	const conn = await ConnectionManager.acquire({ host, port });
	console.log('Connected.\n');

	const text = `n8n test ${stamp()}`;

	// 1) Direct message to the contact
	try {
		const car = await conn.run((c) => c.findContactByName(CONTACT));
		if (!car) {
			const contacts = await conn.run((c) => c.getContacts());
			console.log('Contact not found. Contacts:', show(contacts.map((x) => x.advName)));
		} else {
			console.log(`Sending DM to ${CONTACT} (${show(car.publicKey).slice(0, 12)}…): "${text}"`);
			const sent = await conn.run((c) => c.sendTextMessage(car.publicKey, text, 0));
			console.log('OK  sendTextMessage -> SENT:', show(sent));
		}
	} catch (e) {
		console.log('ERR sendTextMessage:', e?.message ?? e);
	}

	// 2) Channel message
	try {
		console.log(`Sending channel msg (idx ${CHANNEL_IDX}): "${text}"`);
		await conn.run((c) => c.sendChannelTextMessage(CHANNEL_IDX, text));
		console.log('OK  sendChannelTextMessage -> OK');
	} catch (e) {
		console.log('ERR sendChannelTextMessage:', e?.message ?? e);
	}

	// 3) Listen for inbound messages (drain on MSG_WAITING)
	console.log(`\nListening ${LISTEN_MS / 1000}s for inbound messages — reply from your contact now...\n`);
	let received = 0;
	const drain = async () => {
		try {
			const messages = await conn.run((c) => c.getWaitingMessages());
			for (const m of messages) {
				received++;
				console.log(`<< [${stamp()}] inbound:`, show(m));
			}
		} catch (e) {
			console.log('ERR drain:', e?.message ?? e);
		}
	};
	const unsubscribe = conn.subscribe(MSG_WAITING, () => void drain());

	await new Promise((resolve) => setTimeout(resolve, LISTEN_MS));

	unsubscribe();
	ConnectionManager.release(conn);
	console.log(`\nDone. Received ${received} inbound message(s). Connection released.`);
}

main().then(
	() => process.exit(0),
	(e) => {
		console.error('FATAL:', e?.message ?? e);
		process.exit(1);
	},
);
