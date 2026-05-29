/** Authorized: send a direct message to MyContact and listen for SEND_CONFIRMED (0x82). */
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const CONTACT = process.argv[4] ?? 'MyContact';

const conn = await ConnectionManager.acquire({ host, port });
console.log('Connected. Subscribing to SendConfirmed (0x82)...');

let got = 0;
conn.subscribe(0x82, (p) => {
	got++;
	console.log(`<< SendConfirmed (0x82): ${JSON.stringify(p)}`);
});

const car = await conn.run((c) => c.findContactByName(CONTACT));
if (!car) {
	console.log(`${CONTACT} not found`);
} else {
	const text = `n8n ack test ${new Date().toISOString().slice(11, 19)}`;
	const sent = await conn.run((c) => c.sendTextMessage(car.publicKey, text, 0));
	console.log(`Sent DM: "${text}" -> SENT ${JSON.stringify(sent, (k, v) => (v instanceof Uint8Array ? Buffer.from(v).toString('hex') : v))}`);
	console.log('Waiting 40s for delivery confirmation (ack)...');
	await new Promise((r) => setTimeout(r, 40000));
}

console.log(`\nReceived ${got} SendConfirmed push(es).`);
ConnectionManager.release(conn);
process.exit(0);
