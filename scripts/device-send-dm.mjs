/** Authorized: send one direct message to a contact by name. No settings changed. */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const contactName = process.argv[4] ?? 'MyContact';

function hexReplacer(_k, v) {
	if (v && v.type === 'Buffer' && Array.isArray(v.data)) return Buffer.from(v.data).toString('hex');
	if (v instanceof Uint8Array) return Buffer.from(v).toString('hex');
	return v;
}

async function main() {
	const conn = await ConnectionManager.acquire({ host, port });
	const text = `n8n test ${new Date().toISOString().slice(11, 19)}`;
	const contact = await conn.run((c) => c.findContactByName(contactName));
	if (!contact) {
		const contacts = await conn.run((c) => c.getContacts());
		console.log('Contact not found. Names:', JSON.stringify(contacts.map((x) => x.advName)));
	} else {
		console.log(`Sending DM to "${contactName}": "${text}"`);
		const sent = await conn.run((c) => c.sendTextMessage(contact.publicKey, text, 0));
		console.log('OK  SENT:', JSON.stringify(sent, hexReplacer));
	}
	ConnectionManager.release(conn);
}

main().then(
	() => process.exit(0),
	(e) => {
		console.error('FATAL:', e?.message ?? e);
		process.exit(1);
	},
);
