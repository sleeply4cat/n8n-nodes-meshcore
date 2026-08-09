/**
 * Run the packet codec over live radio traffic.
 *
 * Listens to LOG_RX_DATA / RAW_DATA, decodes every frame with the same `decodePacket` the
 * MeshCore Decode node uses, and feeds it the device's own channel secrets plus (with
 * `--private-key`) an identity so direct traffic can be tried too.
 *
 * Nothing is transmitted unless `--probe` is passed, which sends one channel message so a
 * repeater bounces it back and the group decrypt path is exercised on real air data.
 *
 * Usage: node scripts/device-decode-test.mjs <host> <port> [seconds] [--probe]
 *        [--private-key <hex>] [--peer <hex>]
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');
const { decodePacket } = require('../dist/nodes/shared/packetCodec.js');
const { buildGroupTextPacket } = require('../dist/nodes/shared/channelHash.js');

const args = process.argv.slice(2);
const flag = (name) => {
	const i = args.indexOf(name);
	return i === -1 ? null : args[i + 1];
};
const positional = args.filter((a, i) => !a.startsWith('--') && !String(args[i - 1]).startsWith('--'));
const host = positional[0] ?? 'meshcore.local';
const port = Number(positional[1] ?? 5000);
const SECONDS = Number(positional[2] ?? 90);
const probe = args.includes('--probe');
const privateKeyHex = flag('--private-key');
const peerHex = flag('--peer');

async function main() {
	const conn = await ConnectionManager.acquire({ host, port });
	const info = await conn.run((c) => c.deviceQuery());
	const self = await conn.run((c) => c.getSelfInfo(10000));
	const selfPub = Buffer.from(self.publicKey);

	const channels = (await conn.run((c) => c.getChannels()))
		.filter((c) => c.name)
		.map((c) => ({ name: c.name, secret: Buffer.from(c.secret) }));
	console.log(`Channels: ${channels.map((c) => c.name).join(', ')}`);

	const identities = privateKeyHex
		? [{ name: 'device', privateKey: Buffer.from(privateKeyHex, 'hex') }]
		: [];
	const contacts = await conn.run((c) => c.getContacts());
	const peers = contacts.map((c) => ({
		name: c.advName,
		publicKey: Buffer.from(c.publicKey),
	}));
	if (peerHex) peers.push({ name: 'cli', publicKey: Buffer.from(peerHex, 'hex') });
	peers.push({ name: 'self', publicKey: selfPub });
	console.log(
		`Keys: ${channels.length} channel(s), ${identities.length} identity, ${peers.length} peer public key(s)\n`,
	);

	const counts = new Map();
	const bump = (k) => counts.set(k, (counts.get(k) ?? 0) + 1);

	for (const code of [0x88, 0x84]) {
		conn.subscribe(code, async (push) => {
			const raw = Buffer.from(push.raw ?? []);
			if (!raw.length) return;
			let d;
			try {
				d = await decodePacket(raw, { channels, identities, peers, verifyAdverts: true });
			} catch (e) {
				console.log(`  UNPARSEABLE ${raw.length}B: ${e.message}`);
				bump('unparseable');
				return;
			}
			bump(d.payloadTypeName ?? `type ${d.payloadType}`);
			let line = `${(d.payloadTypeName ?? '?').padEnd(11)} ${String(d.routeTypeName).padEnd(16)} hops=${d.hops} hs=${d.pathHashSize} snr=${push.lastSnr}`;
			if (d.decrypted) {
				bump(`${d.payloadTypeName}:decrypted`);
				line += `  DECRYPTED ${JSON.stringify(d.decrypted)}`;
			} else if (d.parsed) {
				line += `  ${JSON.stringify(d.parsed)}`;
			}
			if (d.undecryptedReason) line += `  (${d.undecryptedReason})`;
			console.log(line);
		});
	}

	if (probe) {
		setTimeout(async () => {
			const home = channels[1] ?? channels[0];
			const { frame } = buildGroupTextPacket(
				home.secret,
				'codec-probe',
				`decode check ${Date.now() % 100000}`,
				Math.floor(Date.now() / 1000),
				info.pathHashSize ?? 1,
			);
			await conn.run((c) => c.sendRawPacket(frame, 0));
			console.log(`  (probe sent to #${home.name})\n`);
		}, 4000);
	}

	console.log(`Listening ${SECONDS}s ...\n`);
	await new Promise((r) => setTimeout(r, SECONDS * 1000));
	console.log('\n--- seen ---');
	for (const [k, v] of [...counts].sort((a, b) => b[1] - a[1])) {
		console.log(`  ${String(v).padStart(3)}  ${k}`);
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
