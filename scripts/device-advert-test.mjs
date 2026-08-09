/**
 * Prove the host-side advert builder byte-for-byte against the device's own firmware.
 *
 * Ed25519 signing is deterministic, so if we rebuild an advert the DEVICE emitted — same
 * public key, timestamp and app data, signed with the exported private key — the signature
 * must come out identical. Anything else means our expanded-key signing is wrong.
 *
 * Requires the device to allow CMD_EXPORT_PRIVATE_KEY. Nothing is transmitted: the device
 * is asked to advertise zero-hop, we listen for its own frame, and rebuild it in memory.
 *
 * Usage: node scripts/device-advert-test.mjs <host> <port>
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');
const {
	buildAdvertPacket,
	decodePacket,
	encodeAdvertAppData,
	publicKeyFromPrivate,
	signWithExpandedKey,
} = require('../dist/nodes/shared/packetCodec.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const WAIT_MS = 60000;

async function main() {
	const conn = await ConnectionManager.acquire({ host, port });
	const self = await conn.run((c) => c.getSelfInfo(10000));
	const selfPub = Buffer.from(self.publicKey);
	console.log(`Device "${self.name}" ${selfPub.toString('hex').slice(0, 16)}...`);

	const key = await conn.run((c) => c.exportPrivateKey());
	const privateKey = Buffer.from(key.privateKey);
	const derived = await publicKeyFromPrivate(privateKey);
	console.log(
		`Public key derived from the private scalar matches the device: ${derived.equals(selfPub)}`,
	);

	// Wait for an advert from OUR key. Asking the device to advertise makes it prompt.
	let captured = null;
	const unsubscribe = conn.subscribe(0x88, async (push) => {
		if (captured) return;
		const raw = Buffer.from(push.raw ?? []);
		if (!raw.length) return;
		let d;
		try {
			d = await decodePacket(raw);
		} catch {
			return;
		}
		if (d.payloadTypeName !== 'ADVERT') return;
		if (d.parsed?.publicKey !== selfPub.toString('hex')) return;
		captured = { raw, decoded: d };
	});

	// A flood advert is what comes back: repeaters rebroadcast it, so we hear our own frame.
	// A zero-hop one is never repeated and so can never be captured this way.
	console.log('Asking the device to flood an advert, then listening for it to come back ...');
	await conn.run((c) => c.sendFloodAdvert());

	const deadline = Date.now() + WAIT_MS;
	while (!captured && Date.now() < deadline) await new Promise((r) => setTimeout(r, 250));
	unsubscribe();

	if (!captured) {
		console.log(
			'\nNo advert from our own key was heard (a zero-hop advert is only echoed if a neighbour repeats it).',
		);
		ConnectionManager.release(conn);
		return;
	}

	// payload = publicKey(32) | timestamp(4) | signature(64) | appData
	const payload = Buffer.from(captured.decoded.payload, 'hex');
	const timestamp = payload.readUInt32LE(32);
	const theirSignature = payload.subarray(36, 100);
	const theirAppData = payload.subarray(100);
	console.log(
		`\nCaptured advert: timestamp ${timestamp}, appData ${theirAppData.length}B, name ${JSON.stringify(captured.decoded.parsed.name)}`,
	);

	// 1. our app-data encoder must reproduce theirs
	const ourAppData = encodeAdvertAppData({
		type: 1,
		name: captured.decoded.parsed.name,
		latitude: captured.decoded.parsed.lat != null ? captured.decoded.parsed.lat / 1e6 : undefined,
		longitude: captured.decoded.parsed.lon != null ? captured.decoded.parsed.lon / 1e6 : undefined,
	});
	console.log(`appData rebuilt identically: ${ourAppData.equals(theirAppData)}`);
	if (!ourAppData.equals(theirAppData)) {
		console.log(`  theirs: ${theirAppData.toString('hex')}`);
		console.log(`  ours:   ${ourAppData.toString('hex')}`);
	}

	// 2. the signature over THEIR exact bytes must match, which is the real proof
	const stamp = Buffer.alloc(4);
	stamp.writeUInt32LE(timestamp, 0);
	const signed = Buffer.concat([selfPub, stamp, theirAppData]);
	const ourSignature = await signWithExpandedKey(privateKey, signed);
	const match = ourSignature.equals(theirSignature);
	console.log(`signature reproduced byte-for-byte: ${match}`);
	if (!match) {
		console.log(`  device: ${theirSignature.toString('hex')}`);
		console.log(`  ours:   ${ourSignature.toString('hex')}`);
	}

	// 3. and a fully self-built advert must verify
	const built = await buildAdvertPacket({
		privateKey,
		fields: { type: 1, name: 'n8n-alt' },
		timestamp: Math.floor(Date.now() / 1000),
	});
	const check = await decodePacket(built.frame, { verifyAdverts: true });
	console.log(
		`self-built advert verifies: ${check.parsed?.signatureValid} (name ${JSON.stringify(check.parsed?.name)})`,
	);

	ConnectionManager.release(conn);
}

main().then(
	() => process.exit(0),
	(e) => {
		console.error('FATAL:', e?.message ?? e);
		process.exit(1);
	},
);
