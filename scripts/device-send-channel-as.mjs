/**
 * Send a channel message under an arbitrary sender name, by assembling the GRP_TXT packet
 * on the host and handing it to CMD_SEND_RAW_PACKET (firmware v1.16+).
 *
 * THIS TRANSMITS on the given channel — everyone on it sees the message.
 *
 * Usage: node scripts/device-send-channel-as.mjs <host> <port> <channelName> <senderName> <text>
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');
const {
	buildGroupTextPacket,
	buffersEqual,
	computePacketHash,
	parseRxFrame,
} = require('../dist/nodes/shared/channelHash.js');

const ECHO_WAIT_MS = 20000;

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const channelName = process.argv[4];
const senderName = process.argv[5];
const text = process.argv.slice(6).join(' ');

async function main() {
	if (!channelName || !senderName || !text) {
		console.error('usage: <host> <port> <channelName> <senderName> <text...>');
		process.exit(2);
	}
	const conn = await ConnectionManager.acquire({ host, port });

	const info = await conn.run((c) => c.deviceQuery());
	console.log(`Device: ${info.manufacturerName} ${info.firmwareVersion} (protocol v${info.firmwareVer})`);
	if (info.firmwareVer < 13) {
		console.error('This needs CMD_SEND_RAW_PACKET, i.e. protocol ver 13+ (firmware v1.16).');
		process.exit(1);
	}

	const channel = await conn.run((c) => c.findChannelByName(channelName));
	if (!channel) {
		console.error(`channel ${JSON.stringify(channelName)} not found`);
		process.exit(1);
	}
	const secret = Buffer.from(channel.secret);
	console.log(`Channel "${channel.name}" idx ${channel.channelIdx}, ${secret.length}-byte secret`);

	const hashSize = info.pathHashSize ?? 1;
	const { frame, hash, truncated } = buildGroupTextPacket(
		secret,
		senderName,
		text,
		Math.floor(Date.now() / 1000),
		hashSize,
	);
	console.log(`Path hash size ${hashSize} byte(s) (mesh path_hash_mode ${info.pathHashMode})`);
	console.log(`Frame ${frame.length}B: ${frame.toString('hex')}`);
	console.log(`Packet hash (mesh dedup key): ${hash.toString('hex')}${truncated ? ' [text truncated]' : ''}`);

	// Watch the raw radio log for a neighbour repeating this exact packet. Repeaters only
	// forward well-formed packets, so hearing our own hash come back is on-air proof that
	// the frame was accepted by the mesh — not just by our own companion.
	let echo = null;
	const unsubscribe = conn.subscribe(0x88, (push) => {
		if (echo) return;
		const parsed = parseRxFrame(push.raw ?? []);
		if (!parsed) return;
		const seen = computePacketHash(parsed.payloadType, parsed.payload);
		if (buffersEqual(seen, hash)) {
			echo = { snr: push.lastSnr, rssi: push.lastRssi, hops: parsed.hops, path: parsed.path.toString('hex') };
		}
	});

	const result = await conn.run((c) => c.sendRawPacket(frame, 0));
	console.log(`\nsendRawPacket: ${JSON.stringify(result)}`);
	console.log(`Sent as "${senderName}: ${text}". Listening ${ECHO_WAIT_MS / 1000}s for a repeat ...`);

	const deadline = Date.now() + ECHO_WAIT_MS;
	while (!echo && Date.now() < deadline) {
		await new Promise((r) => setTimeout(r, 250));
	}
	unsubscribe();

	if (echo) {
		console.log(
			`Heard our own packet repeated: snr ${echo.snr}, rssi ${echo.rssi}, ` +
				`${echo.hops} hop(s) path ${echo.path || '(none)'} — the mesh accepted it.`,
		);
	} else {
		console.log('No repeat heard (no repeater in range, or it deduped). Check the channel on another node.');
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
