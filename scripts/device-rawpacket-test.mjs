/**
 * Check CMD_SEND_RAW_PACKET (65, firmware v1.16 / protocol ver 13+) against a device.
 *
 * NOTHING IS TRANSMITTED by default. The probe sends a deliberately INVALID packet and
 * reads which error comes back, which is enough to tell the two cases apart:
 *   "unsupported command" (code 1) -> the firmware has no opcode 65 (pre-v1.16)
 *   "illegal argument"    (code 6) -> opcode 65 exists and rejected the packet body
 * Either way the device queues nothing, so the mesh never sees it.
 *
 * With `--transmit` it also sends one minimal, well-formed zero-hop RAW_CUSTOM packet.
 * That DOES go on the air (direct neighbours only, no repeating) — only use it on a mesh
 * where you are allowed to transmit.
 *
 * Usage: node scripts/device-rawpacket-test.mjs <host> <port> [--transmit]
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');

const args = process.argv.slice(2);
const flags = args.filter((a) => a.startsWith('--'));
const positional = args.filter((a) => !a.startsWith('--'));
const host = positional[0] ?? 'meshcore.local';
const port = Number(positional[1] ?? 5000);
const transmit = flags.includes('--transmit');

// header = payload ver (bits 6-7) | payload type (bits 2-5) | route type (bits 0-1).
// The route type matters here: types 0 and 3 are the TRANSPORT variants, and the firmware
// then expects 4 transport-code bytes right after the header. ROUTE_TYPE_DIRECT (2) with a
// zero-hop path is the simplest packet that carries nothing extra.
const PAYLOAD_TYPE_RAW_CUSTOM = 0x0f;
const ROUTE_TYPE_DIRECT = 0x02;
const RAW_CUSTOM_HEADER = (PAYLOAD_TYPE_RAW_CUSTOM << 2) | ROUTE_TYPE_DIRECT;

async function main() {
	const conn = await ConnectionManager.acquire({ host, port });

	const info = await conn.run((c) => c.deviceQuery());
	console.log(
		`Device: ${info.manufacturerName} ${info.firmwareVersion} (protocol v${info.firmwareVer})`,
	);
	if (info.firmwareVer < 13) {
		console.log('NOTE: protocol < 13, so CMD_SEND_RAW_PACKET is not expected to exist here.');
	}

	// path_len 0xC0 -> path mode 3, which tryParsePacket rejects as reserved for future use.
	const invalid = Buffer.from([RAW_CUSTOM_HEADER, 0xc0, 0xde, 0xad, 0xbe, 0xef]);
	try {
		const r = await conn.run((c) => c.sendRawPacket(invalid, 0));
		console.log(`UNEXPECTED: the device accepted a reserved path mode: ${JSON.stringify(r)}`);
	} catch (e) {
		console.log(`Rejected as expected: ${e.message}`);
		console.log(
			/illegal argument/.test(e.message)
				? '  -> opcode 65 IS implemented (it parsed and refused the body)'
				: '  -> opcode 65 is NOT implemented on this firmware',
		);
	}

	if (!transmit) {
		console.log('\n(no packet was transmitted; pass --transmit to send one zero-hop packet)');
		ConnectionManager.release(conn);
		return;
	}

	// header, packed path_len 0 (zero hop, no path bytes), 4-byte payload
	const valid = Buffer.from([RAW_CUSTOM_HEADER, 0x00, 0xde, 0xad, 0xbe, 0xef]);
	console.log(`\nTransmitting ${valid.toString('hex')} (zero-hop RAW_CUSTOM) ...`);
	const r = await conn.run((c) => c.sendRawPacket(valid, 0));
	console.log(`OK sendRawPacket: ${JSON.stringify(r)}`);

	ConnectionManager.release(conn);
}

main().then(
	() => process.exit(0),
	(e) => {
		console.error('FATAL:', e?.message ?? e);
		process.exit(1);
	},
);
