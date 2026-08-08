/**
 * Radio / tuning parameter check against a real device. Loads the built bundle (the
 * extended TCP connection).
 *
 * READ-ONLY by default: reads the radio config out of SELF_INFO, the tuning params, and
 * the permitted client-repeat frequency ranges, and prints them in both wire units and
 * human units so the conversions can be eyeballed against the firmware.
 *
 * With `--write` it additionally writes the SAME values back (an identity round-trip) to
 * exercise CMD_SET_RADIO_PARAMS / CMD_SET_TUNING_PARAMS end-to-end without changing the
 * radio configuration. Note that a radio-params write always rewrites the firmware's
 * `client_repeat` flag, which SELF_INFO does not report — so the round-trip cannot
 * preserve it. Pass `--client-repeat` if the device had it on.
 *
 * Usage: node scripts/device-radio-test.mjs <host> <port> [--write] [--client-repeat]
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ExtendedTCPConnection = require('../dist/nodes/shared/vendor/meshcore-tcp.js').default;

const args = process.argv.slice(2);
const flags = args.filter((a) => a.startsWith('--'));
const positional = args.filter((a) => !a.startsWith('--'));
const host = positional[0] ?? 'meshcore.local';
const port = Number(positional[1] ?? 5000);
const doWrite = flags.includes('--write');
const clientRepeat = flags.includes('--client-repeat');

function waitForConnected(conn, ms) {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error(`connect timeout after ${ms}ms`)), ms);
		conn.once('connected', () => {
			clearTimeout(timer);
			resolve();
		});
	});
}

function toSignedByte(value) {
	return value > 127 ? value - 256 : value;
}

async function run() {
	console.log(`Connecting to ${host}:${port} ...`);
	const conn = new ExtendedTCPConnection(host, port);
	const connected = waitForConnected(conn, 12000);
	await conn.connect();
	await connected;
	console.log('Connected.\n');

	const info = await conn.getSelfInfo(10000);
	console.log('Radio parameters (wire units, as the frame carries them):');
	console.log(`  radioFreq = ${info.radioFreq} kHz`);
	console.log(`  radioBw   = ${info.radioBw} Hz`);
	console.log(`  radioSf   = ${info.radioSf}`);
	console.log(`  radioCr   = ${info.radioCr}`);
	console.log(`  txPower   = ${info.txPower} (raw byte), max ${info.maxTxPower}`);
	console.log('\nAs the node reports them:');
	console.log(`  frequencyMhz    = ${info.radioFreq / 1000}`);
	console.log(`  bandwidthKhz    = ${info.radioBw / 1000}`);
	console.log(`  spreadingFactor = ${info.radioSf}`);
	console.log(`  codingRate      = ${info.radioCr}`);
	console.log(`  txPowerDbm      = ${toSignedByte(info.txPower)}`);
	console.log(`  maxTxPowerDbm   = ${info.maxTxPower}`);

	const tuning = await conn.getTuningParams();
	console.log(`\nTuning parameters: ${JSON.stringify(tuning)}`);

	try {
		const freqs = await conn.getAllowedRepeatFreq();
		console.log(`Allowed client-repeat frequencies: ${JSON.stringify(freqs)}`);
	} catch (e) {
		console.log(`Allowed client-repeat frequencies: ERR ${e.message}`);
	}

	if (!doWrite) {
		console.log('\n(read-only; pass --write for an identity write-back)');
		conn.close();
		return;
	}

	console.log(`\nWriting the same values back (client repeat = ${clientRepeat}) ...`);
	const radioResult = await conn.setRadioParams(
		info.radioFreq,
		info.radioBw,
		info.radioSf,
		info.radioCr,
		clientRepeat,
	);
	console.log(`OK  setRadioParams: ${JSON.stringify(radioResult)}`);

	const tuningResult = await conn.setTuningParams(tuning.rxDelayBase, tuning.airtimeFactor);
	console.log(`OK  setTuningParams: ${JSON.stringify(tuningResult)}`);

	const after = await conn.getSelfInfo(10000);
	const unchanged =
		after.radioFreq === info.radioFreq &&
		after.radioBw === info.radioBw &&
		after.radioSf === info.radioSf &&
		after.radioCr === info.radioCr;
	console.log(unchanged ? '\nVerified: radio configuration is unchanged.' : '\nMISMATCH after write-back!');

	conn.close();
}

run().then(
	() => process.exit(0),
	(e) => {
		console.error('FATAL:', e.message);
		process.exit(1);
	},
);
