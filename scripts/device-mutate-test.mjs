/**
 * Non-destructive MUTATION test (authorized): exercises safe, reversible writes and
 * restores every change. Touches only advert name/lat-long, the device clock, an EMPTY
 * channel slot (idx 2 — never Public/configured), a throwaway contact, and auto-add config.
 * Avoids anything that could drop WiFi/mesh (radio params, pin, reboot, flood scope).
 */
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const TEST_CHANNEL_IDX = 2; // confirmed empty earlier (not Public/configured)

const show = (o) => JSON.stringify(o);
const run = (conn, fn) => conn.run(fn);

async function main() {
	const conn = await ConnectionManager.acquire({ host, port });
	console.log('Connected.\n');
	const restores = [];

	// 1) Advert name round-trip
	try {
		const before = await run(conn, (c) => c.getSelfInfo(10000));
		const orig = before.name;
		console.log(`advertName: original="${orig}"`);
		await run(conn, (c) => c.setAdvertName(`${orig}-n8n`));
		const mid = await run(conn, (c) => c.getSelfInfo(10000));
		console.log(`  changed -> "${mid.name}" ${mid.name === `${orig}-n8n` ? 'OK' : 'UNEXPECTED'}`);
		await run(conn, (c) => c.setAdvertName(orig));
		const after = await run(conn, (c) => c.getSelfInfo(10000));
		console.log(`  restored -> "${after.name}" ${after.name === orig ? 'OK' : 'FAILED RESTORE'}`);
	} catch (e) {
		console.log('ERR advertName:', e?.message ?? e);
	}

	// 2) Advert lat/long round-trip (restore to original)
	try {
		const before = await run(conn, (c) => c.getSelfInfo(10000));
		const oLat = before.advLat, oLon = before.advLon;
		console.log(`advertLatLong: original=${oLat},${oLon}`);
		await run(conn, (c) => c.setAdvertLatLong(1, 2));
		const mid = await run(conn, (c) => c.getSelfInfo(10000));
		console.log(`  changed -> ${mid.advLat},${mid.advLon}`);
		await run(conn, (c) => c.setAdvertLatLong(oLat, oLon));
		const after = await run(conn, (c) => c.getSelfInfo(10000));
		console.log(`  restored -> ${after.advLat},${after.advLon} ${after.advLat === oLat && after.advLon === oLon ? 'OK' : 'CHECK'}`);
	} catch (e) {
		console.log('ERR advertLatLong:', e?.message ?? e);
	}

	// 3) Sync device time (benign — sets RTC to host time)
	try {
		await run(conn, (c) => c.syncDeviceTime());
		const t = await run(conn, (c) => c.getDeviceTime());
		console.log(`syncDeviceTime: OK -> ${show(t)}`);
	} catch (e) {
		console.log('ERR syncDeviceTime:', e?.message ?? e);
	}

	// 4) Channel round-trip on an empty slot, then delete
	try {
		const secret = randomBytes(16);
		console.log(`channel[${TEST_CHANNEL_IDX}]: creating "n8n-test"`);
		await run(conn, (c) => c.setChannel(TEST_CHANNEL_IDX, 'n8n-test', secret));
		const got = await run(conn, (c) => c.getChannel(TEST_CHANNEL_IDX));
		console.log(`  read back -> name="${got.name}" ${got.name === 'n8n-test' ? 'OK' : 'UNEXPECTED'}`);
		await run(conn, (c) => c.deleteChannel(TEST_CHANNEL_IDX));
		const cleared = await run(conn, (c) => c.getChannel(TEST_CHANNEL_IDX));
		console.log(`  deleted -> name="${cleared.name}" ${!cleared.name ? 'OK (empty)' : 'FAILED CLEANUP'}`);
	} catch (e) {
		console.log('ERR channel:', e?.message ?? e);
	}

	// 5) Throwaway contact add + remove
	try {
		const pub = randomBytes(32);
		const before = (await run(conn, (c) => c.getContacts())).length;
		console.log(`contact: before=${before}, adding throwaway`);
		await run(conn, (c) => c.addOrUpdateContact(pub, 1, 0, 0, Buffer.alloc(0), 'n8n-temp', Math.floor(Date.now() / 1000), 0, 0));
		const mid = (await run(conn, (c) => c.getContacts())).length;
		console.log(`  after add=${mid} ${mid === before + 1 ? 'OK' : 'UNEXPECTED'}`);
		await run(conn, (c) => c.removeContact(pub));
		const after = (await run(conn, (c) => c.getContacts())).length;
		console.log(`  after remove=${after} ${after === before ? 'OK' : 'FAILED CLEANUP'}`);
	} catch (e) {
		console.log('ERR contact:', e?.message ?? e);
	}

	// 6) Auto-add config round-trip
	try {
		const before = await run(conn, (c) => c.getAutoAddConfig());
		console.log(`autoAddConfig: original=${show(before)}`);
		await run(conn, (c) => c.setAutoAddConfig(before.config, 1));
		const mid = await run(conn, (c) => c.getAutoAddConfig());
		console.log(`  changed -> ${show(mid)}`);
		await run(conn, (c) => c.setAutoAddConfig(before.config, before.maxHops));
		const after = await run(conn, (c) => c.getAutoAddConfig());
		console.log(`  restored -> ${show(after)} ${after.config === before.config && after.maxHops === before.maxHops ? 'OK' : 'FAILED RESTORE'}`);
	} catch (e) {
		console.log('ERR autoAddConfig:', e?.message ?? e);
	}

	ConnectionManager.release(conn);
	console.log('\nDone.');
}

main().then(
	() => process.exit(0),
	(e) => {
		console.error('FATAL:', e?.message ?? e);
		process.exit(1);
	},
);
