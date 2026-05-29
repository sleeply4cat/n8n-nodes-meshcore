/**
 * Non-destructive diagnostics pass (authorized): local crypto (sign), contact export,
 * a zero-hop advert, and requests to contact "MyContact" (status/telemetry/neighbours/
 * path-discovery) to validate the remaining push parsers. Changes NO settings.
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const CONTACT = process.argv[4] ?? 'MyContact';

function hexReplacer(_k, v) {
	if (v && v.type === 'Buffer' && Array.isArray(v.data)) return Buffer.from(v.data).toString('hex');
	if (v instanceof Uint8Array) return Buffer.from(v).toString('hex');
	return v;
}
const show = (o) => JSON.stringify(o, hexReplacer);
const stamp = () => new Date().toISOString().slice(11, 19);
const withTimeout = (p, ms, label) =>
	Promise.race([
		Promise.resolve(p),
		new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout ${ms}ms`)), ms)),
	]).catch((e) => {
		throw new Error(`${label}: ${e.message}`);
	});

async function step(conn, label, fn, ms = 20000) {
	try {
		const r = await withTimeout(conn.run(fn), ms, label);
		console.log(`OK  ${label}: ${show(r)}`);
		return r;
	} catch (e) {
		console.log(`ERR ${label}: ${e?.message ?? e}`);
		return null;
	}
}

async function main() {
	const conn = await ConnectionManager.acquire({ host, port });
	console.log('Connected.\n');

	// Passively observe async pushes for the whole run.
	const pushes = {
		0x80: 'Advert', 0x82: 'SendConfirmed', 0x87: 'StatusResponse', 0x89: 'TraceData',
		0x8a: 'NewAdvert', 0x8b: 'TelemetryResponse', 0x8c: 'BinaryResponse', 0x8d: 'PathDiscoveryResponse',
	};
	const unsubs = Object.entries(pushes).map(([code, name]) =>
		conn.subscribe(Number(code), (p) => console.log(`<< push ${name}: ${show(p)}`)),
	);

	// A) local, no radio
	await step(conn, 'sign', (c) => c.sign(Buffer.from('n8n test sign')));
	await step(conn, 'exportContact(self)', (c) => c.exportContact(null));

	// find Car
	const car = await conn.run((c) => c.findContactByName(CONTACT));
	if (!car) {
		console.log(`ERR contact "${CONTACT}" not found`);
	} else {
		console.log(`Car: type=${car.type} key=${show(car.publicKey).slice(0, 12)}…\n`);
		await step(conn, 'exportContact(Car)', (c) => c.exportContact(car.publicKey));

		// B) requests to Car (Car must be in range / responding)
		await step(conn, 'getStatus(Car)', (c) => c.getStatus(car.publicKey));
		await step(conn, 'getTelemetry(Car)', (c) => c.getTelemetry(car.publicKey));
		if (car.type === 2) {
			await step(conn, 'getNeighbours(Car)', (c) => c.getNeighbours(car.publicKey, 10, 0, 0, 8));
		}
		await step(conn, 'sendPathDiscoveryReq(Car)', (c) => c.sendPathDiscoveryReq(car.publicKey));
	}

	// C) zero-hop advert (broadcast, non-destructive)
	await step(conn, 'sendZeroHopAdvert', (c) => c.sendZeroHopAdvert());

	// linger to catch async pushes (path-discovery 0x8D, organic adverts, acks)
	console.log('\nListening 30s for async pushes...\n');
	await new Promise((r) => setTimeout(r, 30000));

	for (const u of unsubs) u();
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
