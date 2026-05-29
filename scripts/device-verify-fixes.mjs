/** READ-ONLY: verify node-layer output fixes (hex strings, outPath trunc, channel filter). */
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { ConnectionManager } = require('../dist/nodes/shared/ConnectionManager.js');
const { operations } = require('../dist/nodes/MeshCore/operations.js');

const host = process.argv[2] ?? 'meshcore.local';
const port = Number(process.argv[3] ?? 5000);
const ctx = { getNodeParameter: () => undefined };

const conn = await ConnectionManager.acquire({ host, port });
const contacts = await operations['contact:getAll'](conn, ctx, 0);
console.log('=== contacts (node output) ===');
for (const c of contacts) {
	console.log(`  ${c.advName}: publicKey=${typeof c.publicKey}:${String(c.publicKey).slice(0, 16)}… outPathLen=${c.outPathLen} outPath="${c.outPath}"`);
}
const channels = await operations['channel:getAll'](conn, ctx, 0);
console.log('=== channels (node output, should be only configured) ===');
for (const ch of channels) console.log(`  idx${ch.channelIdx} name="${ch.name}" secret=${ch.secret}`);
ConnectionManager.release(conn);
process.exit(0);
