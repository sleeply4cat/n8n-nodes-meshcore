/**
 * Copy the nodes' codex files (`*.node.json`) into `dist/`.
 *
 * `n8n-node build` compiles TypeScript and copies icons, but not these; without them n8n
 * has no categories for the nodes and they scatter across the panel instead of grouping
 * under MeshCore. tsc will not do it either — `resolveJsonModule` is about importing JSON,
 * not emitting it.
 */
import { cp, readdir } from 'node:fs/promises';
import { join } from 'node:path';

const SOURCE = 'nodes';
const DEST = 'dist/nodes';

const entries = await readdir(SOURCE, { withFileTypes: true, recursive: true });
let copied = 0;

for (const entry of entries) {
	if (!entry.isFile() || !entry.name.endsWith('.node.json')) {
		continue;
	}
	const from = join(entry.parentPath ?? entry.path, entry.name);
	const to = join(DEST, from.slice(SOURCE.length + 1));
	await cp(from, to);
	copied++;
}

console.log(`Copied ${copied} codex file(s) -> ${DEST}`);
