/**
 * Bundles the meshcore.js TCP transport into the build artifact so the published
 * package carries no runtime dependencies.
 *
 * We deliberately bundle the `tcp_connection.js` SUBMODULE rather than the package
 * index: the index statically imports `serialport` (a native addon), while the TCP
 * transport subtree pulls only pure-JS helpers. Bundling the subpath keeps the
 * package self-contained AND free of native compilation. Node builtins (e.g. `net`,
 * which TCPConnection imports dynamically) are externalized automatically by
 * `platform: 'node'`.
 */
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';

// Our extended TCP connection (subclass adding the §8 gap commands). It imports the
// meshcore.js TCP transport submodule plus pure-JS helpers — never the package index,
// so no native serialport is pulled in.
const entry = fileURLToPath(new URL('./vendor/meshcore-extended.mjs', import.meta.url));

await build({
	entryPoints: [entry],
	outfile: 'dist/nodes/shared/vendor/meshcore-tcp.js',
	bundle: true,
	platform: 'node',
	format: 'cjs',
	target: 'node18',
	legalComments: 'none',
});

console.log('Bundled meshcore TCP transport -> dist/nodes/shared/vendor/meshcore-tcp.js');
