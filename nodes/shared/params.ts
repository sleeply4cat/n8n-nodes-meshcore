/** Parameter helpers shared by MeshCore operation handlers. */

/** Parse a hex string (optional 0x prefix / whitespace) into bytes. */
export function hexToBytes(hex: string): Buffer {
	const clean = hex
		.trim()
		.replace(/^0x/i, '')
		.replace(/\s+/g, '');
	if (clean.length === 0 || clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
		throw new Error(`Invalid hex string: "${hex}"`);
	}
	return Buffer.from(clean, 'hex');
}

/** Render bytes (Uint8Array/Buffer/number[]) as a lowercase hex string. */
export function bytesToHex(bytes: Uint8Array | number[]): string {
	return Buffer.from(bytes).toString('hex');
}

/**
 * Map of meshcore.js short-form output keys to the long form used by this package's UI
 * and outputs. Kept narrow: rename only fields where meshcore.js has a clear short-form
 * variant of a name we use elsewhere in long form. Wider firmware shorthands (advLat,
 * outPathLen, etc.) stay as-is — they have no dual form anywhere in the codebase.
 */
const KEY_RENAMES: Record<string, string> = {
	pubKeyPrefix: 'publicKeyPrefix',
};

/**
 * Recursively convert byte fields (Uint8Array/Buffer, or serialized `{type:'Buffer'}`) to
 * lowercase hex strings so node output is consistent with the hex-string inputs the action
 * node accepts (public keys, secrets, paths, …). Plain number arrays are left untouched.
 * Also applies KEY_RENAMES at every object level to unify naming on the output boundary.
 */
export function normalizeBytesDeep(value: unknown): unknown {
	if (value instanceof Uint8Array) {
		return Buffer.from(value).toString('hex');
	}
	if (value === null || typeof value !== 'object') {
		return value;
	}
	const obj = value as Record<string, unknown>;
	if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
		return Buffer.from(obj.data as number[]).toString('hex');
	}
	if (Array.isArray(value)) {
		return value.map(normalizeBytesDeep);
	}
	const out: Record<string, unknown> = {};
	for (const [key, val] of Object.entries(obj)) {
		const outKey = KEY_RENAMES[key] ?? key;
		out[outKey] = normalizeBytesDeep(val);
	}
	return out;
}
