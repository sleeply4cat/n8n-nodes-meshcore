/**
 * Decode the firmware's packed `out_path_len` byte (used in contact records and in
 * the NewAdvert push). Low 6 bits = hop count, high 2 bits = path-hash bytes per
 * hop minus 1. The special value `0xFF` (read as -1 via Int8) means
 * `OUT_PATH_UNKNOWN` — no route stored, firmware will fall back to flood.
 */
export function decodeOutPathLen(
	outPathLen: number,
): { hops: number; hashSize: number; bytes: number } | null {
	if (!Number.isFinite(outPathLen) || outPathLen < 0 || outPathLen === 0xff) {
		return null;
	}
	const hops = outPathLen & 0x3f;
	const hashSize = (outPathLen >> 6) + 1;
	return { hops, hashSize, bytes: hops * hashSize };
}

/**
 * In-place enrichment of any record that carries `outPathLen` + a 64-byte `outPath`
 * buffer (Contact responses, NewAdvert push, getContactByKey, …):
 *  - truncate `outPath` to its REAL byte length (hops * hashSize), dropping the
 *    uninitialized tail the firmware sends after the actual route bytes.
 *  - add `outPathHops` / `outPathHashSize` decoded from the packed byte
 *    (`null` for the OUT_PATH_UNKNOWN sentinel).
 *
 * Returns the same object instance for chaining.
 */
export function enrichContactRecord(record: Record<string, unknown>): Record<string, unknown> {
	const decoded = decodeOutPathLen(Number(record.outPathLen));
	const path = record.outPath;
	if (path instanceof Uint8Array || Array.isArray(path)) {
		const bytes = decoded?.bytes ?? 0;
		record.outPath = Buffer.from(path as Uint8Array).subarray(0, bytes);
	}
	record.outPathHops = decoded ? decoded.hops : null;
	record.outPathHashSize = decoded ? decoded.hashSize : null;
	return record;
}
