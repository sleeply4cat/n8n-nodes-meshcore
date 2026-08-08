/**
 * Extended MeshCore TCP connection.
 *
 * meshcore.js v1.13.0 does not expose every Companion-protocol command the firmware
 * supports. This subclass adds the missing commands (CLAUDE.md §8), grounded in the
 * firmware command/response layouts in `examples/companion_radio/MyMesh.cpp` — NOT the
 * docs. Request encoding is verified against the firmware's cmd_frame parsing; response
 * parsing against its out_frame writers.
 *
 * NOTE: these were verified against firmware source, not run against a live device.
 *
 * This module is bundled (esbuild) into dist; it imports only pure-JS meshcore.js
 * helpers, so it pulls in no native `serialport`.
 */
import TCPConnection from '@liamcottle/meshcore.js/src/connection/tcp_connection.js';
import BufferWriter from '@liamcottle/meshcore.js/src/buffer_writer.js';
import BufferReader from '@liamcottle/meshcore.js/src/buffer_reader.js';

const PUB_KEY_SIZE = 32;

// How long to wait for the device to accept a send command before it has told us its
// own airtime estimate. Local USB/TCP round-trip, so this is generous.
const SEND_ACK_TIMEOUT_MS = 10000;

// Upper bound when walking channel slots. The firmware reports its real capacity as
// `maxChannels` in DEVICE_INFO; this is only a stop so a bad stream cannot loop forever.
const MAX_CHANNEL_SLOTS = 64;

// Command opcodes missing from meshcore.js (firmware MyMesh.cpp).
const CMD = {
	SET_RADIO_PARAMS: 11,
	SET_TUNING_PARAMS: 21,
	SEND_RAW_DATA: 25,
	GET_CHANNEL: 31,
	HAS_CONNECTION: 28,
	LOGOUT: 29,
	GET_CONTACT_BY_KEY: 30,
	SET_DEVICE_PIN: 37,
	GET_CUSTOM_VARS: 40,
	SET_CUSTOM_VAR: 41,
	GET_ADVERT_PATH: 42,
	GET_TUNING_PARAMS: 43,
	FACTORY_RESET: 51,
	SEND_TRACE_PATH: 36,
	SEND_PATH_DISCOVERY_REQ: 52,
	SEND_CONTROL_DATA: 55,
	SEND_ANON_REQ: 57,
	SET_AUTOADD_CONFIG: 58,
	GET_AUTOADD_CONFIG: 59,
	GET_ALLOWED_REPEAT_FREQ: 60,
	SET_PATH_HASH_MODE: 61,
	SET_DEFAULT_FLOOD_SCOPE: 63,
	GET_DEFAULT_FLOOD_SCOPE: 64,
	SEND_RAW_PACKET: 65,
};

// Response codes (device -> host) not modelled by meshcore.js constants.
const RESP = {
	OK: 0,
	ERR: 1,
	CONTACT: 3,
	SENT: 6,
	DEVICE_INFO: 13,
	CHANNEL_INFO: 18,
	CUSTOM_VARS: 21,
	ADVERT_PATH: 22,
	TUNING_PARAMS: 23,
	AUTOADD_CONFIG: 25,
	ALLOWED_REPEAT_FREQ: 26,
	DEFAULT_FLOOD_SCOPE: 28,
};

// Async push codes (device -> host) not modelled by meshcore.js constants.
const PUSH = {
	TRACE_DATA: 0x89,
	PATH_DISCOVERY_RESPONSE: 0x8d,
	CONTROL_DATA: 0x8e,
	CONTACT_DELETED: 0x8f,
	CONTACTS_FULL: 0x90,
};

// ERR_CODE_* from the firmware, so a rejection can say *why* the device refused.
const ERR_NAMES = {
	1: 'unsupported command',
	2: 'not found',
	3: 'table full',
	4: 'bad state',
	5: 'file I/O error',
	6: 'illegal argument',
};

function describeErr(payload) {
	const code = payload?.errCode;
	if (code == null) {
		return 'device returned an error (no error code)';
	}
	return `device returned an error: ${ERR_NAMES[code] ?? 'unknown'} (code ${code})`;
}

function toHex(bytes) {
	return Buffer.from(bytes).toString('hex');
}

function toInt8(byte) {
	return byte > 127 ? byte - 256 : byte;
}

/** Read a fixed-length, null-terminated ASCII field. */
function readFixedString(reader, length) {
	const bytes = reader.readBytes(length);
	const nul = bytes.indexOf(0);
	return Buffer.from(nul === -1 ? bytes : bytes.slice(0, nul)).toString('utf8');
}

/**
 * Decode the firmware's packed `path_len` byte (low 6 bits = hop count, high 2 bits
 * = bytes per hop minus 1). Returns the number of REAL path bytes that the firmware
 * actually wrote via `mesh::Packet::writePath` (= hops * hashSize), plus the decoded
 * hops and hashSize for downstream consumers.
 */
function decodePackedPathLen(byte) {
	const hops = byte & 0x3f;
	const hashSize = (byte >> 6) + 1;
	return { hops, hashSize, bytes: hops * hashSize };
}

/** Read a packed-path-len byte + its REAL byte payload, returning {pathLen, hops, hashSize, path}. */
function readPackedPath(reader) {
	const pathLen = reader.readByte();
	const { hops, hashSize, bytes } = decodePackedPathLen(pathLen);
	const path = bytes > 0 ? toHex(reader.readBytes(bytes)) : '';
	return { pathLen, hops, hashSize, path };
}

class ExtendedTCPConnection extends TCPConnection {
	/**
	 * Parse response/push codes the base class drops, then delegate everything else.
	 */
	onFrameReceived(frame) {
		const code = frame[0];
		const parser = this._extendedParsers[code];
		if (parser) {
			this.emit('rx', frame);
			const reader = new BufferReader(frame);
			reader.readByte(); // consume the code byte
			parser.call(this, reader);
			return;
		}
		super.onFrameReceived(frame);
	}

	get _extendedParsers() {
		return {
			[RESP.CUSTOM_VARS]: (r) => {
				const raw = Buffer.from(r.readRemainingBytes()).toString('utf8');
				const vars = {};
				for (const pair of raw.split(',')) {
					if (!pair) continue;
					const idx = pair.indexOf(':');
					if (idx === -1) continue;
					vars[pair.slice(0, idx)] = pair.slice(idx + 1);
				}
				this.emit(RESP.CUSTOM_VARS, { raw, vars });
			},
			[RESP.ADVERT_PATH]: (r) => {
				const recvTimestamp = r.readUInt32LE();
				// path_len is PACKED (low 6 bits = hop count, high 2 bits = bytes per hop - 1).
				// Firmware writes `hops * hashSize` real bytes via Packet::writePath, not the
				// raw byte; reading `pathLen` bytes as the previous code did over-reads (and
				// breaks trailing-field parsing) whenever hashSize > 1.
				const { pathLen, hops, hashSize, path } = readPackedPath(r);
				this.emit(RESP.ADVERT_PATH, { recvTimestamp, pathLen, hops, hashSize, path });
			},
			// meshcore.js parses this frame against a much older firmware: it takes
			// `manufacturerModel` as "remainder of frame", which swallows the manufacturer
			// name, the firmware version string, and the two trailing flags into one blob.
			// `pathHashMode` in particular is the only way to learn the mesh's path-hash
			// size (hash bytes = mode + 1), which trace paths have to match.
			[RESP.DEVICE_INFO]: (r) => {
				const firmwareVer = r.readByte();
				const maxContacts = r.readByte() * 2; // firmware sends MAX_CONTACTS / 2
				const maxChannels = r.readByte();
				const blePin = r.readUInt32LE();
				const firmwareBuildDate = readFixedString(r, 12);
				const manufacturerName = readFixedString(r, 40);
				const firmwareVersion = readFixedString(r, 20);
				// v9+ / v10+ tails: absent on older firmware
				const clientRepeat = r.getRemainingBytesCount() > 0 ? r.readByte() === 1 : null;
				const pathHashMode = r.getRemainingBytesCount() > 0 ? r.readByte() : null;
				this.emit(RESP.DEVICE_INFO, {
					firmwareVer,
					maxContacts,
					maxChannels,
					blePin,
					firmwareBuildDate,
					manufacturerName,
					firmwareVersion,
					clientRepeat,
					pathHashMode,
					pathHashSize: pathHashMode == null ? null : pathHashMode + 1,
				});
			},
			[RESP.TUNING_PARAMS]: (r) => {
				const rxDelayBase = r.readUInt32LE() / 1000;
				const airtimeFactor = r.readUInt32LE() / 1000;
				this.emit(RESP.TUNING_PARAMS, { rxDelayBase, airtimeFactor });
			},
			[RESP.AUTOADD_CONFIG]: (r) => {
				const config = r.readByte();
				const maxHops = r.getRemainingBytesCount() > 0 ? r.readByte() : 0;
				this.emit(RESP.AUTOADD_CONFIG, { config, maxHops });
			},
			[RESP.ALLOWED_REPEAT_FREQ]: (r) => {
				const ranges = [];
				while (r.getRemainingBytesCount() >= 8) {
					ranges.push({ lowerFreq: r.readUInt32LE(), upperFreq: r.readUInt32LE() });
				}
				this.emit(RESP.ALLOWED_REPEAT_FREQ, { ranges });
			},
			[RESP.DEFAULT_FLOOD_SCOPE]: (r) => {
				if (r.getRemainingBytesCount() >= 31 + 16) {
					const name = readFixedString(r, 31);
					const key = r.readBytes(16);
					this.emit(RESP.DEFAULT_FLOOD_SCOPE, { name, key: toHex(key) });
				} else {
					this.emit(RESP.DEFAULT_FLOOD_SCOPE, { name: null, key: null });
				}
			},
			// meshcore.js DOES parse 0x89, but reads `pathLen` SNR bytes. The firmware
			// (onTraceRecv) writes `path_len >> path_sz` of them, where path_sz = flags & 3
			// is the v1.11+ multi-byte path-hash size — so with any hash size > 1 byte the
			// base parser over-reads the SNRs and lands `lastSnr` on garbage.
			[PUSH.TRACE_DATA]: (r) => {
				const reserved = r.readByte();
				const pathLen = r.readByte(); // REAL byte count of the path hashes
				const flags = r.readByte();
				const hashSize = 1 << (flags & 0x03);
				const hops = pathLen >> (flags & 0x03);
				const tag = r.readUInt32LE();
				const authCode = r.readUInt32LE();
				const pathHashes = toHex(r.readBytes(pathLen));
				const pathSnrs = [];
				for (let k = 0; k < hops; k++) {
					pathSnrs.push(toInt8(r.readByte()) / 4);
				}
				const lastSnr = r.getRemainingBytesCount() > 0 ? toInt8(r.readByte()) / 4 : null;
				this.emit(PUSH.TRACE_DATA, {
					reserved,
					pathLen,
					flags,
					hops,
					hashSize,
					tag,
					authCode,
					pathHashes,
					pathSnrs,
					lastSnr,
				});
			},
			// async pushes the base class also drops
			[PUSH.PATH_DISCOVERY_RESPONSE]: (r) => {
				r.readByte(); // reserved
				const pubKeyPrefix = toHex(r.readBytes(6));
				// both out_path_len and in_path_len are PACKED (see readPackedPath note).
				const out = readPackedPath(r);
				const inp = readPackedPath(r);
				this.emit(PUSH.PATH_DISCOVERY_RESPONSE, {
					pubKeyPrefix,
					outPath: out.path,
					outPathLen: out.pathLen,
					outPathHops: out.hops,
					outPathHashSize: out.hashSize,
					inPath: inp.path,
					inPathLen: inp.pathLen,
					inPathHops: inp.hops,
					inPathHashSize: inp.hashSize,
				});
			},
			[PUSH.CONTROL_DATA]: (r) => {
				const snr = toInt8(r.readByte()) / 4;
				const rssi = toInt8(r.readByte());
				// path_len is packed (hops + hashSize), but only `hops` is meaningful here:
				// the firmware does not include the path bytes in this frame, only the
				// payload, so the hash size would be a number without a path to apply to.
				const pathLen = r.readByte();
				const { hops } = decodePackedPathLen(pathLen);
				const payload = toHex(r.readRemainingBytes());
				this.emit(PUSH.CONTROL_DATA, { snr, rssi, pathLen, hops, payload });
			},
			[PUSH.CONTACT_DELETED]: (r) => {
				this.emit(PUSH.CONTACT_DELETED, { publicKey: toHex(r.readBytes(PUB_KEY_SIZE)) });
			},
			[PUSH.CONTACTS_FULL]: () => {
				this.emit(PUSH.CONTACTS_FULL, {});
			},
		};
	}

	/**
	 * Send a frame, then resolve when `resolveCode` arrives (mapped by `map`), reject on
	 * ERR (unless `errResolvesNull`), or reject on timeout. Uses on()/off() with the real
	 * listener reference (meshcore's once() wrapper makes off() a no-op).
	 */
	_command(bytes, { resolveCode, map, match, errResolvesNull = false, timeoutMs = 10000 } = {}) {
		return new Promise((resolve, reject) => {
			let done = false;
			const finish = (fn, value) => {
				if (done) return;
				done = true;
				this.off(resolveCode, onResolve);
				this.off(RESP.ERR, onErr);
				clearTimeout(timer);
				fn(value);
			};
			const onResolve = (payload) => {
				// `match` correlates the reply with THIS request. Without it a frame meant for
				// an earlier, abandoned command satisfies this one, and since replies arrive in
				// order every later command then answers with its predecessor's data — a
				// desync that persists for the life of the connection.
				if (match && !match(payload)) {
					return;
				}
				finish(resolve, map ? map(payload) : payload);
			};
			const onErr = (payload) =>
				errResolvesNull ? finish(resolve, null) : finish(reject, new Error(describeErr(payload)));
			const timer = setTimeout(() => finish(reject, new Error('timed out waiting for response')), timeoutMs);
			this.on(resolveCode, onResolve);
			this.on(RESP.ERR, onErr);
			this.sendToRadioFrame(bytes).catch((e) => finish(reject, e));
		});
	}

	// --- commands -------------------------------------------------------------

	/**
	 * Set the LoRa radio parameters, replacing meshcore.js's `setRadioParams`.
	 *
	 * The base version writes only [freq, bw, sf, cr] and stops. The firmware reads an
	 * OPTIONAL trailing `client_repeat` byte (ver 9+), defaults it to 0 when absent, and
	 * then assigns it unconditionally — so every radio-params write through the base
	 * method silently turns client repeat OFF. We always send the byte explicitly; read the
	 * current value from `deviceQuery().clientRepeat` (DEVICE_INFO carries it, SELF_INFO
	 * does not) before writing, so a radio change does not clear it by accident.
	 *
	 * Wire units are the firmware's: `freqKhz` in kHz and `bandwidthHz` in Hz — it divides
	 * both by 1000 into its MHz / kHz prefs.
	 */
	setRadioParams(freqKhz, bandwidthHz, sf, cr, clientRepeat = false) {
		const w = new BufferWriter();
		w.writeByte(CMD.SET_RADIO_PARAMS);
		w.writeUInt32LE(freqKhz);
		w.writeUInt32LE(bandwidthHz);
		w.writeByte(sf);
		w.writeByte(cr);
		w.writeByte(clientRepeat ? 1 : 0);
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ success: true }) });
	}

	/**
	 * Set the MAC tuning parameters (CMD 21). meshcore.js declares the opcode `// todo` and
	 * implements no method, so the node could read these but never write them.
	 *
	 * Both are sent as milli-units (the firmware divides by 1000), matching the units
	 * `getTuningParams` already returns.
	 */
	setTuningParams(rxDelayBase, airtimeFactor) {
		const w = new BufferWriter();
		w.writeByte(CMD.SET_TUNING_PARAMS);
		w.writeUInt32LE(Math.round(rxDelayBase * 1000));
		w.writeUInt32LE(Math.round(airtimeFactor * 1000));
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ success: true }) });
	}

	/**
	 * Send a fully-formed packet (CMD_SEND_RAW_PACKET, firmware v1.16 / protocol ver 13+).
	 * Unlike every other send command, the caller supplies the whole packet — header,
	 * transport codes, path and payload — and the device only validates and queues it.
	 *
	 * `packet` layout, per `Dispatcher::tryParsePacket`:
	 *   header (1)                         payload ver in the top bits must be <= 1
	 *   transport codes (4)                only when the header says hasTransportCodes()
	 *   path_len (1)                       PACKED: low 6 bits = hop count, high 2 = size - 1
	 *                                      (a path mode of 3 is reserved and rejected)
	 *   path (hop count * hash size)       must fit in the frame and in MAX_PATH_SIZE (64)
	 *   payload (the remainder)            must be non-empty
	 *
	 * `priority` orders the outbound queue; lower goes out sooner (the firmware itself uses
	 * 0 for normal traffic, 1 for path packets, 5 for traces).
	 */
	sendRawPacket(packet, priority = 0) {
		const bytes = Buffer.from(packet ?? []);
		// firmware gate is `len >= 4`, i.e. opcode + priority + at least 2 packet bytes
		if (bytes.length < 2) {
			return Promise.reject(
				new Error('Raw packet must be at least 2 bytes (a header and a path length byte)'),
			);
		}
		const w = new BufferWriter();
		w.writeByte(CMD.SEND_RAW_PACKET);
		w.writeByte(priority & 0xff);
		w.writeBytes(bytes);
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ success: true }) });
	}

	/**
	 * Send a custom payload as a RAW_CUSTOM packet along an explicit path
	 * (CMD_SEND_RAW_DATA). The firmware builds the packet — you supply only the route and
	 * the payload, so the header and payload type are not yours to choose. Use
	 * `sendRawPacket` when you need control over those.
	 *
	 * CAVEAT — 1-byte path hashes only. The firmware reads the path-length byte twice with
	 * two different meanings: the bounds check and the read cursor treat it as a raw BYTE
	 * count (`i += path_len`), while `sendDirect` -> `Packet::copyPath` decodes it as the
	 * PACKED count/size byte. Those agree only when the hash size is 1, where packed value,
	 * hop count and byte length are the same number. With a non-empty path on a mesh using
	 * larger hashes there is no value that satisfies both readings, so we send the byte
	 * length (which is what the frame parsing needs) and callers must not use a path there.
	 * An empty path (zero hop) is unaffected.
	 */
	sendRawData(path, data) {
		const route = Buffer.from(path ?? []);
		const payload = Buffer.from(data ?? []);
		if (payload.length < 4) {
			return Promise.reject(
				new Error(`Raw data payload must be at least 4 bytes (got ${payload.length})`),
			);
		}
		if (route.length > 63) {
			return Promise.reject(
				new Error(`Raw data path must be at most 63 bytes (got ${route.length})`),
			);
		}
		const w = new BufferWriter();
		w.writeByte(CMD.SEND_RAW_DATA);
		w.writeByte(route.length);
		w.writeBytes(route);
		w.writeBytes(payload);
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ success: true }) });
	}

	/**
	 * Read one channel slot, replacing meshcore.js's `getChannel`.
	 *
	 * The base version resolves on the FIRST ChannelInfo frame that arrives, whatever
	 * channel it describes — even though the firmware echoes `channel_idx` back
	 * (`out_frame[1] = channel_idx`) and meshcore.js already parses it as `channelIdx`. It
	 * also has no timeout, and its paired `off()` calls are no-ops because `once()` wraps
	 * the listener, so an abandoned lookup stays armed and keeps consuming frames.
	 *
	 * Together those turn one slow or dropped reply into a permanent off-by-one: every
	 * later lookup resolves with the previous one's channel. A workflow that resolves a
	 * channel by name and then sends to the returned index starts sending to the wrong
	 * channel and never recovers on its own. Matching on `channelIdx` makes the whole
	 * class impossible — a stale frame is now ignored instead of accepted.
	 */
	getChannel(channelIdx) {
		const idx = channelIdx & 0xff;
		const w = new BufferWriter();
		w.writeByte(CMD.GET_CHANNEL);
		w.writeByte(idx);
		return this._command(w.toBytes(), {
			resolveCode: RESP.CHANNEL_INFO,
			match: (payload) => payload?.channelIdx === idx,
		});
	}

	/**
	 * Enumerate channel slots. Same behaviour as meshcore.js's version — walk upwards until
	 * the device answers ERR — but bounded, because the base version's `while(true)` has no
	 * stop condition other than that error, and a desynced stream could keep it running
	 * (and issuing commands) forever.
	 */
	async getChannels(maxChannels = MAX_CHANNEL_SLOTS) {
		const channels = [];
		for (let idx = 0; idx < maxChannels; idx++) {
			try {
				channels.push(await this.getChannel(idx));
			} catch {
				break; // ERR = no such slot, i.e. the end of the list
			}
		}
		return channels;
	}

	hasConnection(pubKey) {
		const w = new BufferWriter();
		w.writeByte(CMD.HAS_CONNECTION);
		w.writeBytes(pubKey.slice(0, PUB_KEY_SIZE));
		// OK => connected, ERR(NOT_FOUND) => not connected
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ connected: true }), errResolvesNull: true }).then(
			(r) => r ?? { connected: false },
		);
	}

	logout(pubKey) {
		const w = new BufferWriter();
		w.writeByte(CMD.LOGOUT);
		w.writeBytes(pubKey.slice(0, PUB_KEY_SIZE));
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ success: true }) });
	}

	getContactByKey(pubKey) {
		const w = new BufferWriter();
		w.writeByte(CMD.GET_CONTACT_BY_KEY);
		w.writeBytes(pubKey.slice(0, PUB_KEY_SIZE));
		return this._command(w.toBytes(), { resolveCode: RESP.CONTACT, errResolvesNull: true });
	}

	setDevicePin(pin) {
		const w = new BufferWriter();
		w.writeByte(CMD.SET_DEVICE_PIN);
		w.writeUInt32LE(pin >>> 0);
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ success: true }) });
	}

	getCustomVars() {
		const w = new BufferWriter();
		w.writeByte(CMD.GET_CUSTOM_VARS);
		return this._command(w.toBytes(), { resolveCode: RESP.CUSTOM_VARS });
	}

	setCustomVar(name, value) {
		const w = new BufferWriter();
		w.writeByte(CMD.SET_CUSTOM_VAR);
		w.writeString(`${name}:${value}`);
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ success: true }) });
	}

	getAdvertPath(pubKey) {
		const w = new BufferWriter();
		w.writeByte(CMD.GET_ADVERT_PATH);
		w.writeByte(0); // reserved
		w.writeBytes(pubKey.slice(0, PUB_KEY_SIZE));
		return this._command(w.toBytes(), { resolveCode: RESP.ADVERT_PATH, errResolvesNull: true });
	}

	getTuningParams() {
		const w = new BufferWriter();
		w.writeByte(CMD.GET_TUNING_PARAMS);
		return this._command(w.toBytes(), { resolveCode: RESP.TUNING_PARAMS });
	}

	factoryReset() {
		const w = new BufferWriter();
		w.writeByte(CMD.FACTORY_RESET);
		w.writeString('reset');
		// device reboots right after OK; keep the timeout short
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ success: true }), timeoutMs: 5000 });
	}

	/**
	 * Trace a route, replacing meshcore.js's `tracePath`. The base version is unusable for
	 * diagnostics: it rejects with the bare string `"timeout"` and with `undefined` on a
	 * device ERR, so both collapse into one opaque "device error" for the user, and it
	 * never states the budget it waited for. This version rejects with real Errors that
	 * name the failure, the device's own estimate and the wait actually used.
	 *
	 * `path` must be non-empty: the firmware gates CMD_SEND_TRACE_PATH on `len > 10`
	 * (10 header bytes + at least one path byte), so a zero-length path falls through the
	 * whole dispatch chain to `writeErrFrame(ERR_CODE_UNSUPPORTED_CMD)`.
	 *
	 * `hashSize` is how many bytes each hop takes in the route. meshcore.js hardcodes the
	 * flags byte to 0, i.e. one byte per hop; on a 2-byte mesh the firmware then reads the
	 * route as twice as many single-byte hops, builds a trace for a path that does not
	 * exist, and transmits it — the packet goes out, and no reply ever comes back.
	 *
	 * Traces use their own encoding, NOT the packed `path_len` byte the rest of the
	 * protocol uses. `Mesh.cpp` treats the low 2 bits of the trace flags as a SHIFT — hop
	 * size is `1 << path_sz` and the byte offset is `path_len << path_sz` — so the sizes a
	 * trace can express are 1, 2, 4 and 8. The mesh's own `path_hash_mode` allows 1, 2 or 3
	 * bytes per hop (`mode + 1`), so a 3-byte mesh has no trace encoding at all; callers
	 * resolving the size from the device have to handle that case.
	 */
	tracePath(path, extraTimeoutMs = 0, hashSize = 1) {
		const route = Buffer.from(path ?? []);
		if (route.length === 0) {
			return Promise.reject(
				new Error(
					'Trace Path needs a route: the firmware requires at least one path byte and ' +
						'answers ERR "unsupported command" for an empty one. Give the route as hex ' +
						'path-hash bytes, e.g. "dd4c" for two 1-byte hops or "1be2dddd" for two 2-byte hops.',
				),
			);
		}
		const pathSz = [1, 2, 4, 8].indexOf(hashSize);
		if (pathSz === -1) {
			return Promise.reject(
				new Error(
					`Path hash size must be 1, 2, 4 or 8 bytes (got ${hashSize}) — the trace flags ` +
						'field encodes it as a shift, so other sizes cannot be sent.',
				),
			);
		}
		if (route.length % hashSize !== 0) {
			return Promise.reject(
				new Error(
					`Trace route is ${route.length} bytes, which is not a whole number of ` +
						`${hashSize}-byte hops. The device rejects such a route as an illegal argument.`,
				),
			);
		}

		// correlation tag, echoed in the SENT reply and in the TRACE_DATA push
		const tag = Math.floor(Math.random() * 0x100000000);
		const w = new BufferWriter();
		w.writeByte(CMD.SEND_TRACE_PATH);
		w.writeUInt32LE(tag);
		w.writeUInt32LE(0); // auth code
		w.writeByte(pathSz); // flags: low 2 bits are the hash-size shift
		w.writeBytes(route);

		return new Promise((resolve, reject) => {
			let done = false;
			let timer = null;
			const finish = (fn, value) => {
				if (done) return;
				done = true;
				this.off(RESP.SENT, onSent);
				this.off(RESP.ERR, onErr);
				this.off(PUSH.TRACE_DATA, onTraceData);
				clearTimeout(timer);
				fn(value);
			};

			// Until the device accepts the command there is no estimate to wait on. The base
			// version arms no timer at all here, so a lost SENT hangs the promise forever.
			timer = setTimeout(
				() => finish(reject, new Error('MeshCore device did not acknowledge the trace command')),
				SEND_ACK_TIMEOUT_MS,
			);

			const onSent = (payload) => {
				// The device's est_timeout is calcDirectTimeoutMillisFor() over the OUTBOUND
				// packet; the trace grows a hash + an SNR byte at every hop, so the reply is
				// bigger and slower than what that estimate covers. `extraTimeoutMs` is the
				// user's headroom on top of it.
				const estTimeout = payload?.estTimeout ?? 0;
				const waited = estTimeout + extraTimeoutMs;
				clearTimeout(timer);
				// an ERR now would no longer be about a trace that is already on the air
				this.off(RESP.ERR, onErr);
				timer = setTimeout(
					() =>
						finish(
							reject,
							new Error(
								`MeshCore trace was sent but no reply arrived within ${waited}ms ` +
									`(device estimate ${estTimeout}ms + extra timeout ${extraTimeoutMs}ms). ` +
									'Raise "Extra Timeout (Ms)", or check that the path is correct and every hop is reachable.',
							),
						),
					waited,
				);
			};

			const onTraceData = (payload) => {
				if (payload?.tag === tag) {
					finish(resolve, payload);
				}
			};

			const onErr = (payload) =>
				finish(reject, new Error(`MeshCore device rejected the trace: ${describeErr(payload)}`));

			this.on(RESP.SENT, onSent);
			this.on(RESP.ERR, onErr);
			this.on(PUSH.TRACE_DATA, onTraceData);
			this.sendToRadioFrame(w.toBytes()).catch((e) => finish(reject, e));
		});
	}

	sendPathDiscoveryReq(pubKey) {
		const w = new BufferWriter();
		w.writeByte(CMD.SEND_PATH_DISCOVERY_REQ);
		w.writeByte(0); // reserved
		w.writeBytes(pubKey.slice(0, PUB_KEY_SIZE));
		// resolves on SENT; the discovery result later arrives as push 0x8D
		return this._command(w.toBytes(), { resolveCode: RESP.SENT });
	}

	sendControlData(data) {
		const w = new BufferWriter();
		w.writeByte(CMD.SEND_CONTROL_DATA);
		w.writeBytes(data); // first data byte must have bit 0x80 set (firmware requirement)
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ success: true }) });
	}

	sendAnonReq(pubKey, data) {
		const w = new BufferWriter();
		w.writeByte(CMD.SEND_ANON_REQ);
		w.writeBytes(pubKey.slice(0, PUB_KEY_SIZE));
		w.writeBytes(data);
		return this._command(w.toBytes(), { resolveCode: RESP.SENT });
	}

	setAutoAddConfig(config, maxHops) {
		const w = new BufferWriter();
		w.writeByte(CMD.SET_AUTOADD_CONFIG);
		w.writeByte(config);
		if (maxHops != null) {
			w.writeByte(maxHops);
		}
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ success: true }) });
	}

	getAutoAddConfig() {
		const w = new BufferWriter();
		w.writeByte(CMD.GET_AUTOADD_CONFIG);
		return this._command(w.toBytes(), { resolveCode: RESP.AUTOADD_CONFIG });
	}

	getAllowedRepeatFreq() {
		const w = new BufferWriter();
		w.writeByte(CMD.GET_ALLOWED_REPEAT_FREQ);
		return this._command(w.toBytes(), { resolveCode: RESP.ALLOWED_REPEAT_FREQ });
	}

	setPathHashMode(mode) {
		const w = new BufferWriter();
		w.writeByte(CMD.SET_PATH_HASH_MODE);
		w.writeByte(0); // reserved
		w.writeByte(mode);
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ success: true }) });
	}

	setDefaultFloodScope(name, key) {
		const w = new BufferWriter();
		w.writeByte(CMD.SET_DEFAULT_FLOOD_SCOPE);
		if (name && key && key.length > 0) {
			w.writeCString(name, 31);
			w.writeBytes(key.slice(0, 16));
		}
		return this._command(w.toBytes(), { resolveCode: RESP.OK, map: () => ({ success: true }) });
	}

	getDefaultFloodScope() {
		const w = new BufferWriter();
		w.writeByte(CMD.GET_DEFAULT_FLOOD_SCOPE);
		return this._command(w.toBytes(), { resolveCode: RESP.DEFAULT_FLOOD_SCOPE });
	}
}

export default ExtendedTCPConnection;
