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

// Command opcodes missing from meshcore.js (firmware MyMesh.cpp).
const CMD = {
	HAS_CONNECTION: 28,
	LOGOUT: 29,
	GET_CONTACT_BY_KEY: 30,
	SET_DEVICE_PIN: 37,
	GET_CUSTOM_VARS: 40,
	SET_CUSTOM_VAR: 41,
	GET_ADVERT_PATH: 42,
	GET_TUNING_PARAMS: 43,
	FACTORY_RESET: 51,
	SEND_PATH_DISCOVERY_REQ: 52,
	SEND_CONTROL_DATA: 55,
	SEND_ANON_REQ: 57,
	SET_AUTOADD_CONFIG: 58,
	GET_AUTOADD_CONFIG: 59,
	GET_ALLOWED_REPEAT_FREQ: 60,
	SET_PATH_HASH_MODE: 61,
	SET_DEFAULT_FLOOD_SCOPE: 63,
	GET_DEFAULT_FLOOD_SCOPE: 64,
};

// Response codes (device -> host) not modelled by meshcore.js constants.
const RESP = {
	OK: 0,
	ERR: 1,
	CONTACT: 3,
	SENT: 6,
	CUSTOM_VARS: 21,
	ADVERT_PATH: 22,
	TUNING_PARAMS: 23,
	AUTOADD_CONFIG: 25,
	ALLOWED_REPEAT_FREQ: 26,
	DEFAULT_FLOOD_SCOPE: 28,
};

// Async push codes (device -> host) not modelled by meshcore.js constants.
const PUSH = {
	PATH_DISCOVERY_RESPONSE: 0x8d,
	CONTROL_DATA: 0x8e,
	CONTACT_DELETED: 0x8f,
	CONTACTS_FULL: 0x90,
};

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
	_command(bytes, { resolveCode, map, errResolvesNull = false, timeoutMs = 10000 } = {}) {
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
			const onResolve = (payload) => finish(resolve, map ? map(payload) : payload);
			const onErr = () =>
				errResolvesNull ? finish(resolve, null) : finish(reject, new Error('device returned an error'));
			const timer = setTimeout(() => finish(reject, new Error('timed out waiting for response')), timeoutMs);
			this.on(resolveCode, onResolve);
			this.on(RESP.ERR, onErr);
			this.sendToRadioFrame(bytes).catch((e) => finish(reject, e));
		});
	}

	// --- commands -------------------------------------------------------------

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
