import type { IExecuteFunctions, IDataObject, INodeProperties } from 'n8n-workflow';

import {
	buildGroupTextPacket,
	composeGroupPayload,
	computePacketHash,
} from '../shared/channelHash';
import {
	buildAdvertPacket,
	buildFrame,
	calcSharedSecret,
	composeAnonPayload,
	composeDirectPayload,
	composeDirectTextPlaintext,
	composeGroupDataPlaintext,
	composeMultipartPayload,
	composePathPlaintext,
	composeTracePayload,
	decodePacket,
	expectedAckCode,
	PAYLOAD_TYPE_ACK,
	PAYLOAD_TYPE_ADVERT,
	PAYLOAD_TYPE_ANON_REQ,
	PAYLOAD_TYPE_CONTROL,
	PAYLOAD_TYPE_MULTIPART,
	PAYLOAD_TYPE_PATH,
	PAYLOAD_TYPE_TRACE,
	PAYLOAD_TYPE_TXT_MSG,
	publicKeyFromPrivate,
	ROUTE_TYPE_DIRECT,
	ROUTE_TYPE_FLOOD,
} from '../shared/packetCodec';
import type { ChannelKey, Identity, PeerKey } from '../shared/packetCodec';

/**
 * The Utilities resource: encode and decode MeshCore frames without touching a device.
 *
 * These operations never open a connection, so they work on frames from the trigger's
 * sniffer events, from an MQTT bridge, or from a capture. They live in this node rather
 * than in nodes of their own so that one integration presents one entry in the panel.
 */

const PAYLOAD_TYPE_GRP_DATA = 0x06;
const PAYLOAD_TYPE_RAW_CUSTOM = 0x0f;

const showFor = (operations: string[]): INodeProperties['displayOptions'] => ({
	show: { resource: ['utilities'], operation: operations },
});

const ENCODE_OPERATIONS = [
	'encodeAck',
	'encodeAdvert',
	'encodeAnonRequest',
	'encodeChannelData',
	'encodeChannelMessage',
	'encodeControlData',
	'encodeDirectDatagram',
	'encodeDirectMessage',
	'encodeMultipart',
	'encodePathReturn',
	'encodeRawCustom',
	'encodeRawFrame',
	'encodeTrace',
];

/** Operations that derive an ECDH shared secret from our key and the peer's. */
const KEYED_OPERATIONS = [
	'encodeDirectMessage',
	'encodeDirectDatagram',
	'encodeAnonRequest',
	'encodePathReturn',
];

/** Payload types worth filtering on; values are the firmware's PAYLOAD_TYPE_* constants. */
const PAYLOAD_TYPE_OPTIONS = [
	{ name: 'ACK', value: 0x03, description: 'Delivery acknowledgement' },
	{ name: 'Advert', value: 0x04, description: 'A node advertising its identity' },
	{ name: 'Anonymous Request', value: 0x07 },
	{ name: 'Channel Datagram (GRP_DATA)', value: 0x06, description: 'Group binary data; needs a channel secret' },
	{ name: 'Channel Message (GRP_TXT)', value: 0x05, description: 'Group text; needs a channel secret' },
	{ name: 'Control', value: 0x0b, description: 'Control/discovery packet' },
	{ name: 'Direct Message (TXT_MSG)', value: 0x02, description: 'Needs a private key and the sender public key' },
	{ name: 'Multipart', value: 0x0a, description: 'One packet of a multi-packet set' },
	{ name: 'Path', value: 0x08, description: 'A returned route' },
	{ name: 'Raw Custom', value: 0x0f },
	{ name: 'Request', value: 0x00 },
	{ name: 'Response', value: 0x01 },
	{ name: 'Trace', value: 0x09, description: 'Path trace collecting per-hop SNR' },
];

/** One named key list; the same shape for channel secrets, private keys and peer keys. */
function keyCollection(
	name: string,
	displayName: string,
	valueField: string,
	valueLabel: string,
	valueDescription: string,
	description: string,
): INodeProperties {
	return {
		displayName,
		name,
		type: 'fixedCollection',
		typeOptions: { multipleValues: true },
		default: {},
		description,
		placeholder: `Add ${valueLabel}`,
		displayOptions: showFor(['decode']),
		options: [
			{
				name: 'entry',
				displayName: 'Entry',
				values: [
					{
						displayName: 'Label',
						name: 'name',
						type: 'string',
						default: '',
						description: 'Only used to tag the output, so you can tell matches apart',
					},
					{
						displayName: valueLabel,
						name: valueField,
						type: 'string',
						default: '',
						required: true,
						typeOptions: { password: true },
						description: valueDescription,
					},
				],
			},
		],
	};
}

export const utilitiesOperationSelector: INodeProperties = {
	displayName: 'Operation',
	name: 'operation',
	type: 'options',
	noDataExpression: true,
	displayOptions: { show: { resource: ['utilities'] } },
	default: 'decode',
	options: [
		{
			name: 'Decode Packet',
			value: 'decode',
			action: 'Decode a raw packet',
			description: 'Parse a raw frame and decrypt what the supplied keys can open',
		},
		{
			name: 'Encode ACK',
			value: 'encodeAck',
			action: 'Encode an ack',
			description: 'Build an ACK packet carrying a delivery acknowledgement code',
		},
		{
			name: 'Encode Advert',
			value: 'encodeAdvert',
			action: 'Encode an advert',
			description: 'Build a signed advert announcing an identity (firmware v1.16.0+ to transmit)',
		},
		{
			name: 'Encode Anonymous Request',
			value: 'encodeAnonRequest',
			action: 'Encode an anonymous request',
			description: 'Build an ANON_REQ, which carries your full public key so a stranger can reply',
		},
		{
			name: 'Encode Channel Datagram',
			value: 'encodeChannelData',
			action: 'Encode a channel datagram',
			description: 'Build a typed binary payload encrypted to a channel',
		},
		{
			name: 'Encode Channel Message',
			value: 'encodeChannelMessage',
			action: 'Encode a channel message',
			description: 'Build a channel text packet with any nickname as its author',
		},
		{
			name: 'Encode Control Data',
			value: 'encodeControlData',
			action: 'Encode control data',
			description: 'Build a CONTROL packet, used for discovery and control traffic',
		},
		{
			name: 'Encode Direct Datagram',
			value: 'encodeDirectDatagram',
			action: 'Encode a direct datagram',
			description: 'Build an encrypted REQ or RESPONSE carrying an arbitrary blob',
		},
		{
			name: 'Encode Direct Message',
			value: 'encodeDirectMessage',
			action: 'Encode a direct message',
			description: 'Build an encrypted TXT_MSG addressed to one contact',
		},
		{
			name: 'Encode Multipart',
			value: 'encodeMultipart',
			action: 'Encode a multipart packet',
			description: 'Wrap another packet payload as one part of a multi-packet set',
		},
		{
			name: 'Encode Path Return',
			value: 'encodePathReturn',
			action: 'Encode a path return',
			description: 'Build an encrypted PATH packet handing a route back to a contact',
		},
		{
			name: 'Encode Raw Custom',
			value: 'encodeRawCustom',
			action: 'Encode a raw custom packet',
			description: 'Build a RAW_CUSTOM packet carrying your bytes unencrypted',
		},
		{
			name: 'Encode Raw Frame',
			value: 'encodeRawFrame',
			action: 'Encode a raw frame',
			description: 'Set every header field by hand, for packet types this node does not model',
		},
		{
			name: 'Encode Trace',
			value: 'encodeTrace',
			action: 'Encode a trace',
			description: 'Build a TRACE packet that collects SNR at every hop',
		},
	],
};

export const utilitiesProperties: INodeProperties[] = [
	{
		displayName: 'Packet',
		name: 'packet',
		type: 'string',
		default: '',
		required: true,
		description:
			"The on-air frame as hex. This is the `raw` field of the trigger's Raw Data and Log RX Data events, or whatever your bridge carries.",
		placeholder: '15007d...',
		displayOptions: showFor(['decode']),
	},
	{
		displayName: 'Packet Types',
		name: 'payloadTypes',
		type: 'multiOptions',
		default: [],
		options: PAYLOAD_TYPE_OPTIONS,
		description:
			'Only emit packets of these types. Leave empty for all. Non-matching packets produce no output item at all, so this replaces a downstream IF on a busy sniffer feed.',
		displayOptions: showFor(['decode']),
	},
	keyCollection(
		'channelKeys',
		'Channel Secrets',
		'secret',
		'Secret',
		'The 16-byte channel secret as hex, from Channel → Get Channel',
		'Channel secrets to try on group traffic. The MAC check identifies which one fits, so listing several costs nothing.',
	),
	keyCollection(
		'identities',
		'Private Keys',
		'privateKey',
		'Private Key',
		'A 64-byte identity private key as hex, from Device → Export Private Key',
		'Private keys to try on direct traffic. List several to read messages for several identities on one radio. Each is the full identity of a node — anyone holding it can also send as that node.',
	),
	keyCollection(
		'peerKeys',
		'Peer Public Keys',
		'publicKey',
		'Public Key',
		"A 32-byte public key as hex, e.g. a contact's publicKey",
		'Public keys of the parties you expect to talk to. Direct traffic carries only a 1-byte sender hash, so the full sender key has to be known in advance to derive the shared secret.',
	),
	{
		displayName: 'Verify Advert Signatures',
		name: 'verifyAdverts',
		type: 'boolean',
		default: false,
		description:
			'Whether to check the Ed25519 signature on adverts, adding `signatureValid` to the output. This is the only authenticated field in MeshCore — everything else, including a channel message author, is unverified.',
		displayOptions: showFor(['decode']),
	},

	// --- encode ---------------------------------------------------------------
	{
		displayName: 'Private Key',
		name: 'privateKey',
		type: 'string',
		typeOptions: { password: true },
		default: '',
		required: true,
		description:
			'The 64-byte identity key as hex, from Device → Export Private Key, or one you manage yourself. The advert is signed with it and announces the matching public key, so this is the identity being claimed.',
		displayOptions: showFor(['encodeAdvert']),
	},
	{
		displayName: 'Advert Name',
		name: 'advertName',
		type: 'string',
		default: '',
		required: true,
		description:
			'Node name to advertise. Required — the firmware silently drops an advert whose app data has no name.',
		displayOptions: showFor(['encodeAdvert']),
	},
	{
		displayName: 'Node Type',
		name: 'advertType',
		type: 'options',
		default: 1,
		options: [
			{ name: 'Chat (Companion)', value: 1 },
			{ name: 'Repeater', value: 2 },
			{ name: 'Room Server', value: 3 },
			{ name: 'Sensor', value: 4 },
		],
		displayOptions: showFor(['encodeAdvert']),
	},
	{
		displayName: 'Include Location',
		name: 'includeLocation',
		type: 'boolean',
		default: false,
		description: 'Whether to advertise a latitude/longitude alongside the name',
		displayOptions: showFor(['encodeAdvert']),
	},
	{
		displayName: 'Latitude',
		name: 'latitude',
		type: 'number',
		default: 0,
		typeOptions: { numberPrecision: 6 },
		displayOptions: {
			show: { resource: ['utilities'], operation: ['encodeAdvert'], includeLocation: [true] },
		},
	},
	{
		displayName: 'Longitude',
		name: 'longitude',
		type: 'number',
		default: 0,
		typeOptions: { numberPrecision: 6 },
		displayOptions: {
			show: { resource: ['utilities'], operation: ['encodeAdvert'], includeLocation: [true] },
		},
	},
	{
		displayName: 'Channel Secret',
		name: 'channelSecret',
		type: 'string',
		typeOptions: { password: true },
		default: '',
		required: true,
		description: 'The 16-byte channel secret as hex, from Channel → Get Channel',
		displayOptions: showFor(['encodeChannelMessage', 'encodeChannelData']),
	},
	{
		displayName: 'Nickname',
		name: 'encodeNickname',
		type: 'string',
		default: '',
		required: true,
		description:
			'Author shown in the channel. It is only a prefix inside the encrypted text and nothing authenticates it — any node can claim any nickname.',
		displayOptions: showFor(['encodeChannelMessage']),
	},
	{
		displayName: 'Message',
		name: 'encodeMessage',
		type: 'string',
		typeOptions: { rows: 2 },
		default: '',
		required: true,
		description:
			'Text to send. Truncated so that the nickname, the separator and the text together fit the firmware limit.',
		displayOptions: showFor(['encodeChannelMessage']),
	},
	{
		displayName: 'Timestamp',
		name: 'encodeTimestamp',
		type: 'number',
		default: 0,
		description:
			'Unix seconds stamped into the packet. 0 uses the current time. On a channel message, retries must reuse one value or the mesh shows them separately instead of deduping. On an advert, receivers that already know this key ignore anything not strictly newer than the last advert they stored for it.',
		displayOptions: showFor(['encodeChannelMessage', 'encodeAdvert']),
	},
	{
		displayName: 'Data Type',
		name: 'dataType',
		type: 'number',
		default: 65535,
		required: true,
		typeOptions: { minValue: 0, maxValue: 65535 },
		description: 'Application-defined datagram type (uint16)',
		displayOptions: showFor(['encodeChannelData']),
	},
	{
		displayName: 'Data',
		name: 'data',
		type: 'string',
		default: '',
		required: true,
		description: 'Datagram bytes as hex',
		displayOptions: showFor(['encodeChannelData']),
	},
	{
		displayName: 'Payload',
		name: 'encodePayload',
		type: 'string',
		default: '',
		required: true,
		description: 'Packet payload as hex, used exactly as given',
		displayOptions: showFor(['encodeRawCustom', 'encodeRawFrame']),
	},
	{
		displayName: 'Payload Type',
		name: 'encodePayloadType',
		type: 'number',
		default: 15,
		required: true,
		typeOptions: { minValue: 0, maxValue: 15 },
		description: 'Firmware PAYLOAD_TYPE_* value, 0-15',
		displayOptions: showFor(['encodeRawFrame']),
	},
	{
		displayName: 'Payload Version',
		name: 'payloadVersion',
		type: 'number',
		default: 0,
		typeOptions: { minValue: 0, maxValue: 3 },
		description: 'Header version bits. The firmware only accepts 0 today.',
		displayOptions: showFor(['encodeRawFrame']),
	},
	{
		displayName: 'Route Type',
		name: 'routeType',
		type: 'options',
		default: 1,
		options: [
			{ name: 'Flood', value: 1, description: 'Broadcast; repeaters append their hash to the path' },
			{ name: 'Direct', value: 2, description: 'Along the explicit path below' },
			{ name: 'Transport Flood', value: 0, description: 'Flood carrying two transport codes' },
			{ name: 'Transport Direct', value: 3, description: 'Direct carrying two transport codes' },
		],
		displayOptions: showFor(['encodeRawCustom', 'encodeRawFrame', 'encodeAdvert']),
	},
	{
		displayName: 'Path',
		name: 'encodePath',
		type: 'string',
		default: '',
		description:
			'Route as hex path-hash bytes, hop by hop. Leave empty for a zero-hop packet. Its length must divide by the hop hash size.',
		displayOptions: showFor(['encodeRawCustom', 'encodeRawFrame']),
	},
	{
		displayName: 'Transport Code 1',
		name: 'transportCode1',
		type: 'number',
		default: 0,
		typeOptions: { minValue: 0, maxValue: 65535 },
		description: 'Only used by the transport route types',
		displayOptions: {
			show: { resource: ['utilities'], operation: ['encodeRawFrame'], routeType: [0, 3] },
		},
	},
	{
		displayName: 'Transport Code 2',
		name: 'transportCode2',
		type: 'number',
		default: 0,
		typeOptions: { minValue: 0, maxValue: 65535 },
		description: 'Only used by the transport route types',
		displayOptions: {
			show: { resource: ['utilities'], operation: ['encodeRawFrame'], routeType: [0, 3] },
		},
	},
	{
		displayName: 'Identity Private Key',
		name: 'identityPrivateKey',
		type: 'string',
		typeOptions: { password: true },
		default: '',
		required: true,
		description:
			'The 64-byte private key of the identity SENDING this packet, from Device → Export Private Key. It derives the shared secret with the recipient, so the recipient can only read the packet if this key really is the one they know you by.',
		displayOptions: showFor(KEYED_OPERATIONS),
	},
	{
		displayName: 'Recipient Public Key',
		name: 'recipientPublicKey',
		type: 'string',
		default: '',
		required: true,
		description: "The recipient's 32-byte public key as hex, e.g. a contact's publicKey",
		displayOptions: showFor(KEYED_OPERATIONS),
	},
	{
		displayName: 'Message',
		name: 'directMessage',
		type: 'string',
		typeOptions: { rows: 2 },
		default: '',
		required: true,
		description: 'Text to send, up to 160 bytes',
		displayOptions: showFor(['encodeDirectMessage']),
	},
	{
		displayName: 'Text Type',
		name: 'directTxtType',
		type: 'options',
		default: 0,
		options: [
			{ name: 'Plain', value: 0 },
			{ name: 'CLI Data', value: 1, description: 'A command for a repeater or room server' },
			{ name: 'Signed Plain', value: 2 },
		],
		displayOptions: showFor(['encodeDirectMessage']),
	},
	{
		displayName: 'Attempt',
		name: 'directAttempt',
		type: 'number',
		default: 0,
		typeOptions: { minValue: 0, maxValue: 3 },
		description:
			'Retry counter the firmware packs into the low two bits of the flags byte. It changes the packet, so a retry that reuses the timestamp but bumps this is a different packet to the mesh.',
		displayOptions: showFor(['encodeDirectMessage']),
	},
	{
		displayName: 'Timestamp',
		name: 'directTimestamp',
		type: 'number',
		default: 0,
		description: 'Unix seconds stamped into the packet. 0 uses the current time.',
		displayOptions: showFor(['encodeDirectMessage']),
	},
	{
		displayName: 'Datagram Type',
		name: 'datagramType',
		type: 'options',
		default: 0,
		options: [
			{ name: 'Request (REQ)', value: 0 },
			{ name: 'Response (RESPONSE)', value: 1 },
		],
		displayOptions: showFor(['encodeDirectDatagram']),
	},
	{
		displayName: 'Data',
		name: 'directData',
		type: 'string',
		default: '',
		required: true,
		description: 'Plaintext bytes as hex; they are encrypted to the recipient',
		displayOptions: showFor(['encodeDirectDatagram', 'encodeAnonRequest']),
	},
	{
		displayName: 'ACK Code',
		name: 'ackCode',
		type: 'string',
		default: '',
		required: true,
		description:
			'The acknowledgement bytes as hex, normally the 4-byte code the sender computed when building its message',
		displayOptions: showFor(['encodeAck']),
	},
	{
		displayName: 'Control Data',
		name: 'controlData',
		type: 'string',
		default: '',
		required: true,
		description:
			'Control bytes as hex. The firmware requires the top bit of the first byte to be set.',
		displayOptions: showFor(['encodeControlData']),
	},
	{
		displayName: 'Returned Path',
		name: 'returnPath',
		type: 'string',
		default: '',
		description:
			'The route being handed back, as hex path-hash bytes. Its length must match the hop count and hash size below.',
		displayOptions: showFor(['encodePathReturn']),
	},
	{
		displayName: 'Extra Type',
		name: 'pathExtraType',
		type: 'number',
		default: 0,
		typeOptions: { minValue: 0, maxValue: 15 },
		description: 'Type byte for the extra payload appended after the route',
		displayOptions: showFor(['encodePathReturn']),
	},
	{
		displayName: 'Extra',
		name: 'pathExtra',
		type: 'string',
		default: '',
		description:
			'Extra bytes as hex, appended after the route. Leave empty and the firmware convention of a 0xFF filler plus four bytes is used instead.',
		displayOptions: showFor(['encodePathReturn']),
	},
	{
		displayName: 'Trace Tag',
		name: 'traceTag',
		type: 'number',
		default: 0,
		description: 'Correlation tag echoed back in the trace reply. 0 picks a random one.',
		displayOptions: showFor(['encodeTrace']),
	},
	{
		displayName: 'Auth Code',
		name: 'traceAuth',
		type: 'number',
		default: 0,
		description: 'Auth code carried by the trace; 0 for an unauthenticated trace',
		displayOptions: showFor(['encodeTrace']),
	},
	{
		displayName: 'Trace Route',
		name: 'traceRoute',
		type: 'string',
		default: '',
		required: true,
		description:
			'The route to trace, as hex path-hash bytes. A trace carries its route inside the payload, and its hop size is a power of two — 1, 2, 4 or 8 — unlike the mesh path-hash mode, which also allows 3.',
		displayOptions: showFor(['encodeTrace']),
	},
	{
		displayName: 'Trace Hop Size',
		name: 'traceHashSize',
		type: 'options',
		default: 1,
		options: [
			{ name: '1 Byte per Hop', value: 1 },
			{ name: '2 Bytes per Hop', value: 2 },
			{ name: '4 Bytes per Hop', value: 4 },
			{ name: '8 Bytes per Hop', value: 8 },
		],
		displayOptions: showFor(['encodeTrace']),
	},
	{
		displayName: 'Inner Payload Type',
		name: 'multipartInnerType',
		type: 'number',
		default: 3,
		required: true,
		typeOptions: { minValue: 0, maxValue: 15 },
		description: 'Firmware PAYLOAD_TYPE_* of the wrapped payload; 3 is ACK',
		displayOptions: showFor(['encodeMultipart']),
	},
	{
		displayName: 'Remaining Parts',
		name: 'multipartRemaining',
		type: 'number',
		default: 0,
		typeOptions: { minValue: 0, maxValue: 15 },
		description: 'How many packets of this set are still to be sent; packed into a nibble',
		displayOptions: showFor(['encodeMultipart']),
	},
	{
		displayName: 'Inner Payload',
		name: 'multipartInnerPayload',
		type: 'string',
		default: '',
		required: true,
		description: 'The wrapped payload as hex',
		displayOptions: showFor(['encodeMultipart']),
	},
	{
		displayName: 'Path Hash Size',
		name: 'encodePathHashSize',
		type: 'options',
		default: 1,
		options: [
			{ name: '1 Byte per Hop', value: 1 },
			{ name: '2 Bytes per Hop', value: 2 },
			{ name: '3 Bytes per Hop', value: 3 },
		],
		description:
			'Bytes per hop in the packed path-length byte. Every repeater reads it to size the hash it appends, so it must match the mesh — read `pathHashSize` from Device → Get Device Info.',
		displayOptions: showFor(ENCODE_OPERATIONS),
	},
];

/** Parse a hex parameter, tolerating spaces and colons. */
function readHex(value: string, label: string): Buffer {
	const cleaned = (value ?? '').replace(/[\s:]/g, '');
	if (!cleaned) return Buffer.alloc(0);
	if (!/^[0-9a-fA-F]+$/.test(cleaned) || cleaned.length % 2 !== 0) {
		throw new Error(`${label} must be an even-length hex string`);
	}
	return Buffer.from(cleaned, 'hex');
}

/** Read one `fixedCollection` of labelled hex keys into decoder input. */
function collectKeys<T>(
	ctx: IExecuteFunctions,
	itemIndex: number,
	parameter: string,
	valueField: string,
	outField: string,
): T[] {
	const raw = ctx.getNodeParameter(parameter, itemIndex, {}) as {
		entry?: Array<Record<string, string>>;
	};
	const out: T[] = [];
	for (const entry of raw?.entry ?? []) {
		const hex = (entry[valueField] ?? '').replace(/[\s:]/g, '');
		if (!hex) continue;
		if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
			throw new Error(`${parameter}: "${entry.name || hex.slice(0, 8)}" is not valid hex`);
		}
		out.push({ name: entry.name ?? '', [outField]: Buffer.from(hex, 'hex') } as T);
	}
	return out;
}

/** Explicit timestamp when one is given, otherwise now. */
function timestampFor(ctx: IExecuteFunctions, itemIndex: number): number {
	const supplied = Number(ctx.getNodeParameter('encodeTimestamp', itemIndex, 0));
	return supplied > 0 ? Math.floor(supplied) : Math.floor(Date.now() / 1000);
}

/**
 * An operation that needs no device. Returning null means "emit nothing for this item",
 * which is how the decoder's packet-type filter drops non-matching frames.
 */
export type OfflineOperationHandler = (
	ctx: IExecuteFunctions,
	itemIndex: number,
) => Promise<IDataObject | null>;

/** Common encode result: the frame, its size, and the mesh's dedup hash for the payload. */
function finish(
	frame: Buffer,
	payloadType: number,
	payload: Buffer,
	pathHashSize: number,
): IDataObject {
	return {
		packet: frame.toString('hex'),
		packetBytes: frame.length,
		packetHash: computePacketHash(payloadType, payload).toString('hex'),
		pathHashSize,
	};
}

/**
 * The packet types encrypted to one recipient. All of them key the cipher with the ECDH
 * shared secret between the sender's identity and the recipient's public key, so they
 * share the key handling and differ only in what goes inside.
 */
async function encodeKeyed(
	ctx: IExecuteFunctions,
	i: number,
	operation: string,
	pathHashSize: number,
	routeType: number,
): Promise<IDataObject> {
	const privateKey = readHex(
		ctx.getNodeParameter('identityPrivateKey', i) as string,
		'Identity Private Key',
	);
	const recipient = readHex(
		ctx.getNodeParameter('recipientPublicKey', i) as string,
		'Recipient Public Key',
	);
	const senderPublicKey = await publicKeyFromPrivate(privateKey);
	const shared = await calcSharedSecret(privateKey, recipient);

	if (operation === 'encodeDirectMessage') {
		const supplied = Number(ctx.getNodeParameter('directTimestamp', i, 0));
		const timestamp = supplied > 0 ? Math.floor(supplied) : Math.floor(Date.now() / 1000);
		const plaintext = composeDirectTextPlaintext(
			ctx.getNodeParameter('directMessage', i) as string,
			timestamp,
			Number(ctx.getNodeParameter('directTxtType', i, 0)),
			Number(ctx.getNodeParameter('directAttempt', i, 0)),
		);
		const payload = composeDirectPayload(shared, recipient, senderPublicKey, plaintext);
		const frame = buildFrame({
			routeType,
			payloadType: PAYLOAD_TYPE_TXT_MSG,
			pathHashSize,
			payload,
		});
		return {
			...finish(frame, PAYLOAD_TYPE_TXT_MSG, payload, pathHashSize),
			timestamp,
			senderPublicKey: senderPublicKey.toString('hex'),
			// what the recipient will send back, so a workflow can wait for delivery
			expectedAck: expectedAckCode(plaintext, senderPublicKey).toString('hex'),
		};
	}

	if (operation === 'encodeDirectDatagram') {
		const payloadType = Number(ctx.getNodeParameter('datagramType', i, 0));
		const payload = composeDirectPayload(
			shared,
			recipient,
			senderPublicKey,
			readHex(ctx.getNodeParameter('directData', i) as string, 'Data'),
		);
		const frame = buildFrame({ routeType, payloadType, pathHashSize, payload });
		return {
			...finish(frame, payloadType, payload, pathHashSize),
			senderPublicKey: senderPublicKey.toString('hex'),
		};
	}

	if (operation === 'encodeAnonRequest') {
		const payload = composeAnonPayload(
			shared,
			recipient,
			senderPublicKey,
			readHex(ctx.getNodeParameter('directData', i) as string, 'Data'),
		);
		const frame = buildFrame({
			routeType,
			payloadType: PAYLOAD_TYPE_ANON_REQ,
			pathHashSize,
			payload,
		});
		return {
			...finish(frame, PAYLOAD_TYPE_ANON_REQ, payload, pathHashSize),
			senderPublicKey: senderPublicKey.toString('hex'),
		};
	}

	// encodePathReturn
	const returnPath = readHex(ctx.getNodeParameter('returnPath', i, '') as string, 'Returned Path');
	const extra = readHex(ctx.getNodeParameter('pathExtra', i, '') as string, 'Extra');
	const hops = pathHashSize > 0 ? returnPath.length / pathHashSize : 0;
	if (!Number.isInteger(hops)) {
		throw new Error(
			`Returned Path is ${returnPath.length} bytes, which is not a whole number of ${pathHashSize}-byte hops`,
		);
	}
	const plaintext = composePathPlaintext(
		((pathHashSize - 1) << 6) | hops,
		returnPath,
		extra.length > 0 ? Number(ctx.getNodeParameter('pathExtraType', i, 0)) : null,
		extra,
	);
	const payload = composeDirectPayload(shared, recipient, senderPublicKey, plaintext);
	const frame = buildFrame({ routeType, payloadType: PAYLOAD_TYPE_PATH, pathHashSize, payload });
	return {
		...finish(frame, PAYLOAD_TYPE_PATH, payload, pathHashSize),
		senderPublicKey: senderPublicKey.toString('hex'),
	};
}

async function encode(ctx: IExecuteFunctions, i: number, operation: string): Promise<IDataObject> {
	const pathHashSize = Number(ctx.getNodeParameter('encodePathHashSize', i, 1));
	const routeType = Number(ctx.getNodeParameter('routeType', i, ROUTE_TYPE_FLOOD));

	if (operation === 'encodeChannelMessage') {
		const timestamp = timestampFor(ctx, i);
		const built = buildGroupTextPacket(
			readHex(ctx.getNodeParameter('channelSecret', i) as string, 'Channel Secret'),
			ctx.getNodeParameter('encodeNickname', i) as string,
			ctx.getNodeParameter('encodeMessage', i) as string,
			timestamp,
			pathHashSize,
		);
		return {
			packet: built.frame.toString('hex'),
			packetBytes: built.frame.length,
			packetHash: built.hash.toString('hex'),
			truncated: built.truncated,
			pathHashSize,
			timestamp,
		};
	}

	if (operation === 'encodeAdvert') {
		const timestamp = timestampFor(ctx, i);
		const includeLocation = ctx.getNodeParameter('includeLocation', i, false) as boolean;
		const built = await buildAdvertPacket({
			privateKey: readHex(ctx.getNodeParameter('privateKey', i) as string, 'Private Key'),
			timestamp,
			pathHashSize,
			routeType,
			fields: {
				type: Number(ctx.getNodeParameter('advertType', i, 1)),
				name: ctx.getNodeParameter('advertName', i) as string,
				latitude: includeLocation ? Number(ctx.getNodeParameter('latitude', i, 0)) : undefined,
				longitude: includeLocation ? Number(ctx.getNodeParameter('longitude', i, 0)) : undefined,
			},
		});
		return {
			packet: built.frame.toString('hex'),
			packetBytes: built.frame.length,
			packetHash: computePacketHash(PAYLOAD_TYPE_ADVERT, built.frame.subarray(2)).toString('hex'),
			publicKey: built.publicKey.toString('hex'),
			signature: built.signature.toString('hex'),
			appData: built.appData.toString('hex'),
			pathHashSize,
			timestamp,
		};
	}

	if (operation === 'encodeChannelData') {
		const plaintext = composeGroupDataPlaintext(
			Number(ctx.getNodeParameter('dataType', i)),
			readHex(ctx.getNodeParameter('data', i) as string, 'Data'),
		);
		const payload = composeGroupPayload(
			readHex(ctx.getNodeParameter('channelSecret', i) as string, 'Channel Secret'),
			plaintext,
		);
		const frame = buildFrame({
			routeType: ROUTE_TYPE_FLOOD,
			payloadType: PAYLOAD_TYPE_GRP_DATA,
			pathHashSize,
			payload,
		});
		return {
			packet: frame.toString('hex'),
			packetBytes: frame.length,
			packetHash: computePacketHash(PAYLOAD_TYPE_GRP_DATA, payload).toString('hex'),
			pathHashSize,
		};
	}

	if (KEYED_OPERATIONS.includes(operation)) {
		return encodeKeyed(ctx, i, operation, pathHashSize, routeType);
	}

	if (operation === 'encodeAck') {
		const ack = readHex(ctx.getNodeParameter('ackCode', i) as string, 'ACK Code');
		return finish(
			buildFrame({ routeType, payloadType: PAYLOAD_TYPE_ACK, pathHashSize, payload: ack }),
			PAYLOAD_TYPE_ACK,
			ack,
			pathHashSize,
		);
	}

	if (operation === 'encodeControlData') {
		const data = readHex(ctx.getNodeParameter('controlData', i) as string, 'Control Data');
		if (data.length === 0 || (data[0] & 0x80) === 0) {
			throw new Error(
				'Control data must start with a byte whose top bit is set — the firmware rejects anything else',
			);
		}
		return finish(
			buildFrame({ routeType, payloadType: PAYLOAD_TYPE_CONTROL, pathHashSize, payload: data }),
			PAYLOAD_TYPE_CONTROL,
			data,
			pathHashSize,
		);
	}

	if (operation === 'encodeTrace') {
		const suppliedTag = Number(ctx.getNodeParameter('traceTag', i, 0));
		const tag = suppliedTag > 0 ? suppliedTag >>> 0 : Math.floor(Math.random() * 0x100000000);
		const payload = composeTracePayload(
			tag,
			Number(ctx.getNodeParameter('traceAuth', i, 0)),
			readHex(ctx.getNodeParameter('traceRoute', i) as string, 'Trace Route'),
			Number(ctx.getNodeParameter('traceHashSize', i, 1)),
		);
		// a trace carries its route in the payload, so the frame's own path stays empty
		const frame = buildFrame({
			routeType: ROUTE_TYPE_DIRECT,
			payloadType: PAYLOAD_TYPE_TRACE,
			pathHashSize: 1,
			payload,
		});
		return { ...finish(frame, PAYLOAD_TYPE_TRACE, payload, 1), tag };
	}

	if (operation === 'encodeMultipart') {
		const payload = composeMultipartPayload(
			Number(ctx.getNodeParameter('multipartInnerType', i)),
			Number(ctx.getNodeParameter('multipartRemaining', i, 0)),
			readHex(ctx.getNodeParameter('multipartInnerPayload', i) as string, 'Inner Payload'),
		);
		return finish(
			buildFrame({ routeType, payloadType: PAYLOAD_TYPE_MULTIPART, pathHashSize, payload }),
			PAYLOAD_TYPE_MULTIPART,
			payload,
			pathHashSize,
		);
	}

	// encodeRawCustom / encodeRawFrame
	const payload = readHex(ctx.getNodeParameter('encodePayload', i) as string, 'Payload');
	const payloadType =
		operation === 'encodeRawCustom'
			? PAYLOAD_TYPE_RAW_CUSTOM
			: Number(ctx.getNodeParameter('encodePayloadType', i));
	const frame = buildFrame({
		routeType,
		payloadType,
		payloadVersion:
			operation === 'encodeRawFrame' ? Number(ctx.getNodeParameter('payloadVersion', i, 0)) : 0,
		pathHashSize,
		path: readHex(ctx.getNodeParameter('encodePath', i, '') as string, 'Path'),
		payload,
		transportCodes:
			operation === 'encodeRawFrame'
				? [
						Number(ctx.getNodeParameter('transportCode1', i, 0)),
						Number(ctx.getNodeParameter('transportCode2', i, 0)),
					]
				: undefined,
	});
	return {
		packet: frame.toString('hex'),
		packetBytes: frame.length,
		packetHash: computePacketHash(payloadType, payload).toString('hex'),
		pathHashSize,
	};
}

export const offlineOperations: Record<string, OfflineOperationHandler> = {
	'utilities:decode': async (ctx, i) => {
		const raw = (ctx.getNodeParameter('packet', i) as string).trim();
		if (!raw) {
			throw new Error('Packet is empty');
		}
		const bytes = readHex(raw, 'Packet');

		const decoded = await decodePacket(bytes, {
			channels: collectKeys<ChannelKey>(ctx, i, 'channelKeys', 'secret', 'secret'),
			identities: collectKeys<Identity>(ctx, i, 'identities', 'privateKey', 'privateKey'),
			peers: collectKeys<PeerKey>(ctx, i, 'peerKeys', 'publicKey', 'publicKey'),
			verifyAdverts: ctx.getNodeParameter('verifyAdverts', i, false) as boolean,
		});

		const wanted = ctx.getNodeParameter('payloadTypes', i, []) as number[];
		if (wanted.length > 0 && !wanted.includes(decoded.payloadType)) {
			return null; // filtered out: emit nothing for this item
		}
		return decoded as unknown as IDataObject;
	},
	'utilities:encodeAdvert': async (ctx, i) => encode(ctx, i, 'encodeAdvert'),
	'utilities:encodeChannelMessage': async (ctx, i) => encode(ctx, i, 'encodeChannelMessage'),
	'utilities:encodeChannelData': async (ctx, i) => encode(ctx, i, 'encodeChannelData'),
	'utilities:encodeRawCustom': async (ctx, i) => encode(ctx, i, 'encodeRawCustom'),
	'utilities:encodeRawFrame': async (ctx, i) => encode(ctx, i, 'encodeRawFrame'),
	'utilities:encodeAck': async (ctx, i) => encode(ctx, i, 'encodeAck'),
	'utilities:encodeAnonRequest': async (ctx, i) => encode(ctx, i, 'encodeAnonRequest'),
	'utilities:encodeControlData': async (ctx, i) => encode(ctx, i, 'encodeControlData'),
	'utilities:encodeDirectDatagram': async (ctx, i) => encode(ctx, i, 'encodeDirectDatagram'),
	'utilities:encodeDirectMessage': async (ctx, i) => encode(ctx, i, 'encodeDirectMessage'),
	'utilities:encodeMultipart': async (ctx, i) => encode(ctx, i, 'encodeMultipart'),
	'utilities:encodePathReturn': async (ctx, i) => encode(ctx, i, 'encodePathReturn'),
	'utilities:encodeTrace': async (ctx, i) => encode(ctx, i, 'encodeTrace'),
};
