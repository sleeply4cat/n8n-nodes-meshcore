/**
 * MeshCore protocol codes we reference from node code. Mirrors meshcore.js
 * `Constants` (and the firmware tables) but is declared locally so node code does
 * not import the meshcore.js module at runtime (it is bundled lazily via the
 * ConnectionManager factory only when an actual connection is opened).
 *
 * Source of truth: MeshCore firmware `MyMesh.cpp`; cross-checked against
 * meshcore.js `src/constants.js`.
 */

/** Async device→host pushes. */
export const PushCodes = {
	Advert: 0x80,
	PathUpdated: 0x81,
	SendConfirmed: 0x82,
	MsgWaiting: 0x83,
	RawData: 0x84,
	LoginSuccess: 0x85,
	LoginFail: 0x86,
	StatusResponse: 0x87,
	LogRxData: 0x88,
	TraceData: 0x89,
	NewAdvert: 0x8a,
	TelemetryResponse: 0x8b,
	BinaryResponse: 0x8c,
	PathDiscoveryResponse: 0x8d,
	ControlData: 0x8e,
	ContactDeleted: 0x8f,
	ContactsFull: 0x90,
} as const;

/** Command-reply codes device→host. */
export const ResponseCodes = {
	Ok: 0,
	Err: 1,
	Contact: 3,
	EndOfContacts: 4,
	SelfInfo: 5,
	Sent: 6,
	ContactMsgRecv: 7,
	ChannelMsgRecv: 8,
	CurrTime: 9,
	NoMoreMessages: 10,
} as const;

export const TxtTypes = {
	Plain: 0,
	CliData: 1,
	SignedPlain: 2,
} as const;
