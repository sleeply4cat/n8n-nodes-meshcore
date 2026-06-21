import type { IDataObject, INodePropertyOptions } from 'n8n-workflow';

import type { SharedConnection } from '../shared/ConnectionManager';
import { PushCodes } from '../shared/codes';
import { enrichContactRecord } from '../shared/contactPath';
import { startMessageStream, type EmitFn } from './messageStream';

/** Message sub-events served by draining MSG_WAITING (routed by message type). */
export const messageEvents = ['directMessage', 'channelMessage', 'channelData'];

/**
 * Events that meshcore.js emits directly as parsed push payloads — the trigger can
 * subscribe to their code and forward the payload as-is.
 */
export const directPushEvents: Record<string, number> = {
	advert: PushCodes.Advert,
	newAdvert: PushCodes.NewAdvert,
	sendConfirmed: PushCodes.SendConfirmed,
	pathUpdated: PushCodes.PathUpdated,
	statusResponse: PushCodes.StatusResponse,
	loginSuccess: PushCodes.LoginSuccess,
	loginFail: PushCodes.LoginFail,
	telemetryResponse: PushCodes.TelemetryResponse,
	traceData: PushCodes.TraceData,
	rawData: PushCodes.RawData,
	logRxData: PushCodes.LogRxData,
	pathDiscoveryResponse: PushCodes.PathDiscoveryResponse,
	controlData: PushCodes.ControlData,
	contactDeleted: PushCodes.ContactDeleted,
	contactsFull: PushCodes.ContactsFull,
};

/** UI options for the trigger's "events" multi-select. */
export const eventOptions: INodePropertyOptions[] = [
	{ name: 'New Direct Message', value: 'directMessage', description: 'A direct (private) message was received' },
	{ name: 'New Channel Message', value: 'channelMessage', description: 'A channel message was received' },
	{ name: 'New Channel Data', value: 'channelData', description: 'Binary channel data was received' },
	{ name: 'New Advert', value: 'advert', description: 'An advert was received in auto-add mode (firmware emits only the publicKey; use New Advert (Manual Add) if you need name/coords/path)' },
	{ name: 'New Advert (Manual Add)', value: 'newAdvert', description: 'An advert was received in manual-add mode (includes name, coordinates, path)' },
	{ name: 'Message Delivery Confirmed', value: 'sendConfirmed', description: 'An outgoing message was acknowledged' },
	{ name: 'Path Updated', value: 'pathUpdated', description: 'A route to a contact changed' },
	{ name: 'Status Response', value: 'statusResponse', description: 'A status response was received' },
	{ name: 'Login Success', value: 'loginSuccess', description: 'A repeater/room login succeeded' },
	{ name: 'Login Failed', value: 'loginFail', description: 'A repeater/room login failed' },
	{ name: 'Telemetry Response', value: 'telemetryResponse', description: 'A telemetry response was received' },
	{ name: 'Trace Data', value: 'traceData', description: 'Trace-path data was received' },
	{ name: 'Raw Data (Sniffer)', value: 'rawData', description: 'A raw packet was received' },
	{ name: 'Log RX Data (Sniffer)', value: 'logRxData', description: 'A radio RX log entry was received' },
	{ name: 'Path Discovery Response', value: 'pathDiscoveryResponse', description: 'A path-discovery response was received' },
	{ name: 'Control Data', value: 'controlData', description: 'A control datagram was received' },
	{ name: 'Contact Deleted', value: 'contactDeleted', description: 'A contact was deleted (storage overwrite)' },
	{ name: 'Contacts Full', value: 'contactsFull', description: 'Contact storage is full' },
];

/**
 * Per-event payload transformers applied before emit. Use this to decode
 * firmware-side encodings (e.g. packed `outPathLen`) so workflows see friendly
 * fields. Events without an entry are emitted as-is.
 */
const eventTransforms: Record<string, (payload: IDataObject) => IDataObject> = {
	// NewAdvert (0x8A) carries a full contact record (publicKey, type, flags,
	// outPathLen, outPath, advName, lat/lon, …). Apply the same outPath decoding
	// the action-side Get Many / Get by Key ops use so workflows don't see a
	// 64-byte tail of garbage and have hops/hashSize at hand.
	newAdvert: (payload) => enrichContactRecord({ ...payload }) as IDataObject,
};

/**
 * Wire up the selected events on the shared connection. Returns the unsubscribe
 * functions to call from the trigger's closeFunction.
 */
export function startSubscriptions(
	conn: SharedConnection,
	selectedEvents: string[],
	emit: EmitFn,
): Array<() => void> {
	const unsubscribers: Array<() => void> = [];

	const selectedMessageTypes = messageEvents.filter((e) => selectedEvents.includes(e));
	if (selectedMessageTypes.length > 0) {
		unsubscribers.push(startMessageStream(conn, selectedMessageTypes, emit));
	}

	for (const [event, code] of Object.entries(directPushEvents)) {
		if (selectedEvents.includes(event)) {
			const transform = eventTransforms[event];
			unsubscribers.push(
				conn.subscribe(code, (payload) => {
					const data = (payload ?? {}) as IDataObject;
					emit(event, transform ? transform(data) : data);
				}),
			);
		}
	}

	return unsubscribers;
}
