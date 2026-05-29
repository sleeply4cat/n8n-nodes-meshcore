# n8n-nodes-meshcore

Community [n8n](https://n8n.io) nodes for controlling a **MeshCore** device over
**TCP/WiFi** (the `companion_radio_wifi` firmware). Built on
[`@liamcottle/meshcore.js`](https://github.com/meshcore-dev/meshcore.js).

Two nodes are provided:

- **MeshCore** — an action node exposing the device's commands (send messages, manage
  contacts/channels, read stats/telemetry, run diagnostics, repeater admin, …).
- **MeshCore Trigger** — starts a workflow on device events (incoming messages, adverts,
  delivery confirmations, telemetry, traces, …).

> **Self-hosted only.** These nodes open a raw TCP socket to your device, which the
> n8n Cloud sandbox does not allow. They are intended for self-hosted n8n.

## Requirements

- A self-hosted n8n instance.
- **Node.js 22** (the build tooling — `@n8n/node-cli` — requires Node ≥ 20.12; Node 22 LTS
  is the tested version. Node 26 is too new for a native build dependency).
- A MeshCore device running `companion_radio_wifi`, reachable over your LAN on TCP
  (default port `5000`).

## Installation

In your self-hosted n8n: **Settings → Community Nodes → Install**, then enter
`n8n-nodes-meshcore`.

Or build and link locally (see [Development](#development)).

## Credentials — MeshCore TCP API

| Field | Description |
|---|---|
| **Host** | IP/hostname of the device (e.g. `10.1.0.226`) |
| **Port** | TCP port (default `5000`) |
| **Device PIN** | Optional connection PIN, only if the firmware enforces one over TCP |

Use **Test** on the credential to verify connectivity — it opens a short-lived TCP
connection to the device.

## MeshCore node — operations

| Resource | Operations |
|---|---|
| **Device** | Get Self Info, Get Battery Voltage, Get/Set/Sync Device Time, Set Advert Name, Set Advert Lat/Long, Set TX Power, Get Stats, Reboot, Set Device Pin, Get/Set Custom Variable(s), Get Tuning Parameters, Get Allowed Repeat Frequencies, Get/Set Auto Add Config, Set Path Hash Mode, Factory Reset |
| **Contact** | Get Many, Get by Key, Get Advert Path, Find by Name, Find by Public Key Prefix, Add or Update, Set Path, Reset Path, Share, Export, Import, Remove |
| **Message** | Send Direct Message, Send Direct Message and Await Delivery, Send Direct Message and Await Reply, Send Channel Message, Await Delivery, Get Waiting Messages, Sync Next Message |
| **Channel** | Get Channel, Get Many, Set, Delete, Send Data, Find by Name, Find by Secret |
| **Advert** | Send Flood Advert, Send Zero-Hop Advert |
| **Diagnostics** | Get Status, Get Telemetry, Get Neighbours, Trace Path, Send Binary Request, Send Path Discovery, Discover Path, Await Event |
| **Repeater** | Login, Logout, Has Connection, Sign Data, Send CLI Command, Send Anonymous Request, Send Control Data |
| **Flood Scope** | Set Scope, Clear Scope, Get Default, Set Default |

Binary fields (public keys, secrets, payloads, signatures) are entered/returned as **hex
strings**.

## MeshCore Trigger node — events

New Direct Message, New Channel Message, New Channel Data, New Advert, New Advert (Manual
Add), Message Delivery Confirmed, Path Updated, Status Response, Login Success/Failed,
Telemetry Response, Trace Data, Raw Data (sniffer), Log RX Data (sniffer), Path Discovery
Response, Control Data, Contact Deleted, Contacts Full.

The message events are driven by the `MSG_WAITING` push: on each signal the node drains
queued messages and emits one item per message, routed by type (direct/channel/channel
data). Draining always consumes the whole device queue, so select every message type you
care about on a single trigger node. Each emitted item is tagged with an `event` field.

## Common patterns

These combined operations turn the "send now, result arrives later" protocol flows into a
single synchronous node, so you don't need a second trigger plus shared state:

- **Reliable send** — *Message → Send Direct Message and Await Delivery* sends a message and
  waits for the recipient's ack. Returns `delivered: true/false` (false on timeout) plus
  `roundTrip` and `ackCode`. Branch on `delivered` to react to a confirmation *or its absence*.
- **Request / reply** — *Message → Send Direct Message and Await Reply* sends a message and
  waits for the contact's next reply (or times out). Great for ask-a-node chatbots.
- **Repeater admin** — *Repeater → Login* (guest = empty password, or admin password), then
  *Repeater → Send CLI Command* sends a CLI command and returns the repeater's response.
- **Path discovery** — *Diagnostics → Discover Path* floods a discovery request and waits for
  the discovered route.
- Standalone *Message → Await Delivery* (by `ackCode`) and *Diagnostics → Await Event* are
  building blocks if you need to wait separately from sending.

Message text type (Plain / CLI Data / Signed Plain) is selectable on the direct-send
operations. Public keys, secrets and paths are hex strings on both input and output, so a
received message's sender key pipes straight into a send node.

## How it works

The WiFi companion firmware accepts **exactly one TCP client at a time** and drops the
existing client when a new one connects. To avoid the action and trigger nodes kicking
each other off the radio, all nodes for a given device share **one connection per
`host:port`**, reference-counted, with a serialized command queue and push fan-out
(`nodes/shared/ConnectionManager.ts`).

`meshcore.js` is **bundled into the build artifact** (esbuild), so the published package
has no runtime dependencies and pulls in no native `serialport`. Commands missing from
`meshcore.js` are added by a small subclass (`scripts/vendor/meshcore-extended.mjs`),
grounded in the firmware's command/response layouts.

> ⚠️ The extended ("gap") commands and their response parsing were verified against the
> MeshCore firmware source (`MyMesh.cpp`), **not yet against a live device**. Validate
> them on real hardware before relying on them (see the checklist below).

## Development

This repo bundles Node 22 under `node-v22.22.3-linux-x64/`. Put it on your `PATH`:

```bash
export PATH="$PWD/../node-v22.22.3-linux-x64/bin:$PATH"
npm install          # eslint is pinned to 9.29.0 to match @n8n/node-cli's peer
npm run build        # tsc (via n8n-node) + esbuild bundles meshcore.js into dist
npm run lint
npm test             # node:test; pretest builds, tests run against dist/
```

To try it in a local n8n: `npm run build && npm link`, then in `~/.n8n/custom`
run `npm link n8n-nodes-meshcore`, and restart n8n.

## Manual device test checklist

Run once against real hardware to validate the device-dependent paths:

1. **Connectivity** — add credentials, click **Test** (should report connected).
2. **Round-trip** — Device → *Get Self Info* (exercises the AppStart handshake).
3. **Send** — Message → *Send Direct Message* to a known contact (expects a SENT reply).
4. **Receive** — MeshCore Trigger → *New Message*; send the device a message and confirm
   the workflow fires.
5. **Lists** — Contact → *Get Contacts*; Channel → *Get Many*.
6. **Diagnostics** — Diagnostics → *Get Status* / *Trace Path* (binary-request path).
7. **Gap-command responses (least-verified)** — confirm these parse correctly:
   *Get Custom Variables*, *Get Tuning Parameters*, *Get Auto Add Config*,
   *Get Allowed Repeat Frequencies*, *Get Default Flood Scope*, *Get Advert Path*,
   *Get by Key*.
8. **Reconnect** — power-cycle/disconnect the device and confirm a running trigger
   reconnects and resumes.

## License

MIT
