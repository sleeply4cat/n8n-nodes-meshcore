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
| **Message** | Send Direct Message (toggle: Reliable Delivery), Send Direct Message and Await Reply (toggle: Reliable Delivery), Send Channel Message, Await Delivery, Get Waiting Messages, Sync Next Message |
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

### Channel message fields

The firmware formats channel (group) messages as `"<sender>: <text>"`. For the
`channelMessage` event the trigger splits that into separate fields so you don't have to
parse it in the workflow:

- `author` — the sender's node name (empty if the message has no `"<name>: "` prefix)
- `text` — the message body with the prefix removed
- `rawText` — the original combined string, unchanged

The split is on the first `": "`, so a `": "` inside the message body stays in `text`.
Direct messages are emitted unchanged.

### Routing fields on message events

Both `directMessage` and `channelMessage` carry the firmware's `pathLen` byte. It's
a packed value: `0xFF` is the sentinel for "delivered along a known route" (direct);
otherwise the low 6 bits are the hop count and the high 2 bits encode the path-hash
size (1–4 bytes per hop). The trigger decodes this into friendlier fields and **drops
the raw `pathLen`** from the output:

- `via` — `"direct"` if the message arrived along the stored route, `"flood"` otherwise.
- `hops` — `0` for direct, the actual hop count for flood.
- `pathHashSize` — only on flood, the bytes-per-hop hash size (1–4); useful for routing
  debug.

### Note on the New Advert event

The `advert` event (auto-add mode, push 0x80) carries only the sender's `publicKey` —
that is all the firmware emits in this push (the contact record itself is updated inside
the device). Subscribe to **New Advert (Manual Add)** if you need the full record
(`advName`, `advLat`, `advLon`, `outPath`, etc.); that push is only fired when the device
is in manual-add mode.

## Common patterns

These combined operations turn the "send now, result arrives later" protocol flows into a
single synchronous node, so you don't need a second trigger plus shared state:

- **Reliable send** — *Message → Send Direct Message* with the **Reliable Delivery**
  toggle on. Mirrors the MeshCore app's retry policy: up to **Path Retries** attempts
  along the stored route, then a forced `resetPath` and up to **Flood Retries** attempts
  via flood routing. Each attempt has its own **Ack Timeout (Ms)** — retries fire
  immediately on timeout, no backoff. Returns `delivered: true`, `phase: "path" | "flood"`,
  `attempts`, `ackCode`, `roundTrip` on success. On final non-delivery the node **throws**
  so it shows as a red error (use n8n's *Continue On Fail* if you want to branch on the
  failure as data). The **Force Flood** toggle skips the path phase after an upfront
  route reset. Toggle off = fire-and-forget: one send, return `ackCode`, no waiting.
- **Request / reply** — *Message → Send Direct Message and Await Reply* sends a message and
  waits for the contact's next reply (or times out). Its own **Reliable Delivery** toggle
  runs the same retry+ack pipeline before starting the reply wait — useful for ask-a-node
  chatbots where the question must land first. Toggle off = one send + wait for reply.
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

The quickest way to try it in a local n8n with a ready-to-use account is
`scripts/dev-n8n.sh`: it builds the plugin, launches n8n with the node loaded
(`N8N_CUSTOM_EXTENSIONS`), and provisions a known owner via env so there's no setup
screen — login `test@meshcore.local` / `Meshcore123` at <http://localhost:5678> (Ctrl+C
to stop). `N8N_USER_MANAGEMENT_DISABLED` was removed from n8n, so a pre-provisioned owner
(`N8N_INSTANCE_OWNER_MANAGED_BY_ENV` + a bcrypt password hash) is the supported way to get
a fixed dev login.

Manual alternative: `npm run build && npm link`, then in `~/.n8n/custom` run
`npm link n8n-nodes-meshcore`, and restart n8n.

## Manual device test checklist

Run once against real hardware to validate the device-dependent paths:

1. **Connectivity** — add credentials, click **Test** (should report connected).
2. **Round-trip** — Device → *Get Self Info* (exercises the AppStart handshake).
3. **Send** — Message → *Send Direct Message* to a known contact (expects a SENT reply).
4. **Receive** — MeshCore Trigger → *New Message*; send the device a message and confirm
   the workflow fires. For channel messages, `scripts/device-listen-channel.mjs <host>
   <port>` prints the parsed `author` / `text` / `rawText` fields.
5. **Lists** — Contact → *Get Contacts*; Channel → *Get Many*.
6. **Diagnostics** — Diagnostics → *Get Status* / *Trace Path* (binary-request path).
7. **Gap-command responses (least-verified)** — confirm these parse correctly:
   *Get Custom Variables*, *Get Tuning Parameters*, *Get Auto Add Config*,
   *Get Allowed Repeat Frequencies*, *Get Default Flood Scope*, *Get Advert Path*,
   *Get by Key*.
8. **Reconnect** — power-cycle/disconnect the device and confirm a running trigger
   reconnects and resumes.

## Breaking changes (0.3.0)

Field-name unification — workflows that read these specific keys from node output need
to be updated:

- Output key `pubKeyPrefix` is now `publicKeyPrefix` on every event/operation that emits
  it (direct message, telemetry response, status response, login success, path discovery,
  trace data, …). The 6-byte hex content is unchanged.
- UI parameter `Public Key Prefix Length` on *Diagnostics → Get Neighbours* — the
  parameter name was renamed from `pubKeyPrefixLength` to `publicKeyPrefixLength`
  internally; the displayed name is unchanged. Existing nodes need to be re-opened so
  n8n re-reads the default; node behavior is otherwise identical.
- UI parameter `Extra Timeout (Ms)` on *Diagnostics → Trace Path* and *Send Binary
  Request* — parameter name renamed from `extraTimeoutMillis` to `extraTimeoutMs`,
  matching the suffix used by all other timeout fields. Same re-open caveat.

*Reliable send* defaults: the new `pathRetries` (2) and `floodRetries` (2) mean a
*Send Direct Message and Await Delivery* node that previously resolved `delivered: false`
on timeout will now retry up to four times and then **throw** on final non-delivery (red
status). Set both to 0 to restore single-attempt behavior, or use n8n's *Continue On
Fail* to keep the failure as data.

## License

MIT
