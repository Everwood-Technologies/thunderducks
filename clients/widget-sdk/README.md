# Thunderducks widget SDK

iframe + postMessage JS SDK (Wave F). **Deny-by-default** permissions; **no E2EE key access**.

## Model

```
Host page (has node RPC / keys)
  └── iframe widget (untrusted)
        postMessage channel: td-widget-v1
```

Widgets may only call methods matching granted `WidgetPermission`s:
- `room.send` / `room.read` / `room.list`
- `device.public_id`

Hard-denied forever: `keys.*`, signing keys, Megolm/Olm export, private device keys.

## Usage

```ts
import { WidgetHost } from "@thunderducks/widget-sdk";

const host = new WidgetHost({
  widgetId: "honk-counter",
  permissions: ["room.send", "room.read"],
  allowedOrigin: "null", // iframe srcdoc
  api: {
    send: (roomId, text) => rpc.send(roomId, text),
    listMessages: async (roomId) => (await rpc.listMessages(roomId)).messages,
  },
});
host.attach(iframe.contentWindow!);
```

```ts
// inside iframe
import { WidgetGuest } from "@thunderducks/widget-sdk";
const g = new WidgetGuest("honk-counter");
g.announceReady();
await g.request("room.send", { roomId, text: "honk" });
```

## Test

```bash
npm install
npm test
```
