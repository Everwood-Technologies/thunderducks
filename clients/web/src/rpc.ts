/** Minimal localhost RPC client for td-node (Wave E2). */

export type Status = {
  device_id: string;
  verifying_key: string;
  event_count: number;
  rooms: string[];
  linked_devices: string[];
  peers: { name: string; uri: string }[];
};

export type CreateRoomResponse = { room_id: string; event_id: string };
export type SendResponse = { event_id: string; ts_ms: number };
export type MessageView = {
  event_id: string;
  author: string;
  ts_ms: number;
  text: string;
};
export type MessagesResponse = { room_id: string; messages: MessageView[] };

export class TdRpcClient {
  constructor(public baseUrl: string) {}

  private url(path: string): string {
    return `${this.baseUrl.replace(/\/$/, "")}${path}`;
  }

  async health(): Promise<boolean> {
    const r = await fetch(this.url("/health"));
    if (!r.ok) return false;
    const j = (await r.json()) as { ok?: boolean };
    return j.ok === true;
  }

  async status(): Promise<Status> {
    const r = await fetch(this.url("/v1/status"));
    if (!r.ok) throw new Error(`status HTTP ${r.status}`);
    return (await r.json()) as Status;
  }

  async linkSecondary(): Promise<{ linked: boolean; secondary_device: string }> {
    const r = await fetch(this.url("/v1/devices/link-secondary"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!r.ok) throw new Error(`link HTTP ${r.status}`);
    return (await r.json()) as { linked: boolean; secondary_device: string };
  }

  async createRoom(name: string): Promise<CreateRoomResponse> {
    const r = await fetch(this.url("/v1/rooms"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name }),
    });
    if (!r.ok) throw new Error(`createRoom HTTP ${r.status}`);
    return (await r.json()) as CreateRoomResponse;
  }

  async send(roomId: string, text: string): Promise<SendResponse> {
    const r = await fetch(this.url("/v1/messages"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ room_id: roomId, text }),
    });
    if (!r.ok) throw new Error(`send HTTP ${r.status}`);
    return (await r.json()) as SendResponse;
  }

  async listMessages(roomId: string): Promise<MessagesResponse> {
    const r = await fetch(this.url("/v1/messages/list"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ room_id: roomId }),
    });
    if (!r.ok) throw new Error(`listMessages HTTP ${r.status}`);
    return (await r.json()) as MessagesResponse;
  }

  async addPeer(name: string, uri: string): Promise<void> {
    const r = await fetch(this.url("/v1/peers"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name, uri }),
    });
    if (!r.ok) throw new Error(`addPeer HTTP ${r.status}`);
  }
}

/** In-browser UI bootstrap when loaded as a page script. */
export function mountMinimalUi(root: HTMLElement, client: TdRpcClient): void {
  root.innerHTML = `
    <h1>Thunderducks</h1>
    <p id="status">connecting…</p>
    <button id="link">Link secondary device</button>
    <button id="room">Create room</button>
    <input id="msg" placeholder="message" />
    <button id="send">Send</button>
    <pre id="log"></pre>
  `;
  const log = (s: string) => {
    const el = root.querySelector("#log") as HTMLPreElement;
    el.textContent = `${s}\n${el.textContent ?? ""}`;
  };
  let roomId: string | null = null;
  void client.status().then((st) => {
    (root.querySelector("#status") as HTMLElement).textContent =
      `device ${st.device_id.slice(0, 12)}… events=${st.event_count}`;
  });
  root.querySelector("#link")!.addEventListener("click", () => {
    void client.linkSecondary().then((r) => log(`linked secondary ${r.secondary_device.slice(0, 12)}…`));
  });
  root.querySelector("#room")!.addEventListener("click", () => {
    void client.createRoom("web-pond").then((r) => {
      roomId = r.room_id;
      log(`room ${roomId.slice(0, 12)}…`);
    });
  });
  root.querySelector("#send")!.addEventListener("click", () => {
    const text = (root.querySelector("#msg") as HTMLInputElement).value || "honk";
    if (!roomId) {
      log("create a room first");
      return;
    }
    void client.send(roomId, text).then(async (s) => {
      log(`sent ${s.event_id.slice(0, 12)}…`);
      const msgs = await client.listMessages(roomId!);
      log(JSON.stringify(msgs.messages, null, 2));
    });
  });
}
