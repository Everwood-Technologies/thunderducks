/** Minimal localhost RPC client for td-node (Wave E2 + multi-node). */

export type Status = {
  device_id: string;
  verifying_key: string;
  event_count: number;
  rooms: string[];
  linked_devices: string[];
  peers: { name: string; uri: string; rpc?: string | null; p2p?: string | null }[];
  passkey_credentials?: number;
  e2ee_default?: boolean;
  p2p_uri?: string | null;
  claimed?: boolean;
  display_name?: string | null;
  claimed_at_ms?: number | null;
  pair_tokens_active?: number;
};

export type ClaimStatus = {
  claimed: boolean;
  display_name?: string | null;
  claimed_at_ms?: number | null;
  device_id: string;
  rpc_base?: string | null;
  p2p_uri?: string | null;
};

export type ClaimResponse = {
  ok: boolean;
  claimed: boolean;
  display_name: string;
  recovery_code: string;
  device_id: string;
  claimed_at_ms: number;
};

export type PairCreateResponse = {
  ok: boolean;
  token: string;
  label: string;
  expires_in_secs: number;
  pair_path: string;
  rpc_base?: string | null;
};

export type PairRedeemResponse = {
  ok: boolean;
  paired: boolean;
  label: string;
  pond_name?: string | null;
  device_id: string;
  rpc_base?: string | null;
  p2p_uri?: string | null;
};

export type CreateRoomResponse = { room_id: string; event_id: string };
export type SendResponse = {
  event_id: string;
  ts_ms: number;
  fanout_ok?: number;
  fanout_peers?: number;
  fanout_errors?: string[];
};
export type MessageView = {
  event_id: string;
  author: string;
  ts_ms: number;
  text: string;
};
export type MessagesResponse = { room_id: string; messages: MessageView[] };
export type WaitMessagesResponse = MessagesResponse & {
  count: number;
  changed: boolean;
  timed_out: boolean;
};

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

  /** Long-poll until message count changes or timeout (server clamps 250–30000ms). */
  async waitMessages(
    roomId: string,
    sinceCount: number,
    timeoutMs = 15000,
    signal?: AbortSignal,
  ): Promise<WaitMessagesResponse> {
    const r = await fetch(this.url("/v1/messages/wait"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        room_id: roomId,
        since_count: sinceCount,
        timeout_ms: timeoutMs,
      }),
      signal,
    });
    if (!r.ok) throw new Error(`waitMessages HTTP ${r.status}`);
    return (await r.json()) as WaitMessagesResponse;
  }

  /** SSE URL for true push live updates (EventSource). */
  messagesStreamUrl(roomId: string): string {
    const u = new URL(this.url("/v1/messages/stream"));
    u.searchParams.set("room_id", roomId);
    return u.toString();
  }

  /**
   * Open SSE stream for room messages.
   * Returns a closer. Prefer over long-poll when EventSource is available.
   */
  openMessagesStream(
    roomId: string,
    handlers: {
      onSnapshot?: (msgs: MessageView[], count: number) => void;
      onMessages?: (msgs: MessageView[], count: number) => void;
      onError?: (err: Event) => void;
    },
  ): { close: () => void } {
    const es = new EventSource(this.messagesStreamUrl(roomId));
    const parse = (raw: string) => {
      const j = JSON.parse(raw) as {
        messages?: MessageView[];
        count?: number;
      };
      return {
        messages: j.messages ?? [],
        count: j.count ?? (j.messages?.length ?? 0),
      };
    };
    es.addEventListener("snapshot", (ev) => {
      try {
        const p = parse((ev as MessageEvent).data);
        handlers.onSnapshot?.(p.messages, p.count);
      } catch {
        /* ignore */
      }
    });
    es.addEventListener("messages", (ev) => {
      try {
        const p = parse((ev as MessageEvent).data);
        handlers.onMessages?.(p.messages, p.count);
      } catch {
        /* ignore */
      }
    });
    es.onerror = (err) => {
      handlers.onError?.(err);
    };
    return {
      close: () => {
        es.close();
      },
    };
  }

  async passkeyRegisterBegin(
    userName = "thunderducks-user",
    displayName = "Thunderducks User",
  ): Promise<{
    challenge: string;
    rp: { id: string; name: string };
    user: { id: string; name: string; display_name: string };
  }> {
    const r = await fetch(this.url("/v1/passkeys/register/begin"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user_name: userName, display_name: displayName }),
    });
    if (!r.ok) throw new Error(`passkey begin HTTP ${r.status}`);
    return (await r.json()) as {
      challenge: string;
      rp: { id: string; name: string };
      user: { id: string; name: string; display_name: string };
    };
  }

  async passkeyList(): Promise<{ credentials: { credential_id: string; label: string }[] }> {
    const r = await fetch(this.url("/v1/passkeys"));
    if (!r.ok) throw new Error(`passkey list HTTP ${r.status}`);
    return (await r.json()) as { credentials: { credential_id: string; label: string }[] };
  }

  async syncPeer(
    peerRpc: string,
    roomId: string,
  ): Promise<{ ok: boolean; accepted_from_peer: number; pushed_accepted: number }> {
    const r = await fetch(this.url("/v1/sync/peer"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ peer_rpc: peerRpc, room_id: roomId }),
    });
    if (!r.ok) throw new Error(`syncPeer HTTP ${r.status}`);
    return (await r.json()) as {
      ok: boolean;
      accepted_from_peer: number;
      pushed_accepted: number;
    };
  }

  async shareSession(peerRpc: string, roomId: string): Promise<void> {
    const r = await fetch(this.url("/v1/e2ee/share-session"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ peer_rpc: peerRpc, room_id: roomId }),
    });
    if (!r.ok) throw new Error(`shareSession HTTP ${r.status}`);
  }

  async addPeer(
    name: string,
    uri: string,
    opts?: { rpc?: string; p2p?: string },
  ): Promise<void> {
    const r = await fetch(this.url("/v1/peers"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name, uri, rpc: opts?.rpc, p2p: opts?.p2p }),
    });
    if (!r.ok) throw new Error(`addPeer HTTP ${r.status}`);
  }

  async claimStatus(): Promise<ClaimStatus> {
    const r = await fetch(this.url("/v1/claim"));
    if (!r.ok) throw new Error(`claim status HTTP ${r.status}`);
    return (await r.json()) as ClaimStatus;
  }

  async claim(displayName: string, recoveryCode?: string): Promise<ClaimResponse> {
    const body: Record<string, string> = { display_name: displayName };
    if (recoveryCode && recoveryCode.trim()) body.recovery_code = recoveryCode.trim();
    const r = await fetch(this.url("/v1/claim"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const err = await r.text();
      throw new Error(`claim HTTP ${r.status}: ${err}`);
    }
    return (await r.json()) as ClaimResponse;
  }

  async pairCreate(label = "device", ttlSecs = 600): Promise<PairCreateResponse> {
    const r = await fetch(this.url("/v1/pair"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ label, ttl_secs: ttlSecs }),
    });
    if (!r.ok) {
      const err = await r.text();
      throw new Error(`pair create HTTP ${r.status}: ${err}`);
    }
    return (await r.json()) as PairCreateResponse;
  }

  async pairRedeem(token: string, deviceLabel?: string): Promise<PairRedeemResponse> {
    const r = await fetch(this.url("/v1/pair/redeem"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, device_label: deviceLabel }),
    });
    if (!r.ok) {
      const err = await r.text();
      throw new Error(`pair redeem HTTP ${r.status}: ${err}`);
    }
    return (await r.json()) as PairRedeemResponse;
  }

  async pairList(): Promise<{ claimed: boolean; tokens: unknown[] }> {
    const r = await fetch(this.url("/v1/pair"));
    if (!r.ok) throw new Error(`pair list HTTP ${r.status}`);
    return (await r.json()) as { claimed: boolean; tokens: unknown[] };
  }
}

function mountClaimWizard(root: HTMLElement, client: TdRpcClient): void {
  root.innerHTML = `
    <h1>Thunderducks Pond</h1>
    <p style="color:#444">First-run setup — claim this node. Save the recovery code offline.</p>
    <p style="font-size:0.9rem">RPC <code>${client.baseUrl}</code></p>
    <label>Pond name<br/><input id="name" value="Home Pond" style="min-width:16rem" /></label>
    <div style="margin-top:0.75rem">
      <button id="claim">Claim Pond</button>
    </div>
    <pre id="out" style="margin-top:1rem"></pre>
  `;
  const out = root.querySelector("#out") as HTMLPreElement;
  root.querySelector("#claim")!.addEventListener("click", () => {
    const name = (root.querySelector("#name") as HTMLInputElement).value.trim() || "Home Pond";
    void (async () => {
      try {
        const res = await client.claim(name);
        out.textContent =
          `Claimed "${res.display_name}"\n\nRECOVERY CODE (save now — shown once):\n${res.recovery_code}\n\ndevice ${res.device_id.slice(0, 16)}…`;
        const btn = document.createElement("button");
        btn.textContent = "Continue to chat";
        btn.style.marginTop = "0.75rem";
        btn.onclick = () => mountChatUi(root, client);
        root.appendChild(btn);
      } catch (e) {
        out.textContent = `claim failed: ${(e as Error).message}`;
      }
    })();
  });
}

function mountPairRedeem(root: HTMLElement, client: TdRpcClient, token: string): void {
  root.innerHTML = `
    <h1>Pair with Pond</h1>
    <p>Redeeming invite on <code>${client.baseUrl}</code></p>
    <label>Device label<br/><input id="label" value="Phone" style="min-width:12rem" /></label>
    <div style="margin-top:0.75rem">
      <button id="go">Pair</button>
    </div>
    <pre id="out" style="margin-top:1rem"></pre>
  `;
  const out = root.querySelector("#out") as HTMLPreElement;
  root.querySelector("#go")!.addEventListener("click", () => {
    const label = (root.querySelector("#label") as HTMLInputElement).value.trim() || "Phone";
    void (async () => {
      try {
        const res = await client.pairRedeem(token, label);
        out.textContent = `Paired with "${res.pond_name ?? "Pond"}" as ${res.label}\nnode ${res.device_id.slice(0, 16)}…\np2p ${res.p2p_uri ?? "—"}`;
        const btn = document.createElement("button");
        btn.textContent = "Open chat";
        btn.style.marginTop = "0.75rem";
        btn.onclick = () => mountChatUi(root, client);
        root.appendChild(btn);
      } catch (e) {
        out.textContent = `pair failed: ${(e as Error).message}`;
      }
    })();
  });
}

/** Chat UI (post-claim). */
export function mountChatUi(root: HTMLElement, client: TdRpcClient): void {
  const params = new URLSearchParams(location.search);
  const presetRoom = params.get("room");
  const nodeName = params.get("name") || "node";
  const peerParam = params.get("peers") || "";
  const liveOff = params.get("live") === "0";
  root.innerHTML = `
    <h1>Thunderducks <small style="font-weight:normal;color:#666">${nodeName}</small></h1>
    <p id="status">connecting…</p>
    <p id="live" style="font-size:0.85rem;color:#555">live: off</p>
    <p style="font-size:0.9rem;color:#444">
      RPC <code id="rpcurl"></code>
      · room <input id="roomId" placeholder="room hex" style="min-width:18rem" />
    </p>
    <div>
      <button id="link">Link secondary</button>
      <button id="pair">Pair device</button>
      <button id="room">Create room</button>
      <button id="sync">Sync peers (manual)</button>
      <button id="refresh">Refresh msgs</button>
      <button id="liveToggle">Live on/off</button>
    </div>
    <div style="margin-top:0.5rem">
      <input id="msg" placeholder="message" />
      <button id="send">Send</button>
    </div>
    <p style="font-size:0.85rem;color:#666">Peers (RPC): <input id="peers" style="min-width:22rem" placeholder="http://127.0.0.1:8789,http://127.0.0.1:8790" /></p>
    <pre id="log"></pre>
  `;
  (root.querySelector("#rpcurl") as HTMLElement).textContent = client.baseUrl;
  const roomInput = root.querySelector("#roomId") as HTMLInputElement;
  const peersInput = root.querySelector("#peers") as HTMLInputElement;
  const liveEl = root.querySelector("#live") as HTMLElement;
  if (presetRoom) roomInput.value = presetRoom;
  if (peerParam) peersInput.value = peerParam;
  else {
    const u = client.baseUrl.replace(/\/$/, "");
    const defaults = [
      "http://127.0.0.1:8788",
      "http://127.0.0.1:8789",
      "http://127.0.0.1:8790",
    ].filter((p) => p !== u);
    peersInput.value = defaults.join(",");
  }
  const log = (s: string) => {
    const el = root.querySelector("#log") as HTMLPreElement;
    el.textContent = `${s}\n${el.textContent ?? ""}`;
  };
  const peerList = () =>
    peersInput.value
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

  let liveEnabled = !liveOff;
  let sinceCount = 0;
  let lastRender = "";
  let waitAbort: AbortController | null = null;
  let sseClose: (() => void) | null = null;
  let liveGen = 0;
  const preferSse =
    typeof EventSource !== "undefined" && params.get("live") !== "poll";

  const setLiveLabel = (extra = "") => {
    const mode = preferSse ? "sse" : "long-poll";
    liveEl.textContent = liveEnabled
      ? `live: on (${mode}) count=${sinceCount}${extra ? " · " + extra : ""}`
      : `live: off${extra ? " · " + extra : ""}`;
  };

  const renderMessages = (msgs: MessageView[], note?: string) => {
    const body = JSON.stringify(msgs, null, 2);
    if (body !== lastRender) {
      lastRender = body;
      log(note ? `${note}\n${body}` : body);
    }
    sinceCount = msgs.length;
    setLiveLabel();
  };

  const ensurePeers = async () => {
    let i = 0;
    for (const peer of peerList()) {
      i += 1;
      try {
        await client.addPeer(`peer${i}`, peer, { rpc: peer });
      } catch {
        /* already added */
      }
    }
  };

  const pullOnce = async (roomId: string) => {
    const msgs = await client.listMessages(roomId);
    renderMessages(msgs.messages);
  };

  const stopLive = () => {
    liveGen += 1;
    waitAbort?.abort();
    waitAbort = null;
    sseClose?.();
    sseClose = null;
  };

  const peerSyncLoop = async (gen: number, roomId: string) => {
    // Background peer sync so fan-in from other nodes reaches local DAG + SSE.
    while (liveEnabled && gen === liveGen) {
      const room = roomInput.value.trim() || roomId;
      for (const peer of peerList()) {
        try {
          await client.syncPeer(peer, room);
        } catch {
          /* ignore */
        }
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
  };

  const startLive = () => {
    stopLive();
    if (!liveEnabled) {
      setLiveLabel();
      return;
    }
    const roomId = roomInput.value.trim();
    if (!roomId) {
      setLiveLabel("set room id");
      return;
    }
    const gen = liveGen;
    void (async () => {
      await ensurePeers().catch(() => undefined);
      for (const peer of peerList()) {
        try {
          await client.syncPeer(peer, roomId);
        } catch {
          /* ignore */
        }
      }
      try {
        await pullOnce(roomId);
      } catch (e) {
        setLiveLabel(`list fail: ${(e as Error).message}`);
      }
      if (!liveEnabled || gen !== liveGen) return;

      // True SSE path (default when EventSource exists).
      if (preferSse) {
        setLiveLabel("connecting");
        const handle = client.openMessagesStream(roomId, {
          onSnapshot: (msgs, count) => {
            if (gen !== liveGen) return;
            renderMessages(msgs, "sse snapshot");
            sinceCount = count;
            setLiveLabel();
          },
          onMessages: (msgs, count) => {
            if (gen !== liveGen) return;
            renderMessages(msgs, "sse update");
            sinceCount = count;
            setLiveLabel();
          },
          onError: () => {
            if (gen !== liveGen) return;
            setLiveLabel("sse reconnecting…");
          },
        });
        sseClose = handle.close;
        void peerSyncLoop(gen, roomId);
        return;
      }

      // Long-poll fallback (?live=poll or no EventSource).
      while (liveEnabled && gen === liveGen) {
        const room = roomInput.value.trim();
        if (!room) {
          setLiveLabel("set room id");
          await new Promise((r) => setTimeout(r, 1000));
          continue;
        }
        for (const peer of peerList()) {
          try {
            await client.syncPeer(peer, room);
          } catch {
            /* ignore */
          }
        }
        waitAbort = new AbortController();
        try {
          const w = await client.waitMessages(room, sinceCount, 12000, waitAbort.signal);
          if (gen !== liveGen) return;
          if (w.changed || w.messages.length !== sinceCount) {
            renderMessages(w.messages, w.changed ? "live update" : undefined);
          } else {
            sinceCount = w.count;
            setLiveLabel(w.timed_out ? "idle" : "");
          }
        } catch (e) {
          if ((e as Error).name === "AbortError") return;
          setLiveLabel(`wait fail: ${(e as Error).message}`);
          await new Promise((r) => setTimeout(r, 1500));
        }
      }
    })();
  };

  void client.status().then((st) => {
    const pond = st.display_name ? ` · ${st.display_name}` : "";
    (root.querySelector("#status") as HTMLElement).textContent =
      `device ${st.device_id.slice(0, 12)}…${pond} events=${st.event_count} e2ee=${st.e2ee_default ?? false} claimed=${st.claimed ?? false} p2p=${st.p2p_uri ?? "—"}`;
  });

  root.querySelector("#link")!.addEventListener("click", () => {
    void client
      .linkSecondary()
      .then((r) => log(`linked secondary ${r.secondary_device.slice(0, 12)}…`));
  });
  root.querySelector("#pair")!.addEventListener("click", () => {
    void (async () => {
      try {
        const p = await client.pairCreate(nodeName || "device", 600);
        const link = `${location.origin}${location.pathname}?rpc=${encodeURIComponent(client.baseUrl)}&pair=${p.token}`;
        log(`pair token (10m): ${p.token}\nopen on other device:\n${link}`);
        try {
          await navigator.clipboard.writeText(link);
          log("pair link copied to clipboard");
        } catch {
          /* ignore */
        }
      } catch (e) {
        log(`pair fail: ${(e as Error).message}`);
      }
    })();
  });
  root.querySelector("#room")!.addEventListener("click", () => {
    void client.createRoom(`web-${nodeName}`).then((r) => {
      roomInput.value = r.room_id;
      log(`room ${r.room_id.slice(0, 12)}…`);
      if (liveEnabled) startLive();
    });
  });
  root.querySelector("#sync")!.addEventListener("click", () => {
    const roomId = roomInput.value.trim();
    if (!roomId) {
      log("set room id first");
      return;
    }
    void (async () => {
      for (const peer of peerList()) {
        try {
          const s = await client.syncPeer(peer, roomId);
          log(`sync ${peer}: from_peer=${s.accepted_from_peer} pushed=${s.pushed_accepted}`);
          await client.shareSession(peer, roomId).catch(() => undefined);
        } catch (e) {
          log(`sync fail ${peer}: ${(e as Error).message}`);
        }
      }
      const msgs = await client.listMessages(roomId);
      renderMessages(msgs.messages, "manual sync");
    })();
  });
  root.querySelector("#refresh")!.addEventListener("click", () => {
    const roomId = roomInput.value.trim();
    if (!roomId) return;
    void pullOnce(roomId).catch((e) => log(`refresh fail: ${(e as Error).message}`));
  });
  root.querySelector("#liveToggle")!.addEventListener("click", () => {
    liveEnabled = !liveEnabled;
    if (liveEnabled) startLive();
    else {
      stopLive();
      setLiveLabel();
    }
  });
  roomInput.addEventListener("change", () => {
    if (liveEnabled) startLive();
  });
  root.querySelector("#send")!.addEventListener("click", () => {
    const text = (root.querySelector("#msg") as HTMLInputElement).value || "honk";
    const roomId = roomInput.value.trim();
    if (!roomId) {
      log("set room id first");
      return;
    }
    void (async () => {
      await ensurePeers();
      const s = await client.send(roomId, text);
      const fo = s.fanout_ok ?? 0;
      const fp = s.fanout_peers ?? 0;
      log(`sent ${s.event_id.slice(0, 12)}… fanout ${fo}/${fp}`);
      if (s.fanout_errors?.length) log(`fanout errs: ${s.fanout_errors.join("; ")}`);
      const msgs = await client.listMessages(roomId);
      renderMessages(msgs.messages);
      if (liveEnabled) startLive();
    })();
  });

  setLiveLabel();
  if (liveEnabled && roomInput.value.trim()) startLive();
}

/** In-browser UI bootstrap when loaded as a page script. */
export function mountMinimalUi(root: HTMLElement, client: TdRpcClient): void {
  const params = new URLSearchParams(location.search);
  const pair = params.get("pair");
  if (pair) {
    mountPairRedeem(root, client, pair);
    return;
  }
  root.innerHTML = `<p>loading Pond…</p>`;
  void (async () => {
    try {
      const st = await client.claimStatus();
      if (!st.claimed) {
        mountClaimWizard(root, client);
      } else {
        mountChatUi(root, client);
      }
    } catch (e) {
      root.innerHTML = "";
      const note = document.createElement("p");
      note.style.color = "#a00";
      note.textContent = `claim status unavailable: ${(e as Error).message}`;
      root.appendChild(note);
      mountChatUi(root, client);
    }
  })();
}
