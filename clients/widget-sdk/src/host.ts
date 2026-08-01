/**
 * Host-side widget bridge.
 * Deny-by-default: only explicitly granted WidgetPermission methods run.
 * Key material is never exposed.
 */

import {
  FORBIDDEN_PERMISSIONS,
  TD_WIDGET_CHANNEL,
  type HostToWidget,
  type WidgetPermission,
  type WidgetToHost,
  isWidgetMessage,
} from "./protocol.js";

export type HostRoomApi = {
  send?: (roomId: string, text: string) => Promise<{ event_id: string }>;
  listMessages?: (roomId: string) => Promise<{ text: string; event_id: string }[]>;
  listRooms?: () => Promise<string[]>;
  publicDeviceId?: () => string;
};

export type WidgetHostOptions = {
  widgetId: string;
  /** Permissions granted to this widget instance. */
  permissions: WidgetPermission[];
  /** Origin expected from the iframe (use "*" only in local demos). */
  allowedOrigin: string;
  api: HostRoomApi;
  /** Optional sink for audit log lines. */
  onAudit?: (line: string) => void;
};

export class WidgetHost {
  readonly widgetId: string;
  readonly permissions: Set<WidgetPermission>;
  private readonly allowedOrigin: string;
  private readonly api: HostRoomApi;
  private readonly onAudit?: (line: string) => void;
  private target: Window | null = null;
  private bound = false;

  constructor(opts: WidgetHostOptions) {
    this.widgetId = opts.widgetId;
    this.permissions = new Set(opts.permissions);
    this.allowedOrigin = opts.allowedOrigin;
    this.api = opts.api;
    this.onAudit = opts.onAudit;
  }

  /** Attach to iframe contentWindow and start listening. */
  attach(iframeWindow: Window): void {
    this.target = iframeWindow;
    if (!this.bound) {
      globalThis.addEventListener("message", this.onMessage);
      this.bound = true;
    }
    this.post({
      channel: TD_WIDGET_CHANNEL,
      type: "hello",
      widgetId: this.widgetId,
      granted: [...this.permissions],
    });
  }

  detach(): void {
    if (this.bound) {
      globalThis.removeEventListener("message", this.onMessage);
      this.bound = false;
    }
    this.target = null;
  }

  private audit(line: string): void {
    this.onAudit?.(line);
  }

  private post(msg: HostToWidget): void {
    if (!this.target) return;
    const origin = this.allowedOrigin === "*" ? "*" : this.allowedOrigin;
    this.target.postMessage(msg, origin);
  }

  private onMessage = (ev: MessageEvent): void => {
    if (this.allowedOrigin !== "*" && ev.origin !== this.allowedOrigin) {
      this.audit(`drop: bad origin ${ev.origin}`);
      return;
    }
    if (!isWidgetMessage(ev.data)) return;
    const msg = ev.data as WidgetToHost;
    if (msg.type === "ready") {
      this.audit(`ready widget=${msg.widgetId}`);
      return;
    }
    if (msg.type !== "request") return;
    void this.handleRequest(msg);
  };

  private async handleRequest(msg: Extract<WidgetToHost, { type: "request" }>): Promise<void> {
    const { id, method, params } = msg;

    // Hard deny key-related methods regardless of grants.
    if (
      FORBIDDEN_PERMISSIONS.includes(method as (typeof FORBIDDEN_PERMISSIONS)[number]) ||
      method.startsWith("keys.") ||
      method.includes("private") ||
      method.includes("signing")
    ) {
      this.audit(`DENY forbidden method=${method}`);
      this.post({
        channel: TD_WIDGET_CHANNEL,
        type: "result",
        id,
        ok: false,
        error: `permission denied: ${method}`,
      });
      return;
    }

    try {
      const data = await this.dispatch(method, params ?? {});
      this.post({ channel: TD_WIDGET_CHANNEL, type: "result", id, ok: true, data });
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      this.audit(`error method=${method} ${error}`);
      this.post({ channel: TD_WIDGET_CHANNEL, type: "result", id, ok: false, error });
    }
  }

  private require(perm: WidgetPermission): void {
    if (!this.permissions.has(perm)) {
      throw new Error(`missing permission: ${perm}`);
    }
  }

  private async dispatch(method: string, params: Record<string, unknown>): Promise<unknown> {
    switch (method) {
      case "room.send": {
        this.require("room.send");
        const roomId = String(params.roomId ?? "");
        const text = String(params.text ?? "");
        if (!this.api.send) throw new Error("send api unavailable");
        return this.api.send(roomId, text);
      }
      case "room.read": {
        this.require("room.read");
        const roomId = String(params.roomId ?? "");
        if (!this.api.listMessages) throw new Error("listMessages api unavailable");
        return this.api.listMessages(roomId);
      }
      case "room.list": {
        this.require("room.list");
        if (!this.api.listRooms) throw new Error("listRooms api unavailable");
        return this.api.listRooms();
      }
      case "device.public_id": {
        this.require("device.public_id");
        if (!this.api.publicDeviceId) throw new Error("publicDeviceId api unavailable");
        return { device_id: this.api.publicDeviceId() };
      }
      default:
        throw new Error(`unknown method: ${method}`);
    }
  }
}

/** Pure permission check used by unit tests (no DOM). */
export function evaluateWidgetRequest(
  granted: WidgetPermission[],
  method: string,
): { allowed: boolean; reason?: string } {
  if (
    FORBIDDEN_PERMISSIONS.includes(method as (typeof FORBIDDEN_PERMISSIONS)[number]) ||
    method.startsWith("keys.") ||
    method.includes("private") ||
    method.includes("signing")
  ) {
    return { allowed: false, reason: "forbidden" };
  }
  const need: Record<string, WidgetPermission> = {
    "room.send": "room.send",
    "room.read": "room.read",
    "room.list": "room.list",
    "device.public_id": "device.public_id",
  };
  const perm = need[method];
  if (!perm) return { allowed: false, reason: "unknown" };
  if (!granted.includes(perm)) return { allowed: false, reason: "missing permission" };
  return { allowed: true };
}
