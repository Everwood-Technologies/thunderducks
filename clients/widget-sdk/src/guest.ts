/**
 * Guest (iframe) SDK — talk to host via postMessage only.
 */

import {
  TD_WIDGET_CHANNEL,
  type HostToWidget,
  type WidgetPermission,
  isWidgetMessage,
} from "./protocol.js";

type Pending = {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
};

export class WidgetGuest {
  readonly widgetId: string;
  private granted: WidgetPermission[] = [];
  private pending = new Map<string, Pending>();
  private seq = 0;
  private targetOrigin: string;
  private ready = false;

  constructor(widgetId: string, targetOrigin = "*") {
    this.widgetId = widgetId;
    this.targetOrigin = targetOrigin;
    if (typeof globalThis.addEventListener === "function") {
      globalThis.addEventListener("message", this.onMessage);
    }
  }

  get permissions(): readonly WidgetPermission[] {
    return this.granted;
  }

  /** Notify host that widget script is loaded. */
  announceReady(): void {
    this.post({
      channel: TD_WIDGET_CHANNEL,
      type: "ready",
      widgetId: this.widgetId,
    });
  }

  waitHello(timeoutMs = 5000): Promise<WidgetPermission[]> {
    if (this.ready) return Promise.resolve(this.granted);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("hello timeout")), timeoutMs);
      const prev = this.onHello;
      this.onHello = (g) => {
        clearTimeout(t);
        this.onHello = prev;
        resolve(g);
      };
    });
  }

  private onHello: ((g: WidgetPermission[]) => void) | null = null;

  async request(method: string, params: Record<string, unknown> = {}): Promise<unknown> {
    const id = `r${++this.seq}`;
    const p = new Promise<unknown>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    this.post({
      channel: TD_WIDGET_CHANNEL,
      type: "request",
      id,
      method,
      params,
    });
    return p;
  }

  destroy(): void {
    if (typeof globalThis.removeEventListener === "function") {
      globalThis.removeEventListener("message", this.onMessage);
    }
    this.pending.clear();
  }

  private post(msg: unknown): void {
    const g = globalThis as unknown as {
      parent?: { postMessage?: (m: unknown, o: string) => void };
      postMessage?: (m: unknown, o: string) => void;
    };
    const parent = g.parent;
    // Node tests / top-level window: no distinct parent frame.
    if (!parent || parent === (g as unknown) || typeof parent.postMessage !== "function") {
      return;
    }
    parent.postMessage(msg, this.targetOrigin);
  }

  private onMessage = (ev: MessageEvent): void => {
    if (!isWidgetMessage(ev.data)) return;
    const msg = ev.data as HostToWidget;
    if (msg.type === "hello") {
      this.granted = msg.granted;
      this.ready = true;
      this.onHello?.(msg.granted);
      return;
    }
    if (msg.type === "result") {
      const pend = this.pending.get(msg.id);
      if (!pend) return;
      this.pending.delete(msg.id);
      if (msg.ok) pend.resolve(msg.data);
      else pend.reject(new Error(msg.error));
    }
  };
}
