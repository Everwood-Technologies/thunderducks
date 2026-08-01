/** postMessage protocol between host and iframe widgets. */

export const TD_WIDGET_CHANNEL = "td-widget-v1" as const;

/** Capabilities a widget may request. Deny-by-default. */
export type WidgetPermission =
  | "room.send"
  | "room.read"
  | "room.list"
  | "device.public_id";

/** Permissions that must NEVER be granted to widgets. */
export const FORBIDDEN_PERMISSIONS = [
  "keys.read",
  "keys.export",
  "e2ee.session",
  "device.private_key",
  "signing_key",
  "megolm.export",
  "olm.export",
] as const;

export type ForbiddenPermission = (typeof FORBIDDEN_PERMISSIONS)[number];

export type HostToWidget =
  | { channel: typeof TD_WIDGET_CHANNEL; type: "hello"; widgetId: string; granted: WidgetPermission[] }
  | { channel: typeof TD_WIDGET_CHANNEL; type: "result"; id: string; ok: true; data: unknown }
  | { channel: typeof TD_WIDGET_CHANNEL; type: "result"; id: string; ok: false; error: string }
  | { channel: typeof TD_WIDGET_CHANNEL; type: "event"; name: string; payload: unknown };

export type WidgetToHost =
  | { channel: typeof TD_WIDGET_CHANNEL; type: "ready"; widgetId: string }
  | {
      channel: typeof TD_WIDGET_CHANNEL;
      type: "request";
      id: string;
      method: string;
      params?: Record<string, unknown>;
    };

export function isWidgetMessage(data: unknown): data is WidgetToHost | HostToWidget {
  return (
    typeof data === "object" &&
    data !== null &&
    (data as { channel?: string }).channel === TD_WIDGET_CHANNEL
  );
}
