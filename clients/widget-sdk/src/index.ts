export {
  TD_WIDGET_CHANNEL,
  FORBIDDEN_PERMISSIONS,
  isWidgetMessage,
  type WidgetPermission,
  type ForbiddenPermission,
  type HostToWidget,
  type WidgetToHost,
} from "./protocol.js";
export { WidgetHost, evaluateWidgetRequest, type HostRoomApi, type WidgetHostOptions } from "./host.js";
export { WidgetGuest } from "./guest.js";
