import assert from "node:assert/strict";
import test from "node:test";
import {
  FORBIDDEN_PERMISSIONS,
  evaluateWidgetRequest,
  type WidgetPermission,
} from "./index.js";

test("deny-by-default: no grants => nothing allowed", () => {
  const granted: WidgetPermission[] = [];
  assert.equal(evaluateWidgetRequest(granted, "room.send").allowed, false);
  assert.equal(evaluateWidgetRequest(granted, "room.read").allowed, false);
  assert.equal(evaluateWidgetRequest(granted, "device.public_id").allowed, false);
});

test("widgets cannot request key material", () => {
  const granted: WidgetPermission[] = ["room.send", "room.read", "device.public_id"];
  for (const m of FORBIDDEN_PERMISSIONS) {
    const r = evaluateWidgetRequest(granted, m);
    assert.equal(r.allowed, false, m);
    assert.equal(r.reason, "forbidden");
  }
  assert.equal(evaluateWidgetRequest(granted, "keys.read").allowed, false);
  assert.equal(evaluateWidgetRequest(granted, "device.private_key").allowed, false);
  assert.equal(evaluateWidgetRequest(granted, "export_signing_key").allowed, false);
});

test("granted room.send allows only send", () => {
  const granted: WidgetPermission[] = ["room.send"];
  assert.equal(evaluateWidgetRequest(granted, "room.send").allowed, true);
  assert.equal(evaluateWidgetRequest(granted, "room.read").allowed, false);
});

test("unknown methods denied", () => {
  const granted: WidgetPermission[] = ["room.send", "room.read", "room.list", "device.public_id"];
  assert.equal(evaluateWidgetRequest(granted, "admin.shutdown").allowed, false);
  assert.equal(evaluateWidgetRequest(granted, "fs.read").allowed, false);
});
