import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { HonkBot } from "./honk-bot.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

async function waitHealth(bot, n = 80) {
  for (let i = 0; i < n; i++) {
    try {
      if (await bot.health()) return;
    } catch {
      /* retry */
    }
    await sleep(100);
  }
  throw new Error("rpc unhealthy");
}

test("bot posts via public RPC without key APIs", async () => {
  const bind = "127.0.0.1:18791";
  const base = `http://${bind}`;
  const bin = path.join(repoRoot, "target/debug/tducks");
  assert.ok(existsSync(bin), "build tducks first: cargo build -p tducks");
  const child = spawn(bin, ["serve", "--bind", bind], {
    cwd: repoRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });
  try {
    const bot = new HonkBot(base, "test-bot");
    await waitHealth(bot);
    assert.equal(typeof bot.exportKeys, "undefined");
    assert.equal(typeof bot.signingKey, "undefined");
    const room = await bot.createRoom("bot-smoke");
    const sent = await bot.post(room.room_id, "hello-from-bot");
    assert.equal(String(sent.event_id).length, 64);
    const msgs = await bot.listMessages(room.room_id);
    assert.equal(msgs.messages.length, 1);
    assert.match(msgs.messages[0].text, /hello-from-bot/);
    assert.match(msgs.messages[0].text, /test-bot/);
  } finally {
    child.kill("SIGTERM");
    await Promise.race([once(child, "exit"), sleep(2000)]);
  }
});
