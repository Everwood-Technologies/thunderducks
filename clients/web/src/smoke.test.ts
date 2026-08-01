import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { TdRpcClient } from "./rpc.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

async function waitForHealth(client: TdRpcClient, attempts = 100): Promise<void> {
  for (let i = 0; i < attempts; i++) {
    try {
      if (await client.health()) return;
    } catch {
      // retry
    }
    await sleep(200);
  }
  throw new Error("rpc never became healthy");
}

function spawnRpc(bind: string): ChildProcess {
  const releaseBin = path.join(repoRoot, "target/release/tducks");
  const debugBin = path.join(repoRoot, "target/debug/tducks");
  if (existsSync(debugBin) || existsSync(releaseBin)) {
    const bin = existsSync(debugBin) ? debugBin : releaseBin;
    return spawn(bin, ["serve", "--bind", bind], {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });
  }
  return spawn("cargo", ["run", "-q", "-p", "tducks", "--", "serve", "--bind", bind], {
    cwd: repoRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

test("web client enroll -> room -> send/recv against local rpc", async () => {
  const bind = "127.0.0.1:18788";
  const base = `http://${bind}`;
  let child: ChildProcess | null = null;
  try {
    child = spawnRpc(bind);
    let stderr = "";
    child.stdout?.on("data", () => {});
    child.stderr?.on("data", (buf: Buffer) => {
      stderr += buf.toString();
    });
    child.on("exit", (code, signal) => {
      if (code && code !== 0) {
        stderr += "\n[exit code=" + String(code) + " signal=" + String(signal) + "]";
      }
    });

    const client = new TdRpcClient(base);
    try {
      await waitForHealth(client);
    } catch (e) {
      throw new Error((e as Error).message + "\nserver stderr:\n" + stderr);
    }

    const st = await client.status();
    assert.equal(st.device_id.length, 64);

    const linked = await client.linkSecondary();
    assert.equal(linked.linked, true);

    await client.addPeer("bob", "td://127.0.0.1:9");
    const room = await client.createRoom("web-smoke");
    assert.equal(room.room_id.length, 64);

    const sent = await client.send(room.room_id, "from-ts-web");
    assert.equal(sent.event_id.length, 64);

    const msgs = await client.listMessages(room.room_id);
    assert.equal(msgs.messages.length, 1);
    assert.equal(msgs.messages[0]?.text, "from-ts-web");

    // long-poll: already have 1 message → since_count=0 returns immediately changed
    const waited = await client.waitMessages(room.room_id, 0, 2000);
    assert.equal(waited.changed, true);
    assert.equal(waited.count, 1);
    assert.equal(waited.messages[0]?.text, "from-ts-web");

    // timeout path: since_count matches → timed_out
    const idle = await client.waitMessages(room.room_id, 1, 400);
    assert.equal(idle.timed_out, true);
    assert.equal(idle.changed, false);
    assert.equal(idle.count, 1);
  } finally {
    if (child && !child.killed) {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), sleep(2000)]);
    }
  }
});
