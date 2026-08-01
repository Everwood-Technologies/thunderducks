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

    // A2 SSE: snapshot + messages event after send (fetch stream; no browser EventSource in node)
    {
      const esUrl = client.messagesStreamUrl(room.room_id);
      const got: { type: string; count: number; text?: string }[] = [];
      const ac = new AbortController();
      const res = await fetch(esUrl, {
        headers: { accept: "text/event-stream" },
        signal: ac.signal,
      });
      assert.equal(res.status, 200);
      assert.ok((res.headers.get("content-type") || "").includes("text/event-stream"));
      const reader = res.body!.getReader();
      const dec = new TextDecoder();
      let buf = "";
      let sentPush = false;
      const deadline = Date.now() + 8000;
      while (Date.now() < deadline) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        // Parse complete SSE blocks separated by blank line
        for (;;) {
          const sep = buf.indexOf("\n\n");
          if (sep < 0) break;
          const block = buf.slice(0, sep);
          buf = buf.slice(sep + 2);
          let evName = "message";
          const dataLines: string[] = [];
          for (const line of block.split("\n")) {
            if (line.startsWith("event:")) evName = line.slice(6).trim();
            else if (line.startsWith("data:")) dataLines.push(line.slice(5).trimStart());
          }
          if (!dataLines.length) continue;
          const j = JSON.parse(dataLines.join("\n")) as {
            count: number;
            messages: { text: string }[];
          };
          got.push({
            type: evName,
            count: j.count,
            text: j.messages[j.messages.length - 1]?.text,
          });
          if (evName === "snapshot" && !sentPush) {
            sentPush = true;
            void client.send(room.room_id, "sse-push");
          }
          if (evName === "messages" && j.count >= 2) {
            ac.abort();
            break;
          }
        }
        if (got.some((g) => g.type === "messages" && g.count >= 2)) break;
      }
      try {
        ac.abort();
      } catch {
        /* ignore */
      }
      assert.ok(
        got.some((g) => g.type === "snapshot"),
        "missing snapshot; got=" + JSON.stringify(got),
      );
      assert.ok(
        got.some((g) => g.type === "messages" && g.count >= 2),
        "missing messages push; got=" + JSON.stringify(got),
      );
      const last = got.filter((g) => g.type === "messages").at(-1);
      assert.equal(last?.text, "sse-push");
    }
  } finally {
    if (child && !child.killed) {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), sleep(2000)]);
    }
  }
});
