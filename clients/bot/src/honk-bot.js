/**
 * Honk bot — uses only public localhost RPC.
 * Never loads device keys or E2EE session material.
 */

export class HonkBot {
  /**
   * @param {string} baseUrl e.g. http://127.0.0.1:8788
   * @param {string} [name]
   */
  constructor(baseUrl, name = "honk-bot") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.name = name;
  }

  async #post(path, body) {
    const r = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body ?? {}),
    });
    if (!r.ok) {
      const t = await r.text();
      throw new Error(`HTTP ${r.status}: ${t}`);
    }
    return r.json();
  }

  async #get(path) {
    const r = await fetch(`${this.baseUrl}${path}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  async health() {
    const j = await this.#get("/health");
    return j.ok === true;
  }

  async status() {
    return this.#get("/v1/status");
  }

  /**
   * Post a bot message into a room via public API.
   * @param {string} roomId
   * @param {string} text
   */
  async post(roomId, text) {
    const payload = `[${this.name}] ${text}`;
    return this.#post("/v1/messages", { room_id: roomId, text: payload });
  }

  async createRoom(name) {
    return this.#post("/v1/rooms", { name });
  }

  async listMessages(roomId) {
    return this.#post("/v1/messages/list", { room_id: roomId });
  }
}

async function main() {
  const base = process.env.TD_RPC || "http://127.0.0.1:8788";
  const room = process.env.TD_ROOM;
  const text = process.argv[2] || "automated honk";
  const bot = new HonkBot(base);
  if (!(await bot.health())) {
    console.error("rpc not healthy at", base);
    process.exit(1);
  }
  let roomId = room;
  if (!roomId) {
    const r = await bot.createRoom("bot-pond");
    roomId = r.room_id;
    console.log("created room", roomId);
  }
  const sent = await bot.post(roomId, text);
  console.log("posted", sent);
  const msgs = await bot.listMessages(roomId);
  console.log("messages", JSON.stringify(msgs.messages, null, 2));
}

// Only auto-run when executed directly, not when imported by tests.
const entry = process.argv[1] ? String(process.argv[1]) : "";
const isDirectRun = /honk-bot\.js$/.test(entry) && !entry.includes("honk-bot.test");
if (isDirectRun && !process.env.TD_BOT_AS_LIB) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

export default HonkBot;
