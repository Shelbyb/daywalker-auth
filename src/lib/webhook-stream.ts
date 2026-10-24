/**
 * Live event stream for the CLI (`daywalker listen`). Development instances only: an event emitted
 * anywhere in the fleet is published on a per-instance Valkey channel and forwarded over SSE to the
 * connected CLI. Nothing is stored. Payloads carry user data, so they are encrypted (AES-GCM, bound to
 * the instance) before they touch Valkey, and nothing is published unless a listener is connected.
 */
import { decrypt, encrypt } from "./crypto";
import { cache } from "./cache";

export const MAX_STREAMS_PER_INSTANCE = 5;
const LISTENER_TTL = 60; // seconds; refreshed by each open stream, so a crashed server's count expires on its own
const KEEPALIVE_MS = 20_000;
export const MAX_STREAM_MS = 60 * 60_000; // clients reconnect after an hour

const countKey = (instanceId: string) => `whstream:n:${instanceId}`;
const channel = (instanceId: string) => `whstream:c:${instanceId}`;
const aad = (instanceId: string) => `webhook_stream:${instanceId}`;

/** Called for every emitted event. Cheap when nobody is listening (one GET). */
export async function publishToStream(instanceId: string, type: string, body: string) {
  try {
    const n = await cache().get(countKey(instanceId));
    if (!n || Number(n) <= 0) return;
    await cache().publish(channel(instanceId), encrypt(JSON.stringify({ type, body }), aad(instanceId)));
  } catch {
    // a dev tool must never affect the real flow
  }
}

const sse = (event: string, data: string) => `event: ${event}\ndata: ${data}\n\n`;

/** Opens a server-sent-events response for an instance. Returns null when the instance already has the maximum number of listeners. */
export async function openStream(instanceId: string, signal: AbortSignal, types: string[] | null): Promise<Response | null> {
  const key = countKey(instanceId);
  const n = await cache().incr(key);
  await cache().expire(key, LISTENER_TTL);
  if (n > MAX_STREAMS_PER_INSTANCE) {
    await cache().decr(key);
    return null;
  }
  const sub = cache().duplicate();
  const enc = new TextEncoder();
  let closed = false;
  let timers: NodeJS.Timeout[] = [];
  const cleanup = async (controller?: ReadableStreamDefaultController) => {
    if (closed) return;
    closed = true;
    timers.forEach(clearTimeout);
    timers = [];
    try { controller?.close(); } catch { /* already closed */ }
    await sub.quit().catch(() => {});
    const left = await cache().decr(key).catch(() => 0);
    if (left <= 0) await cache().del(key).catch(() => {});
  };
  const body = new ReadableStream<Uint8Array>({
    async start(controller) {
      const write = (s: string) => { if (!closed) try { controller.enqueue(enc.encode(s)); } catch { void cleanup(controller); } };
      try {
        await sub.subscribe(channel(instanceId));
      } catch {
        await cleanup(controller);
        return;
      }
      sub.on("message", (_ch, msg) => {
        try {
          const { type, body: payload } = JSON.parse(decrypt(msg, aad(instanceId))) as { type: string; body: string };
          if (types && !types.includes(type)) return;
          write(sse("webhook", payload));
        } catch { /* ignore anything we can't authenticate */ }
      });
      write(sse("ready", JSON.stringify({ instanceId })));
      timers.push(setInterval(() => {
        write(": keepalive\n\n");
        void cache().expire(key, LISTENER_TTL).catch(() => {});
      }, KEEPALIVE_MS));
      timers.push(setTimeout(() => { write(sse("bye", JSON.stringify({ reason: "max_duration" }))); void cleanup(controller); }, MAX_STREAM_MS));
      signal.addEventListener("abort", () => void cleanup(controller), { once: true });
    },
    cancel() { return cleanup(); },
  });
  return new Response(body, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store, no-transform",
      "x-accel-buffering": "no",
      "x-content-type-options": "nosniff",
    },
  });
}
