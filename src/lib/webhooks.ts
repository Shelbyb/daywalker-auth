import { createHmac, randomBytes } from "node:crypto";
import { record, type Actor } from "./audit";
import https from "node:https";
import http from "node:http";
import { and, asc, desc, eq, gte, inArray, lt, lte, sql } from "drizzle-orm";
import { db, schema } from "./db";
import { decrypt, encrypt } from "./crypto";
import { errors } from "./http";
import { newId } from "./ids";
import { checkPublicUrl, safeLookup, type UrlProblem } from "./net-guard";
import { publishToStream } from "./webhook-stream";

/** Everything we can emit. Endpoints subscribe to a list of these, or "*" for all. */
export const EVENT_TYPES = [
  "user.created",
  "user.deleted",
  "user.deletion_requested",
  "user.deletion_canceled",
  "user.locked",
  "user.unlocked",
  "session.created",
  "session.revoked",
  "organization.created",
  "organization.deleted",
  "organizationMembership.created",
  "organizationMembership.deleted",
  "organizationInvitation.created",
  "webhook.test",
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

const MAX_ENDPOINTS = 10;
const MAX_ATTEMPTS = 8;
/** Seconds to wait after failed attempt 1, 2, 3... (±10% jitter). Roughly a day in total. */
const BACKOFF = [30, 120, 600, 1800, 3600, 10_800, 21_600, 43_200];
const REQUEST_TIMEOUT_MS = 10_000;
const RETENTION_DAYS = 30;
const LEASE_SECONDS = 120;

// ---------- SSRF protection (see net-guard.ts) ----------

/** Throws a 400 if the URL isn't a public HTTPS address. */
export async function assertSafeUrl(raw: string) {
  const c = await checkPublicUrl(raw);
  if (c.ok) return c.url;
  const msg: Record<UrlProblem, string> = {
    invalid: "That isn't a valid URL",
    too_long: "URL is too long",
    insecure: "Webhook URLs must use https",
    credentials: "Put credentials in a header or token, not the URL's user info",
    unresolvable: "We couldn't resolve that hostname",
    private: "That address is private or internal. Use a public URL",
  };
  throw errors.badRequest("invalid_url", msg[c.problem]);
}

// ---------- Signing (Standard Webhooks compatible) ----------

export const newSecret = () => `whsec_${randomBytes(32).toString("base64")}`;

export function sign(secret: string, msgId: string, timestamp: number, body: string) {
  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  return `v1,${createHmac("sha256", key).update(`${msgId}.${timestamp}.${body}`).digest("base64")}`;
}

// ---------- Endpoint management ----------

const ctx = (table: string, col: string, id: string) => `${table}.${col}:${id}`;
type EndpointRow = typeof schema.webhookEndpoints.$inferSelect;

function view(e: EndpointRow) {
  return {
    id: e.id,
    url: decrypt(e.urlEnc, ctx("webhook_endpoints", "url", e.id)),
    events: e.events,
    description: e.description,
    enabled: e.enabled,
    createdAt: e.createdAt,
  };
}

function checkEvents(events: string[]) {
  const bad = events.find((e) => e !== "*" && !(EVENT_TYPES as readonly string[]).includes(e));
  if (bad) throw errors.badRequest("invalid_event", `Unknown event type "${bad}"`);
  return events.includes("*") ? ["*"] : [...new Set(events)];
}

const API: Actor = { type: "api" };

export async function createEndpoint(instanceId: string, input: { url: string; events?: string[]; description?: string | null }, actor: Actor = API) {
  await assertSafeUrl(input.url);
  const existing = await db().select({ id: schema.webhookEndpoints.id }).from(schema.webhookEndpoints).where(eq(schema.webhookEndpoints.instanceId, instanceId));
  if (existing.length >= MAX_ENDPOINTS) throw errors.badRequest("too_many_endpoints", `You can have up to ${MAX_ENDPOINTS} webhook endpoints`);
  const id = newId("we");
  const secret = newSecret();
  const [row] = await db()
    .insert(schema.webhookEndpoints)
    .values({
      id,
      instanceId,
      urlEnc: encrypt(input.url, ctx("webhook_endpoints", "url", id)),
      secretEnc: encrypt(secret, ctx("webhook_endpoints", "secret", id)),
      events: checkEvents(input.events?.length ? input.events : ["*"]),
      description: input.description?.slice(0, 200) ?? null,
    })
    .returning();
  void record(instanceId, "webhook.created", { actor, target: row.id, data: { events: row.events } });
  return { ...view(row), secret }; // the only time the secret is shown (besides rotation)
}

export async function listEndpoints(instanceId: string) {
  const rows = await db().select().from(schema.webhookEndpoints).where(eq(schema.webhookEndpoints.instanceId, instanceId)).orderBy(desc(schema.webhookEndpoints.createdAt));
  return rows.map(view);
}

async function load(instanceId: string, id: string) {
  const [row] = await db()
    .select()
    .from(schema.webhookEndpoints)
    .where(and(eq(schema.webhookEndpoints.id, id), eq(schema.webhookEndpoints.instanceId, instanceId)));
  if (!row) throw errors.notFound("Webhook endpoint not found");
  return row;
}

export async function getEndpoint(instanceId: string, id: string) {
  return view(await load(instanceId, id));
}

export async function updateEndpoint(
  instanceId: string,
  id: string,
  input: { url?: string; events?: string[]; description?: string | null; enabled?: boolean },
  actor: Actor = API,
) {
  await load(instanceId, id);
  const set: Partial<typeof schema.webhookEndpoints.$inferInsert> = {};
  if (input.url !== undefined) {
    await assertSafeUrl(input.url);
    set.urlEnc = encrypt(input.url, ctx("webhook_endpoints", "url", id));
  }
  if (input.events !== undefined) set.events = checkEvents(input.events.length ? input.events : ["*"]);
  if (input.description !== undefined) set.description = input.description?.slice(0, 200) ?? null;
  if (input.enabled !== undefined) set.enabled = input.enabled;
  if (!Object.keys(set).length) return getEndpoint(instanceId, id);
  const [row] = await db().update(schema.webhookEndpoints).set(set).where(eq(schema.webhookEndpoints.id, id)).returning();
  void record(instanceId, "webhook.updated", { actor, target: id, data: { changed: Object.keys(input).filter((k) => input[k as keyof typeof input] !== undefined) } });
  return view(row);
}

export async function deleteEndpoint(instanceId: string, id: string, actor: Actor = API) {
  await load(instanceId, id);
  await db().delete(schema.webhookEndpoints).where(eq(schema.webhookEndpoints.id, id));
  void record(instanceId, "webhook.deleted", { actor, target: id });
}

export async function rotateSecret(instanceId: string, id: string, actor: Actor = API) {
  await load(instanceId, id);
  const secret = newSecret();
  await db().update(schema.webhookEndpoints).set({ secretEnc: encrypt(secret, ctx("webhook_endpoints", "secret", id)) }).where(eq(schema.webhookEndpoints.id, id));
  void record(instanceId, "webhook.secret_rotated", { actor, target: id });
  return { id, secret };
}

export async function listDeliveries(instanceId: string, endpointId: string, limit = 50) {
  await load(instanceId, endpointId);
  const rows = await db()
    .select()
    .from(schema.webhookDeliveries)
    .where(eq(schema.webhookDeliveries.endpointId, endpointId))
    .orderBy(desc(schema.webhookDeliveries.createdAt))
    .limit(Math.min(limit, 100));
  return rows.map((d) => ({
    id: d.id,
    eventId: d.eventId,
    eventType: d.eventType,
    status: d.status,
    attempts: d.attempts,
    lastStatusCode: d.lastStatusCode,
    lastError: d.lastError,
    nextAttemptAt: d.status === "pending" ? d.nextAttemptAt : null,
    deliveredAt: d.deliveredAt,
    replayOf: d.replayOf,
    createdAt: d.createdAt,
  }));
}

/** Put a finished (or failed) delivery back in the queue. */
export async function retryDelivery(instanceId: string, deliveryId: string) {
  const rows = await db()
    .update(schema.webhookDeliveries)
    .set({ status: "pending", attempts: 0, nextAttemptAt: new Date(), lastError: null })
    .where(and(eq(schema.webhookDeliveries.id, deliveryId), eq(schema.webhookDeliveries.instanceId, instanceId)))
    .returning({ id: schema.webhookDeliveries.id });
  if (!rows.length) throw errors.notFound("Delivery not found");
  void processDue();
}

export const REPLAY_MAX_BULK = 500;

async function loadDelivery(instanceId: string, deliveryId: string) {
  const [row] = await db()
    .select({ d: schema.webhookDeliveries, e: schema.webhookEndpoints })
    .from(schema.webhookDeliveries)
    .innerJoin(schema.webhookEndpoints, eq(schema.webhookEndpoints.id, schema.webhookDeliveries.endpointId))
    .where(and(eq(schema.webhookDeliveries.id, deliveryId), eq(schema.webhookDeliveries.instanceId, instanceId), eq(schema.webhookEndpoints.instanceId, instanceId)));
  if (!row) throw errors.notFound("Delivery not found");
  return row;
}

/** Queues a copy of a past delivery as a new delivery (same event ID and payload, signed fresh with the endpoint's current secret). */
async function queueReplay(d: typeof schema.webhookDeliveries.$inferSelect) {
  const id = newId("wd");
  const body = decrypt(d.payloadEnc, ctx("webhook_deliveries", "payload", d.id));
  await db().insert(schema.webhookDeliveries).values({
    id,
    instanceId: d.instanceId,
    endpointId: d.endpointId,
    eventId: d.eventId,
    eventType: d.eventType,
    payloadEnc: encrypt(body, ctx("webhook_deliveries", "payload", id)),
    replayOf: d.replayOf ?? d.id, // always the original, so replays of replays still point at the source
  });
  return id;
}

/**
 * Re-sends a past delivery (any status) as a new, separate delivery. It keeps the original event ID
 * so receivers can recognise it, carries `webhook-replay` headers, and is signed with the endpoint's
 * current secret. The original row is untouched.
 */
export async function replayDelivery(instanceId: string, deliveryId: string, actor: Actor = API) {
  const { d, e } = await loadDelivery(instanceId, deliveryId);
  if (!e.enabled) throw errors.conflict("endpoint_disabled", "Enable the endpoint before replaying to it");
  const root = d.replayOf ?? d.id;
  const [pending] = await db()
    .select({ id: schema.webhookDeliveries.id })
    .from(schema.webhookDeliveries)
    .where(and(eq(schema.webhookDeliveries.replayOf, root), eq(schema.webhookDeliveries.status, "pending")))
    .limit(1);
  if (pending) throw errors.conflict("replay_pending", "A replay of this delivery is already queued");
  const id = await queueReplay(d);
  void record(instanceId, "webhook.delivery_replayed", { actor, target: root, data: { endpointId: e.id, eventType: d.eventType, replayId: id } });
  void processDue();
  return { id, replayOf: root, status: "pending" as const };
}

/**
 * Replays failed deliveries created between `from` and `to` (at most the retention window, at most
 * REPLAY_MAX_BULK per call, oldest first). Deliveries that already have a queued or successful replay,
 * and ones whose endpoint is disabled, are skipped, so running it twice doesn't send everything twice.
 */
export async function replayFailed(
  instanceId: string,
  input: { from: Date; to: Date; endpointId?: string },
  actor: Actor = API,
) {
  const { from, to } = input;
  if (!(from < to)) throw errors.badRequest("invalid_range", "`from` must be before `to`");
  if (to.getTime() - from.getTime() > RETENTION_DAYS * 86_400_000) throw errors.badRequest("invalid_range", `The range can be at most ${RETENTION_DAYS} days`);
  if (input.endpointId) await load(instanceId, input.endpointId);
  const rows = await db()
    .select({ d: schema.webhookDeliveries, enabled: schema.webhookEndpoints.enabled })
    .from(schema.webhookDeliveries)
    .innerJoin(schema.webhookEndpoints, eq(schema.webhookEndpoints.id, schema.webhookDeliveries.endpointId))
    .where(
      and(
        eq(schema.webhookDeliveries.instanceId, instanceId),
        eq(schema.webhookDeliveries.status, "failed"),
        gte(schema.webhookDeliveries.createdAt, from),
        lte(schema.webhookDeliveries.createdAt, to),
        input.endpointId ? eq(schema.webhookDeliveries.endpointId, input.endpointId) : undefined,
      ),
    )
    .orderBy(asc(schema.webhookDeliveries.createdAt))
    .limit(REPLAY_MAX_BULK + 1);
  const truncated = rows.length > REPLAY_MAX_BULK;
  const candidates = rows.slice(0, REPLAY_MAX_BULK);
  const roots = [...new Set(candidates.map((r) => r.d.replayOf ?? r.d.id))];
  const covered = new Set(
    roots.length
      ? (
          await db()
            .select({ root: schema.webhookDeliveries.replayOf })
            .from(schema.webhookDeliveries)
            .where(and(inArray(schema.webhookDeliveries.replayOf, roots), inArray(schema.webhookDeliveries.status, ["pending", "succeeded"])))
        ).map((r) => r.root)
      : [],
  );
  let replayed = 0, skippedDisabled = 0, skippedAlreadyReplayed = 0;
  const seen = new Set<string>();
  for (const { d, enabled } of candidates) {
    const root = d.replayOf ?? d.id;
    if (seen.has(root)) continue;
    seen.add(root);
    if (!enabled) { skippedDisabled++; continue; }
    if (covered.has(root)) { skippedAlreadyReplayed++; continue; }
    await queueReplay(d);
    replayed++;
  }
  void record(instanceId, "webhook.bulk_replayed", {
    actor,
    target: input.endpointId ?? null,
    data: { from: from.toISOString(), to: to.toISOString(), replayed, skippedDisabled, skippedAlreadyReplayed, truncated },
  });
  if (replayed) void processDue();
  return { replayed, skippedDisabled, skippedAlreadyReplayed, truncated };
}

export async function sendTest(instanceId: string, endpointId: string) {
  const e = await load(instanceId, endpointId);
  const eventId = newId("evt");
  await enqueue(e, instanceId, eventId, "webhook.test", eventBody(eventId, "webhook.test", { message: "This is a test event from Daywalker Auth." }));
  void processDue();
  return { eventId };
}

// ---------- Emitting ----------

const eventBody = (eventId: string, type: EventType, data: unknown) => JSON.stringify({ id: eventId, type, createdAt: new Date().toISOString(), data });

async function enqueue(endpoint: EndpointRow, instanceId: string, eventId: string, type: EventType, body: string) {
  const id = newId("wd");
  await db().insert(schema.webhookDeliveries).values({
    id,
    instanceId,
    endpointId: endpoint.id,
    eventId,
    eventType: type,
    payloadEnc: encrypt(body, ctx("webhook_deliveries", "payload", id)),
  });
}

/**
 * Queue an event for every enabled endpoint subscribed to it. Never throws: a webhook
 * problem must not break sign-in or sign-up.
 */
export async function emit(instanceId: string, type: EventType, data: Record<string, unknown>) {
  try {
    const eventId = newId("evt");
    const body = eventBody(eventId, type, data);
    await publishToStream(instanceId, type, body); // development instances only, and only while a CLI is listening
    const endpoints = await db()
      .select()
      .from(schema.webhookEndpoints)
      .where(and(eq(schema.webhookEndpoints.instanceId, instanceId), eq(schema.webhookEndpoints.enabled, true)));
    const targets = endpoints.filter((e) => e.events.includes("*") || e.events.includes(type));
    if (!targets.length) return;
    await Promise.all(targets.map((e) => enqueue(e, instanceId, eventId, type, body)));
    void processDue();
  } catch (e) {
    console.error("[webhooks] emit failed", (e as Error).message);
  }
}

// ---------- Delivery ----------

function post(url: URL, headers: Record<string, string>, body: string): Promise<{ status: number }> {
  return new Promise((resolve, reject) => {
    const mod = url.protocol === "https:" ? https : http;
    const req = mod.request(
      url,
      { method: "POST", headers: { ...headers, "content-length": Buffer.byteLength(body) }, lookup: safeLookup, timeout: REQUEST_TIMEOUT_MS },
      (res) => {
        res.resume(); // never read the receiver's response body: it's untrusted and we don't store it
        res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end(body);
  });
}

const errorLabel = (e: unknown) => {
  const m = (e as Error)?.message ?? "";
  if (m === "timeout") return "Timed out";
  if (m === "blocked_address") return "Blocked: address is private";
  const code = (e as { code?: string })?.code;
  return code ? `Connection failed (${code})` : "Connection failed";
};

const delay = (attempt: number) => {
  const base = BACKOFF[Math.min(attempt - 1, BACKOFF.length - 1)];
  return Math.round(base * (0.9 + Math.random() * 0.2)) * 1000;
};

async function attempt(deliveryId: string) {
  const [row] = await db()
    .select({ d: schema.webhookDeliveries, e: schema.webhookEndpoints })
    .from(schema.webhookDeliveries)
    .innerJoin(schema.webhookEndpoints, eq(schema.webhookEndpoints.id, schema.webhookDeliveries.endpointId))
    .where(eq(schema.webhookDeliveries.id, deliveryId));
  if (!row) return;
  const { d, e } = row;
  const attempts = d.attempts + 1;
  let status = 0;
  let error: string | null = null;
  try {
    const url = await assertSafeUrl(decrypt(e.urlEnc, ctx("webhook_endpoints", "url", e.id)));
    const body = decrypt(d.payloadEnc, ctx("webhook_deliveries", "payload", d.id));
    const ts = Math.floor(Date.now() / 1000);
    const secret = decrypt(e.secretEnc, ctx("webhook_endpoints", "secret", e.id));
    ({ status } = await post(
      url,
      {
        "content-type": "application/json",
        "user-agent": "Daywalker-Webhooks/1",
        "webhook-id": d.eventId,
        "webhook-timestamp": String(ts),
        "webhook-signature": sign(secret, d.eventId, ts, body),
        ...(d.replayOf ? { "webhook-replay": "true", "webhook-replay-of": d.replayOf } : {}),
      },
      body,
    ));
    if (status < 200 || status >= 300) error = `HTTP ${status}`;
  } catch (err) {
    error = (err as { code?: string }).code === "invalid_url" || (err as { status?: number }).status === 400 ? "Blocked: address is private" : errorLabel(err);
  }
  const ok = !error;
  await db()
    .update(schema.webhookDeliveries)
    .set(
      ok
        ? { status: "succeeded", attempts, lastStatusCode: status, lastError: null, deliveredAt: new Date() }
        : attempts >= MAX_ATTEMPTS
          ? { status: "failed", attempts, lastStatusCode: status || null, lastError: error }
          : { attempts, lastStatusCode: status || null, lastError: error, nextAttemptAt: new Date(Date.now() + delay(attempts)) },
    )
    .where(eq(schema.webhookDeliveries.id, d.id));
}

let running = false;
/**
 * Deliver whatever is due. Safe to run on many instances at once: rows are claimed with
 * FOR UPDATE SKIP LOCKED and leased for two minutes, so a crash just means a retry.
 */
export async function processDue(limit = 25) {
  if (running) return 0;
  running = true;
  try {
    const claimed = await db().execute<{ id: string }>(sql`
      UPDATE webhook_deliveries SET next_attempt_at = now() + make_interval(secs => ${LEASE_SECONDS})
      WHERE id IN (
        SELECT id FROM webhook_deliveries
        WHERE status = 'pending' AND next_attempt_at <= now()
        ORDER BY next_attempt_at LIMIT ${limit} FOR UPDATE SKIP LOCKED
      ) RETURNING id`);
    await Promise.all([...claimed].map((r) => attempt(r.id).catch((e) => console.error("[webhooks] attempt failed", (e as Error).message))));
    return claimed.length;
  } finally {
    running = false;
  }
}

/** Delivery logs hold encrypted user data; don't keep them forever. */
export async function purgeOld() {
  await db()
    .delete(schema.webhookDeliveries)
    .where(lt(schema.webhookDeliveries.createdAt, new Date(Date.now() - RETENTION_DAYS * 86_400_000)));
}
