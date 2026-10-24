/**
 * Optional push of the audit log to the customer's own S3-compatible bucket (AWS S3, Cloudflare R2, MinIO,
 * Backblaze B2...). A copy outside our database is what makes the hash chain meaningful against someone who
 * can rewrite the whole database: keep the exported heads, and `verifyAuditExport` (server SDK) checks the files.
 *
 * Credentials are encrypted at rest (field encryption, in the rotation registry) and never returned by any API.
 * Requests are signed with AWS Signature V4 and sent through the SSRF guard: public addresses only, no redirects.
 */
import { createHash, createHmac } from "node:crypto";
import { z } from "zod";
import { eq } from "drizzle-orm";
import { db, schema } from "./db";
import { cache, rateLimit } from "./cache";
import { decrypt, encrypt } from "./crypto";
import { errors } from "./http";
import { exportLines } from "./audit-chain";
import { guardedFetch, checkPublicUrl, type UrlProblem } from "./net-guard";
import { record } from "./audit";
import type { AuditExportConfig } from "./db/schema";

const sha256hex = (v: string | Buffer) => createHash("sha256").update(v).digest("hex");
const hmac = (key: string | Buffer, v: string) => createHmac("sha256", key).update(v).digest();

// ---------- AWS Signature Version 4 ----------

/** RFC 3986 encoding, as SigV4 requires (`encodeURIComponent` leaves !'()* alone). */
const enc = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

export function sigV4(o: {
  method: string;
  /** Already-encoded absolute path, e.g. "/bucket/a/b.ndjson". */
  path: string;
  query?: string;
  /** Headers to sign (must include host and x-amz-date). Names are matched case-insensitively. */
  headers: Record<string, string>;
  payloadHash: string;
  region: string;
  service: string;
  accessKeyId: string;
  secretAccessKey: string;
  amzDate: string; // 20150830T123600Z
}) {
  const names = Object.keys(o.headers).map((h) => h.toLowerCase()).sort();
  const lower = Object.fromEntries(Object.entries(o.headers).map(([k, v]) => [k.toLowerCase(), v.trim().replace(/\s+/g, " ")]));
  const canonicalHeaders = names.map((n) => `${n}:${lower[n]}\n`).join("");
  const signedHeaders = names.join(";");
  const canonical = [o.method, o.path, o.query ?? "", canonicalHeaders, signedHeaders, o.payloadHash].join("\n");
  const day = o.amzDate.slice(0, 8);
  const scope = `${day}/${o.region}/${o.service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", o.amzDate, scope, sha256hex(canonical)].join("\n");
  const key = hmac(hmac(hmac(hmac(`AWS4${o.secretAccessKey}`, day), o.region), o.service), "aws4_request");
  const signature = createHmac("sha256", key).update(toSign).digest("hex");
  return { signature, signedHeaders, authorization: `AWS4-HMAC-SHA256 Credential=${o.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` };
}

// ---------- Configuration ----------

export const configInput = z
  .object({
    /** Blank for AWS S3. Otherwise the https endpoint of your S3-compatible service. */
    endpoint: z.string().trim().max(500).nullish(),
    region: z.string().trim().regex(/^[a-z0-9][a-z0-9-]{0,62}$/i, "Region looks like us-east-1 (or auto)"),
    bucket: z.string().trim().regex(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/, "Bucket names are 3 to 63 lowercase letters, digits, dots or hyphens").refine((b) => !b.includes(".."), "Bucket names can't contain .."),
    prefix: z.string().trim().max(200).regex(/^[A-Za-z0-9!_.*'()/-]*$/, "Prefix may contain letters, digits and ! _ . * ' ( ) / -").optional(),
    pathStyle: z.boolean().optional(),
    serverSideEncryption: z.boolean().optional(),
    accessKeyId: z.string().trim().regex(/^[A-Za-z0-9/+=_.-]{8,128}$/, "That access key ID doesn't look right").optional(),
    secretAccessKey: z.string().regex(/^[\x21-\x7e]{8,256}$/, "That secret access key doesn't look right").optional(),
    enabled: z.boolean().optional(),
  })
  .strict();
export type ConfigInput = z.infer<typeof configInput>;

const idCtx = (instanceId: string) => `audit_export_configs.access_key_id:${instanceId}`;
const secretCtx = (instanceId: string) => `audit_export_configs.secret_access_key:${instanceId}`;
const maskKey = (k: string) => `${k.slice(0, 4)}${"•".repeat(Math.max(0, Math.min(k.length - 8, 8)))}${k.slice(-4)}`;

const PROBLEM: Record<UrlProblem, string> = {
  invalid: "That isn't a valid endpoint URL",
  too_long: "Endpoint URL is too long",
  insecure: "The endpoint must use https",
  credentials: "Don't put credentials in the endpoint URL",
  unresolvable: "We couldn't resolve that hostname",
  private: "That address is private or internal. Use a public endpoint",
};

/** What the API shows: everything except the secret, and the access key ID masked. */
export function configView(c: AuditExportConfig | undefined, instanceId: string) {
  if (!c) return { configured: false as const };
  return {
    configured: true as const,
    endpoint: c.endpoint,
    region: c.region,
    bucket: c.bucket,
    prefix: c.prefix,
    pathStyle: c.pathStyle,
    serverSideEncryption: c.serverSideEncryption,
    enabled: c.enabled,
    accessKeyId: maskKey(decrypt(c.accessKeyIdEnc, idCtx(instanceId))),
    lastPushedSeq: c.lastPushedSeq,
    lastPushedAt: c.lastPushedAt,
    lastError: c.lastError,
    lastErrorAt: c.lastErrorAt,
  };
}

export async function getConfig(instanceId: string) {
  const [c] = await db().select().from(schema.auditExportConfigs).where(eq(schema.auditExportConfigs.instanceId, instanceId));
  return c;
}

export async function saveConfig(instanceId: string, input: ConfigInput, by: { type: "developer" | "api"; id?: string }) {
  const existing = await getConfig(instanceId);
  if (!existing && (!input.accessKeyId || !input.secretAccessKey)) throw errors.badRequest("credentials_required", "An access key ID and secret access key are required");
  if ((input.accessKeyId === undefined) !== (input.secretAccessKey === undefined)) throw errors.badRequest("credentials_required", "Send the access key ID and the secret access key together, or neither to keep the current ones");
  const endpoint = input.endpoint?.trim() ? input.endpoint.trim().replace(/\/+$/, "") : null;
  if (endpoint) {
    const c = await checkPublicUrl(endpoint);
    if (!c.ok) throw errors.badRequest("invalid_endpoint", PROBLEM[c.problem]);
    if (c.url.search || c.url.hash || (c.url.pathname !== "/" && c.url.pathname !== "")) throw errors.badRequest("invalid_endpoint", "The endpoint is just the origin, for example https://s3.example.com");
  }
  const prefix = (input.prefix ?? existing?.prefix ?? "").replace(/^\/+/, "").replace(/\/+$/, "");
  if (prefix.includes("//") || prefix.split("/").some((s) => s === "." || s === "..")) throw errors.badRequest("invalid_prefix", "The prefix can't contain empty or dot segments");
  const row = {
    endpoint,
    region: input.region,
    bucket: input.bucket,
    prefix,
    pathStyle: input.pathStyle ?? existing?.pathStyle ?? false,
    serverSideEncryption: input.serverSideEncryption ?? existing?.serverSideEncryption ?? false,
    enabled: input.enabled ?? existing?.enabled ?? true,
    ...(input.accessKeyId ? { accessKeyIdEnc: encrypt(input.accessKeyId, idCtx(instanceId)), secretAccessKeyEnc: encrypt(input.secretAccessKey!, secretCtx(instanceId)) } : {}),
    updatedAt: new Date(),
  };
  if (existing) await db().update(schema.auditExportConfigs).set(row).where(eq(schema.auditExportConfigs.instanceId, instanceId));
  else await db().insert(schema.auditExportConfigs).values({ instanceId, ...row, accessKeyIdEnc: encrypt(input.accessKeyId!, idCtx(instanceId)), secretAccessKeyEnc: encrypt(input.secretAccessKey!, secretCtx(instanceId)) });
  void record(instanceId, "audit_export.configured", { actor: by, data: { endpoint, region: row.region, bucket: row.bucket, prefix, enabled: row.enabled, credentialsChanged: !!input.accessKeyId } });
  return configView(await getConfig(instanceId), instanceId);
}

export async function removeConfig(instanceId: string, by: { type: "developer" | "api"; id?: string }) {
  const gone = await db().delete(schema.auditExportConfigs).where(eq(schema.auditExportConfigs.instanceId, instanceId)).returning({ id: schema.auditExportConfigs.instanceId });
  if (gone.length) void record(instanceId, "audit_export.removed", { actor: by });
  return gone.length > 0;
}

// ---------- Upload ----------

export function s3Target(c: Pick<AuditExportConfig, "endpoint" | "region" | "bucket" | "pathStyle">, key: string) {
  const path = key.split("/").map(enc).join("/");
  if (!c.endpoint) {
    const host = `s3.${c.region}.amazonaws.com`;
    // Dotted bucket names don't match the wildcard certificate in virtual-hosted style.
    return c.pathStyle || c.bucket.includes(".") ? { url: `https://${host}/${c.bucket}/${path}`, host, path: `/${c.bucket}/${path}` } : { url: `https://${c.bucket}.${host}/${path}`, host: `${c.bucket}.${host}`, path: `/${path}` };
  }
  const base = new URL(c.endpoint);
  if (c.pathStyle) return { url: `${base.origin}/${c.bucket}/${path}`, host: base.host, path: `/${c.bucket}/${path}` };
  return { url: `${base.protocol}//${c.bucket}.${base.host}/${path}`, host: `${c.bucket}.${base.host}`, path: `/${path}` };
}

/** First <Code> and <Message> of an S3 error body, trimmed: enough to act on, nothing that could echo a secret. */
function s3Reason(status: number, body: string) {
  const code = body.match(/<Code>([^<]{1,60})<\/Code>/)?.[1];
  const msg = body.match(/<Message>([^<]{1,160})<\/Message>/)?.[1];
  return `HTTP ${status}${code ? ` ${code}` : ""}${msg ? `: ${msg}` : ""}`;
}

async function put(c: AuditExportConfig, instanceId: string, key: string, body: string, contentType: string, now = new Date()) {
  const t = s3Target(c, key);
  const payloadHash = sha256hex(body);
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const headers: Record<string, string> = { host: t.host, "content-type": contentType, "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate, ...(c.serverSideEncryption ? { "x-amz-server-side-encryption": "AES256" } : {}) };
  const auth = sigV4({
    method: "PUT", path: t.path, headers, payloadHash, region: c.region, service: "s3", amzDate,
    accessKeyId: decrypt(c.accessKeyIdEnc, idCtx(instanceId)), secretAccessKey: decrypt(c.secretAccessKeyEnc, secretCtx(instanceId)),
  });
  const { host: _host, ...send } = headers; // guardedFetch sets Host from the URL
  void _host;
  const r = await guardedFetch(t.url, { method: "PUT", headers: { ...send, authorization: auth.authorization }, body, timeoutMs: 30_000, maxBytes: 16 * 1024 });
  if (r.status < 200 || r.status >= 300) throw new Error(s3Reason(r.status, r.text));
}

const day = (d: Date) => d.toISOString().slice(0, 10).replaceAll("-", "/");
const objectKey = (c: AuditExportConfig, instanceId: string, first: number, last: number, now: Date) =>
  `${c.prefix ? `${c.prefix}/` : ""}${instanceId}/${day(now)}/audit-${String(first).padStart(10, "0")}-${String(last).padStart(10, "0")}.ndjson`;

/** Writes a tiny object to confirm the credentials, bucket and endpoint work. */
export async function testConfig(instanceId: string) {
  const c = await getConfig(instanceId);
  if (!c) throw errors.notFound("No audit export is configured");
  const key = `${c.prefix ? `${c.prefix}/` : ""}${instanceId}/.daywalker-connection-test`;
  try {
    await put(c, instanceId, key, `Daywalker Auth connection test ${new Date().toISOString()}\n`, "text/plain");
  } catch (e) {
    throw errors.badRequest("export_failed", `The bucket refused the test upload (${(e as Error).message})`);
  }
  return { ok: true as const, key };
}

const OBJECT_EVENTS = 2000;
const MAX_OBJECTS_PER_RUN = 10;

/**
 * Uploads chained entries not yet pushed, oldest first, as NDJSON objects of up to 2000 entries each.
 * `lastPushedSeq` moves only after the bucket accepted the object, so a failure repeats the same entries
 * (same key, so the retry overwrites rather than duplicates). One push at a time per instance.
 */
export async function pushAuditLog(instanceId: string, o: { force?: boolean } = {}) {
  const c = await getConfig(instanceId);
  if (!c) throw errors.notFound("No audit export is configured");
  if (!c.enabled && !o.force) return { pushed: 0, objects: 0, lastSeq: c.lastPushedSeq };
  if ((await cache().set(`audit-push:${instanceId}`, "1", "EX", 300, "NX")) !== "OK") throw errors.conflict("push_in_progress", "A push is already running");
  try {
    const [chain] = await db().select().from(schema.auditChains).where(eq(schema.auditChains.instanceId, instanceId));
    let after = Math.max(c.lastPushedSeq, chain?.purgedSeq ?? 0);
    let pushed = 0;
    let objects = 0;
    for (; objects < MAX_OBJECTS_PER_RUN; objects++) {
      const lines: string[] = [];
      let first = 0;
      let last = 0;
      for await (const line of exportLines(instanceId, { afterSeq: after, limit: OBJECT_EVENTS })) {
        lines.push(line);
        const j = JSON.parse(line) as { type: string; seq?: number };
        if (j.type === "event" && j.seq) { first ||= j.seq; last = j.seq; }
      }
      if (!last) break;
      try {
        await put(c, instanceId, objectKey(c, instanceId, first, last, new Date()), `${lines.join("\n")}\n`, "application/x-ndjson");
      } catch (e) {
        const msg = (e as Error).message.slice(0, 300);
        await db().update(schema.auditExportConfigs).set({ lastError: msg, lastErrorAt: new Date() }).where(eq(schema.auditExportConfigs.instanceId, instanceId));
        throw errors.badRequest("export_failed", `The bucket refused the upload (${msg})`);
      }
      after = last;
      pushed += last - first + 1;
      await db().update(schema.auditExportConfigs).set({ lastPushedSeq: last, lastPushedAt: new Date(), lastError: null, lastErrorAt: null }).where(eq(schema.auditExportConfigs.instanceId, instanceId));
    }
    return { pushed, objects, lastSeq: after };
  } finally {
    await cache().del(`audit-push:${instanceId}`);
  }
}

/** The background job: pushes every enabled configuration that has new entries. */
export async function pushDue() {
  const configs = await db().select({ id: schema.auditExportConfigs.instanceId }).from(schema.auditExportConfigs).where(eq(schema.auditExportConfigs.enabled, true));
  for (const { id } of configs) await pushAuditLog(id).catch(() => undefined); // failures are stored on the config
}

// ---------- Download ----------

/** Streams the log as NDJSON (one JSON object per line). The download itself is recorded in the log, first. */
export async function exportResponse(instanceId: string, o: { from?: Date; to?: Date }, by: { type: "developer" | "api"; id?: string }) {
  if ((await rateLimit(`audit-export:${instanceId}`, 12, 3600)) < 0) throw errors.tooMany();
  await record(instanceId, "audit.exported", { actor: by, data: { from: o.from?.toISOString() ?? null, to: o.to?.toISOString() ?? null } });
  const lines = exportLines(instanceId, o);
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      const next = await lines.next();
      if (next.done) controller.close();
      else controller.enqueue(new TextEncoder().encode(`${next.value}\n`));
    },
    cancel() {
      void lines.return(undefined);
    },
  });
  return new Response(body, {
    headers: {
      "content-type": "application/x-ndjson; charset=utf-8",
      "content-disposition": `attachment; filename="audit-${instanceId}-${new Date().toISOString().slice(0, 10)}.ndjson"`,
      "cache-control": "no-store",
    },
  });
}

/** `from` / `to` query values: ISO dates, or nothing. */
export function parseRange(from: string | null, to: string | null) {
  const d = (v: string | null, name: string) => {
    if (!v) return undefined;
    const t = new Date(v);
    if (Number.isNaN(t.getTime())) throw errors.badRequest("invalid_date", `${name} must be an ISO date such as 2026-10-01`);
    return t;
  };
  return { from: d(from, "from"), to: d(to, "to") };
}
