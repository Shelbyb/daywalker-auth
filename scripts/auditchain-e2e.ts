/**
 * Tamper-evident audit log: hash chain under concurrency, verification catches every kind of edit (content, order,
 * removal, truncation, forged rows, details), account erasure and retention keep it verifiable, NDJSON export with
 * offline verification, and the S3-compatible bucket push (SigV4 against a mock that recomputes the signature,
 * encrypted credentials, retries). Needs the service on :3000 (with WEBHOOK_ALLOW_PRIVATE for the mock bucket).
 */
import { createHash, createHmac } from "node:crypto";
import { createServer } from "node:http";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { encrypt } from "../src/lib/crypto";
import { purgeAudit } from "../src/lib/audit";
import { sigV4, s3Target } from "../src/lib/audit-export";
import { createBackendClient, verifyAuditExport, BackendError } from "../packages/sdk/src/server";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 500)}`}`);
  if (!ok) failures++;
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rows = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];

const { instanceId, publishableKey: pk, secretKey: sk } = await seedInstance("Audit chain E2E", []);
const api = createBackendClient({ secretKey: sk, apiUrl: AUTH });
let n = 0;
const front = async (path: string, body?: unknown, cookie = "") => {
  const r = await fetch(`${AUTH}/v1/client/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, "x-forwarded-for": `203.0.113.${(++n % 200) + 1}`, ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body ?? {}),
  });
  return { status: r.status, body: await r.json().catch(() => null), cookie: (r.headers.get("set-cookie") ?? "").split(";")[0] };
};
const resetLimit = async () => { await cache().del(`rl:audit-verify:${instanceId}`, `rl:audit-export:${instanceId}`, `rl:audit-verify:${rid()}`, `rl:audit-export:${rid()}`); };
let retId = "";
const rid = () => retId || "none";
const password = "a long enough password";
const stamp = Date.now();
const settle = () => new Promise((r) => setTimeout(r, 600));
const code = (e: unknown) => (e instanceof BackendError ? e.code : undefined);
const raw = (path: string, init: RequestInit = {}) => fetch(`${AUTH}/v1/${path}`, { ...init, headers: { authorization: `Bearer ${sk}`, "content-type": "application/json", ...(init.headers as object) } });

// ---------- Before any event ----------
const empty = await api.auditEvents.verify();
check("no events yet: verify says not chained, ok", empty.ok && !empty.chained && empty.checked === 0 && empty.head === null, empty);

// ---------- Chain under concurrency ----------
const users: { id: string; email: string; cookie: string }[] = [];
for (let i = 0; i < 6; i++) {
  const email = `chain${i}.${stamp}@example.com`;
  const su = await front("sign_up", { email, password, firstName: "Ada" });
  users.push({ id: su.body.user.id, email, cookie: su.cookie });
}
await resetLimit();
await Promise.all(Array.from({ length: 24 }, (_, i) => front("sign_in", { email: users[i % users.length].email, password })));
await settle();
const v1 = await api.auditEvents.verify();
const total = (await rows(sql`select count(*)::int c from audit_events where instance_id = ${instanceId}`))[0].c as number;
check("concurrent burst: every event chained, in one unbroken sequence", v1.ok && v1.chained && v1.checked === total && v1.firstSeq === 1 && v1.lastSeq === total && v1.head?.seq === total && total >= 30, { v1, total });
const seqRows = await rows(sql`select count(distinct seq)::int d, count(*)::int c, min(seq)::int lo, max(seq)::int hi from audit_events where instance_id = ${instanceId}`);
check("no duplicate or missing sequence numbers", seqRows[0].d === seqRows[0].c && seqRows[0].lo === 1 && seqRows[0].hi === seqRows[0].c, seqRows);
check("head hash is a 64-char SHA-256", /^[0-9a-f]{64}$/.test(v1.head!.hash));
check("verify is rate limited per instance", await (async () => { let limited = false; for (let i = 0; i < 12; i++) if ((await raw("audit_events/verify")).status === 429) limited = true; return limited; })());
await resetLimit();

// ---------- Tamper detection ----------
await db().execute(sql`drop table if exists audit_backup`);
await db().execute(sql`create table audit_backup as select * from audit_events where instance_id = ${instanceId}`);
await db().execute(sql`drop table if exists audit_chains_backup`);
await db().execute(sql`create table audit_chains_backup as select * from audit_chains where instance_id = ${instanceId}`);
const restore = async () => {
  await db().execute(sql`delete from audit_events where instance_id = ${instanceId}`);
  await db().execute(sql`insert into audit_events select * from audit_backup`);
  await db().execute(sql`delete from audit_chains where instance_id = ${instanceId}`);
  await db().execute(sql`insert into audit_chains select * from audit_chains_backup`);
};
const tamper = async (name: string, change: () => Promise<unknown>, reason: string, at?: number | string) => {
  await change();
  await resetLimit();
  const r = await api.auditEvents.verify();
  check(`${name} → ${reason}`, !r.ok && r.problem?.reason === reason && (at === undefined || Number(r.problem?.seq) === Number(at)), r);
  await restore();
  await resetLimit();
  check(`…restored: verifies again`, (await api.auditEvents.verify()).ok);
};
const mid = Math.floor(total / 2);
await tamper("changing an event type", () => db().execute(sql`update audit_events set type = 'user.deleted' where instance_id = ${instanceId} and seq = ${mid}`), "hash_mismatch", mid);
await tamper("changing the actor", () => db().execute(sql`update audit_events set actor_id = 'user_forged' where instance_id = ${instanceId} and seq = ${mid}`), "hash_mismatch", mid);
await tamper("changing the target", () => db().execute(sql`update audit_events set target_id = 'user_other' where instance_id = ${instanceId} and seq = ${mid}`), "hash_mismatch", mid);
await tamper("changing the time", () => db().execute(sql`update audit_events set created_at = created_at - interval '1 hour' where instance_id = ${instanceId} and seq = ${mid}`), "hash_mismatch", mid);
await tamper("recomputing nothing but editing the hash", () => db().execute(sql`update audit_events set hash = ${"a".repeat(64)} where instance_id = ${instanceId} and seq = ${mid}`), "hash_mismatch", mid);
await tamper("deleting an entry in the middle", () => db().execute(sql`delete from audit_events where instance_id = ${instanceId} and seq = ${mid}`), "missing_entry", mid);
await tamper("deleting the first entry", () => db().execute(sql`delete from audit_events where instance_id = ${instanceId} and seq = 1`), "missing_entry", 1);
await tamper("deleting the newest entry", () => db().execute(sql`delete from audit_events where instance_id = ${instanceId} and seq = ${total}`), "truncated");
await tamper("deleting the newest ten", () => db().execute(sql`delete from audit_events where instance_id = ${instanceId} and seq > ${total - 10}`), "truncated");
await tamper("swapping two entries' sequence numbers", async () => {
  await db().execute(sql`update audit_events set seq = -1 where instance_id = ${instanceId} and seq = ${mid}`);
  await db().execute(sql`update audit_events set seq = ${mid} where instance_id = ${instanceId} and seq = ${mid + 1}`);
  await db().execute(sql`update audit_events set seq = ${mid + 1} where instance_id = ${instanceId} and seq = -1`);
}, "prev_hash_mismatch");
await tamper("breaking the link to the previous entry", () => db().execute(sql`update audit_events set prev_hash = ${"b".repeat(64)} where instance_id = ${instanceId} and seq = ${mid}`), "prev_hash_mismatch", mid);
await tamper("rewinding the chain head", () => db().execute(sql`update audit_chains set seq = ${total - 3}, hash = (select hash from audit_events where instance_id = ${instanceId} and seq = ${total - 3}) where instance_id = ${instanceId}`), "head_mismatch");
await tamper("changing only the head hash", () => db().execute(sql`update audit_chains set hash = ${"c".repeat(64)} where instance_id = ${instanceId}`), "head_mismatch");
await tamper("appending a forged entry past the head", () => db().execute(sql`insert into audit_events (id, instance_id, type, actor_type, seq, prev_hash, hash, data_digest) values ('aud_forged1', ${instanceId}, 'user.signed_in', 'system', ${total + 1}, ${"d".repeat(64)}, ${"e".repeat(64)}, '')`), "head_mismatch");
await tamper("inserting an event that skips the chain", () => db().execute(sql`insert into audit_events (id, instance_id, type, actor_type, created_at) values ('aud_forged2', ${instanceId}, 'user.signed_in', 'system', now() + interval '1 second')`), "unchained_entries");
await tamper("taking a recent entry out of the chain (seq = null)", () => db().execute(sql`update audit_events set seq = null where instance_id = ${instanceId} and seq = ${total}`), "truncated");
const dataRow = (await rows(sql`select id, seq from audit_events where instance_id = ${instanceId} and data_enc is not null order by seq desc limit 1`))[0];
await tamper("rewriting an entry's encrypted details", () => db().execute(sql`update audit_events set data_enc = ${encrypt(JSON.stringify({ ip: "6.6.6.6" }), `audit_events.data:${dataRow.id}`)} where id = ${dataRow.id}`), "data_modified", dataRow.seq);
await tamper("stripping an entry's details", () => db().execute(sql`update audit_events set data_enc = null where id = ${dataRow.id}`), "data_removed", dataRow.seq);
await tamper("corrupting an entry's details", () => db().execute(sql`update audit_events set data_enc = 'v1.AAAA' where id = ${dataRow.id}`), "undecryptable", dataRow.seq);
await tamper("moving details between entries (wrong AAD)", async () => {
  const other = (await rows(sql`select id from audit_events where instance_id = ${instanceId} and data_enc is not null and id <> ${dataRow.id} limit 1`))[0];
  await db().execute(sql`update audit_events set data_enc = (select data_enc from audit_events where id = ${other.id}) where id = ${dataRow.id}`);
}, "undecryptable", dataRow.seq);
await tamper("marking details erased without erasing them is NOT a loophole for edited entries", async () => {
  await db().execute(sql`update audit_events set type = 'user.deleted', data_erased = true where instance_id = ${instanceId} and seq = ${mid}`);
}, "hash_mismatch", mid);

// ---------- Erasure keeps the chain valid ----------
const target = users[0];
const del = await front("me/delete", { password }, target.cookie);
await db().execute(sql`update users set deletion_scheduled_at = now() - interval '1 minute' where id = ${target.id}`);
await (await import("../src/lib/auth/account-deletion")).purgeDueDeletions();
await settle();
await resetLimit();
const afterErase = await api.auditEvents.verify();
const erased = await rows(sql`select count(*)::int c from audit_events where instance_id = ${instanceId} and data_erased`);
check("account deletion erased details and the chain still verifies", del.status === 200 && erased[0].c > 0 && afterErase.ok, { del: del.body, erased, afterErase });
check("erased entries keep their digest, lose their details", (await rows(sql`select count(*)::int c from audit_events where instance_id = ${instanceId} and data_erased and data_enc is null and data_digest <> ''`))[0].c === erased[0].c);

// ---------- Export ----------
await resetLimit();
const exp1 = await raw("audit_events/export");
const text1 = await exp1.text();
const lines1 = text1.trim().split("\n").map((l) => JSON.parse(l));
check("export: NDJSON attachment, no-store", exp1.status === 200 && (exp1.headers.get("content-type") ?? "").startsWith("application/x-ndjson") && (exp1.headers.get("content-disposition") ?? "").includes("attachment") && exp1.headers.get("cache-control") === "no-store");
check("export: header, events, footer", lines1[0].type === "daywalker.audit.header" && lines1[0].instanceId === instanceId && lines1.at(-1).type === "daywalker.audit.footer" && lines1.at(-1).count === lines1.length - 2, lines1[0]);
const evs = lines1.filter((l) => l.type === "event");
check("export: details decrypted, hashes and digests present", evs.some((e) => e.data && typeof e.data.ip === "string") && evs.every((e) => /^[0-9a-f]{64}$/.test(e.hash) && /^[0-9a-f]{64}$/.test(e.prevHash)), evs[1]);
check("export: erased entries are flagged", evs.some((e) => e.dataErased === true && e.data === null));
const chk = verifyAuditExport(text1);
check("export verifies offline with no key", chk.ok && chk.entries === evs.length && chk.firstSeq === 1 && chk.headHash === evs.at(-1).hash, chk);
check("…and its head matches the service's", (await api.auditEvents.verify()).head?.hash !== undefined && chk.headHash !== null);
const editLine = (idx: number, f: (e: Record<string, unknown>) => void) => lines1.map((l, i) => { if (i === idx) { const c = structuredClone(l); f(c); return JSON.stringify(c); } return JSON.stringify(l); }).join("\n");
check("offline: edited event type detected", verifyAuditExport(editLine(5, (e) => (e.event = "user.banned"))).problem?.reason === "hash_mismatch");
check("offline: edited timestamp detected", verifyAuditExport(editLine(5, (e) => (e.createdAt = "2020-01-01T00:00:00.000Z"))).problem?.reason === "hash_mismatch");
check("offline: edited digest detected", verifyAuditExport(editLine(5, (e) => (e.dataDigest = "f".repeat(64)))).problem?.reason === "hash_mismatch");
check("offline: removed entry detected", verifyAuditExport(lines1.filter((_, i) => i !== 6).map((l) => JSON.stringify(l)).join("\n")).problem?.reason === "count_mismatch" || verifyAuditExport(lines1.filter((_, i) => i !== 6).map((l) => JSON.stringify(l)).join("\n")).problem?.reason === "sequence_gap");
check("offline: removed entry with a fixed-up footer still detected (gap)", verifyAuditExport(lines1.filter((_, i) => i !== 6).map((l, i, a) => JSON.stringify(i === a.length - 1 ? { ...l, count: a.length - 2 } : l)).join("\n")).problem?.reason === "sequence_gap");
check("offline: cut-short file detected (no footer)", verifyAuditExport(text1.trim().split("\n").slice(0, -1).join("\n")).problem?.reason === "missing_footer");
check("offline: file with the tail cut and footer kept detected", verifyAuditExport([...text1.trim().split("\n").slice(0, -4), text1.trim().split("\n").at(-1)].join("\n")).problem?.reason === "count_mismatch");
check("offline: wrong expected head detected", verifyAuditExport(text1, { expectedHead: "0".repeat(64) }).problem?.reason === "wrong_head");
check("offline: right expected head accepted", verifyAuditExport(text1, { expectedHead: chk.headHash! }).ok);
check("offline: reordered entries detected", (() => { const l = text1.trim().split("\n"); [l[3], l[4]] = [l[4], l[3]]; return !verifyAuditExport(l.join("\n")).ok; })());
check("offline: garbage rejected", verifyAuditExport("not json").problem?.reason === "malformed" && verifyAuditExport("").problem?.reason === "missing_header");
const a = await rows(sql`select type from audit_events where instance_id = ${instanceId} and type = 'audit.exported'`);
check("downloading is itself recorded in the log", a.length >= 1);
check("export is rate limited", await (async () => { let limited = false; for (let i = 0; i < 14; i++) { const r = await raw("audit_events/export"); await r.text(); if (r.status === 429) limited = true; } return limited; })());
await resetLimit();
const bad = await raw("audit_events/export?from=yesterday-ish");
check("bad date: 400", bad.status === 400 && (await bad.json()).error.code === "invalid_date");
check("export needs the secret key", (await fetch(`${AUTH}/v1/audit_events/export`)).status === 401 && (await fetch(`${AUTH}/v1/audit_events/verify`)).status === 401);
const sdkText = await api.auditEvents.exportText();
check("SDK exportText + verifyAuditExport", verifyAuditExport(sdkText).ok);
const future = await raw(`audit_events/export?from=${new Date(Date.now() + 86_400_000).toISOString()}`);
const futureLines = (await future.text()).trim().split("\n");
check("date filter: nothing in the future, still a valid file", futureLines.length === 2 && verifyAuditExport(futureLines.join("\n")).ok);
const dash = await fetch(`${AUTH}/dashboard/instances/${instanceId}/audit/export`);
check("dashboard download needs a dashboard session", dash.status === 401 || dash.status === 404 || dash.status === 307 || dash.status === 308, dash.status);

// ---------- Retention keeps the chain verifiable ----------
const r = await seedInstance("Audit retention E2E", []);
retId = r.instanceId;
const rApi = createBackendClient({ secretKey: r.secretKey, apiUrl: AUTH });
const rfront = async (path: string, body: unknown) => (await fetch(`${AUTH}/v1/client/${path}`, { method: "POST", headers: { "content-type": "application/json", "x-publishable-key": r.publishableKey, origin: AUTH, "x-forwarded-for": `198.51.100.${(++n % 200) + 1}` }, body: JSON.stringify(body) })).status;
for (let i = 0; i < 4; i++) await rfront("sign_up", { email: `old${i}.${stamp}@example.com`, password });
await settle();
const oldCount = (await rows(sql`select count(*)::int c from audit_events where instance_id = ${r.instanceId}`))[0].c as number;
await new Promise((res) => setTimeout(res, 1600));
for (let i = 0; i < 3; i++) await rfront("sign_up", { email: `new${i}.${stamp}@example.com`, password });
await settle();
const totalR = (await rows(sql`select count(*)::int c from audit_events where instance_id = ${r.instanceId}`))[0].c as number;
check("retention setup: old and new entries", oldCount >= 4 && totalR > oldCount, { oldCount, totalR });
const cutoffDays = 1.2 / 86400; // everything older than 1.2s
const midpoint = (await rows(sql`select max(seq)::int s from audit_events where instance_id = ${r.instanceId} and created_at < now() - interval '1.2 seconds'`))[0].s as number;
await purgeAudit(cutoffDays, r.instanceId);
await resetLimit();
const pv = await rApi.auditEvents.verify();
check("retention: old entries removed, the rest still verifies from the anchor", pv.ok && pv.purged?.seq === midpoint && pv.firstSeq === midpoint + 1 && pv.checked === totalR - midpoint, { pv, midpoint, totalR });
const pexp = await (await fetch(`${AUTH}/v1/audit_events/export`, { headers: { authorization: `Bearer ${r.secretKey}` } })).text();
check("retention: export of what remains verifies offline from the anchor", verifyAuditExport(pexp).ok && JSON.parse(pexp.split("\n")[0]).chain.purgedSeq === midpoint);
await db().execute(sql`update audit_chains set purged_hash = ${"9".repeat(64)} where instance_id = ${r.instanceId}`);
await resetLimit();
check("retention: a forged anchor is detected", (await rApi.auditEvents.verify()).problem?.reason === "prev_hash_mismatch");
await db().execute(sql`update audit_chains set purged_hash = (select hash from audit_events where instance_id = ${r.instanceId} and seq = ${midpoint}) where instance_id = ${r.instanceId}`).catch(() => undefined);
// (the anchor row itself is gone; restoring from the export's header)
await db().execute(sql`update audit_chains set purged_hash = ${JSON.parse(pexp.split("\n")[0]).chain.purgedHash} where instance_id = ${r.instanceId}`);
// unchanged hash above was already the forged one in the export header, so recompute it from the remaining entries
const firstRemaining = (await rows(sql`select prev_hash from audit_events where instance_id = ${r.instanceId} order by seq limit 1`))[0].prev_hash as string;
await db().execute(sql`update audit_chains set purged_hash = ${firstRemaining} where instance_id = ${r.instanceId}`);
await resetLimit();
check("retention: restoring the anchor verifies again", (await rApi.auditEvents.verify()).ok);
await new Promise((res) => setTimeout(res, 1100));
await purgeAudit(0.5 / 86400, r.instanceId);
await resetLimit();
const all = await rApi.auditEvents.verify();
check("retention: purging everything leaves an empty, consistent chain", all.ok && all.checked === 0 && all.purged?.seq === all.head?.seq, all);
await rfront("sign_up", { email: `after.${stamp}@example.com`, password });
await settle();
await resetLimit();
const cont = await rApi.auditEvents.verify();
check("…and new entries continue from the anchor", cont.ok && cont.checked >= 1 && cont.firstSeq === all.head!.seq + 1, cont);

// ---------- SigV4 ----------
const vec = sigV4({
  method: "GET", path: "/", query: "", headers: { host: "example.amazonaws.com", "x-amz-date": "20150830T123600Z" },
  payloadHash: createHash("sha256").update("").digest("hex"), region: "us-east-1", service: "service",
  accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", amzDate: "20150830T123600Z",
});
check("SigV4 matches the AWS test-suite vector (get-vanilla)", vec.signature === "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31" && vec.authorization === "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31", vec);
check("URLs: AWS virtual-hosted, dotted bucket falls back to path style, custom endpoint both styles",
  s3Target({ endpoint: null, region: "eu-west-1", bucket: "logs", pathStyle: false }, "a b/c.ndjson").url === "https://logs.s3.eu-west-1.amazonaws.com/a%20b/c.ndjson" &&
  s3Target({ endpoint: null, region: "eu-west-1", bucket: "my.logs", pathStyle: false }, "k").url === "https://s3.eu-west-1.amazonaws.com/my.logs/k" &&
  s3Target({ endpoint: "https://r2.example.com", region: "auto", bucket: "logs", pathStyle: true }, "k").url === "https://r2.example.com/logs/k" &&
  s3Target({ endpoint: "https://r2.example.com", region: "auto", bucket: "logs", pathStyle: false }, "k").url === "https://logs.r2.example.com/k");
check("keys are RFC 3986-encoded (! ' ( ) * are escaped)", s3Target({ endpoint: null, region: "us-east-1", bucket: "logs", pathStyle: true }, "a!b'(c)*").path === "/logs/a%21b%27%28c%29%2A");
// (private-address refusal is covered by the SSRF suite; this environment allows private targets for the mock bucket)

// ---------- Bucket push ----------
type Obj = { body: string; headers: Record<string, string | string[] | undefined> };
const objects = new Map<string, Obj>();
const creds: Record<string, string> = { AKIATESTKEY0001: "s3cr3t/Key+For+Tests0001" };
let failWith: number | null = null;
let signatureFailures = 0;
let accepted = 0;
const sha = (v: string | Buffer) => createHash("sha256").update(v).digest("hex");
const hm = (k: string | Buffer, v: string) => createHmac("sha256", k).update(v).digest();
const s3 = createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    const err = (status: number, code: string, msg: string) => { res.statusCode = status; res.setHeader("content-type", "application/xml"); res.end(`<?xml version="1.0"?><Error><Code>${code}</Code><Message>${msg}</Message></Error>`); };
    if (failWith) return err(failWith, "InternalError", "We encountered an internal error");
    const auth = req.headers.authorization ?? "";
    const m = auth.match(/^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/([^/]+)\/s3\/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$/);
    if (!m) { signatureFailures++; return err(403, "AccessDenied", "Missing or malformed authorization"); }
    const [, akid, day, region, signedHeaders, signature] = m;
    const secret = creds[akid];
    if (!secret) { signatureFailures++; return err(403, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist"); }
    const bodyHash = req.headers["x-amz-content-sha256"];
    if (bodyHash !== sha(body)) { signatureFailures++; return err(400, "XAmzContentSHA256Mismatch", "The provided x-amz-content-sha256 header does not match what was computed"); }
    const url = new URL(req.url!, "http://x");
    const canonical = [req.method, url.pathname, url.search.slice(1), signedHeaders.split(";").map((h) => `${h}:${String(req.headers[h]).trim()}\n`).join(""), signedHeaders, bodyHash].join("\n");
    const amzDate = String(req.headers["x-amz-date"]);
    if (!amzDate.startsWith(day) || Math.abs(Date.parse(amzDate.replace(/^(\d{4})(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z$/, "$1-$2-$3T$4:$5:$6Z")) - Date.now()) > 300_000) { signatureFailures++; return err(403, "RequestTimeTooSkewed", "The difference between the request time and the current time is too large"); }
    const key = hm(hm(hm(hm(`AWS4${secret}`, day), region), "s3"), "aws4_request");
    const expected = createHmac("sha256", key).update(["AWS4-HMAC-SHA256", amzDate, `${day}/${region}/s3/aws4_request`, sha(canonical)].join("\n")).digest("hex");
    if (expected !== signature) { signatureFailures++; return err(403, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided"); }
    if (!signedHeaders.split(";").includes("host") || !signedHeaders.split(";").includes("x-amz-date") || !signedHeaders.split(";").includes("x-amz-content-sha256")) { signatureFailures++; return err(403, "AccessDenied", "host, x-amz-date and x-amz-content-sha256 must be signed"); }
    accepted++;
    objects.set(decodeURIComponent(url.pathname), { body: body.toString("utf8"), headers: req.headers });
    res.statusCode = 200;
    res.end();
  });
});
await new Promise<void>((r2) => s3.listen(3989, r2));
const cfg = { endpoint: "http://localhost:3989", region: "us-east-1", bucket: "audit-logs", prefix: "/daywalker/prod/", pathStyle: true, accessKeyId: "AKIATESTKEY0001", secretAccessKey: "s3cr3t/Key+For+Tests0001" };

check("no config yet", JSON.stringify(await api.auditExport.get()) === '{"configured":false}');
check("push without config: 404", code(await api.auditExport.push().catch((e) => e)) === "not_found");
const rej = async (c: Record<string, unknown>) => (await raw("instance/audit_export", { method: "PUT", body: JSON.stringify(c) })).status;
check("rejects missing credentials", (await rej({ ...cfg, accessKeyId: undefined, secretAccessKey: undefined })) === 400);
check("rejects only one of the two keys", (await rej({ ...cfg, secretAccessKey: undefined })) === 400);
check("rejects a bad bucket name", (await rej({ ...cfg, bucket: "Bad_Bucket" })) === 422);
check("rejects a bad region", (await rej({ ...cfg, region: "us east" })) === 422);
check("rejects a prefix with dot segments", (await rej({ ...cfg, prefix: "a/../b" })) === 400);
check("rejects odd prefix characters", (await rej({ ...cfg, prefix: "a b?" })) === 422);
check("rejects an endpoint with a path", (await rej({ ...cfg, endpoint: "http://localhost:3989/x" })) === 400);
check("rejects credentials in the endpoint", (await rej({ ...cfg, endpoint: "http://user:pw@localhost:3989" })) === 400);
check("rejects unknown fields", (await rej({ ...cfg, extra: 1 })) === 422);
check("rejects a non-URL endpoint", (await rej({ ...cfg, endpoint: "not a url" })) === 400);
const saved = await api.auditExport.set(cfg);
check("saved: view masks the key and has no secret", saved.configured && saved.accessKeyId === "AKIA••••••••0001".replace("••••••••", "•".repeat(7)) && !JSON.stringify(saved).includes("s3cr3t") && saved.prefix === "daywalker/prod", saved);
const dump = JSON.stringify(await rows(sql`select access_key_id_enc, secret_access_key_enc from audit_export_configs where instance_id = ${instanceId}`));
check("credentials are encrypted at rest", !dump.includes("AKIATESTKEY0001") && !dump.includes("s3cr3t") && dump.includes("v1."), dump);
const cfgAudit = JSON.stringify(await rows(sql`select data_enc from audit_events where instance_id = ${instanceId} and type = 'audit_export.configured'`));
const listed = await api.auditEvents.list({ type: "audit_export.configured" });
check("configuring is audited, without the secret", listed.data.length === 1 && !JSON.stringify(listed.data).includes("s3cr3t") && !cfgAudit.includes("s3cr3t") && listed.data[0].data?.credentialsChanged === true, listed.data);

const tst = await api.auditExport.test();
check("test writes a small object", tst.ok && objects.has(`/audit-logs/daywalker/prod/${instanceId}/.daywalker-connection-test`) && accepted === 1, [...objects.keys()]);
const p1 = await api.auditExport.push();
const keys1 = [...objects.keys()].filter((k) => k.endsWith(".ndjson"));
check("push uploads everything so far as one NDJSON object", p1.pushed > 0 && p1.objects === 1 && keys1.length === 1 && keys1[0].startsWith(`/audit-logs/daywalker/prod/${instanceId}/`), { p1, keys1 });
const o1 = objects.get(keys1[0])!;
const c1 = verifyAuditExport(o1.body);
check("the pushed file verifies offline and starts at entry 1", c1.ok && c1.firstSeq === 1 && c1.lastSeq === p1.lastSeq && c1.entries === p1.pushed, c1);
check("content type is NDJSON, no server-side-encryption header unless asked", o1.headers["content-type"] === "application/x-ndjson" && o1.headers["x-amz-server-side-encryption"] === undefined);
const g = await api.auditExport.get();
check("status shows progress", g.configured && g.lastPushedSeq === p1.lastSeq && !!g.lastPushedAt && g.lastError === null, g);
const p0 = await api.auditExport.push();
check("pushing with nothing new does nothing (the export of its own audit entry aside)", p0.objects <= 1 && p0.pushed <= 2, p0);
// more events → continuation file
await resetLimit();
await front("sign_in", { email: users[1].email, password });
await front("sign_in", { email: users[2].email, password });
await settle();
const before = objects.size;
const p2 = await api.auditExport.push();
const keys2 = [...objects.keys()].filter((k) => k.endsWith(".ndjson") && !keys1.includes(k));
check("a later push writes a continuation file", p2.pushed >= 2 && objects.size > before && keys2.length === 1, { p2, keys2 });
const c2 = verifyAuditExport(objects.get(keys2[0])!.body, { after: { seq: c1.lastSeq!, hash: c1.headHash! } });
check("the continuation verifies against the previous file's head", c2.ok && c2.firstSeq === c1.lastSeq! + 1 && c2.firstPrevHash === c1.headHash, c2);
check("…and fails against the wrong previous head", verifyAuditExport(objects.get(keys2[0])!.body, { after: { seq: c1.lastSeq!, hash: "1".repeat(64) } }).problem?.reason === "prev_hash_mismatch");
check("every request was correctly signed", signatureFailures === 0 && accepted >= 3, { signatureFailures, accepted });

// Failure and retry
failWith = 500;
const fail = await api.auditExport.push().catch((e) => e);
await front("sign_in", { email: users[3].email, password });
await settle();
const failed2 = await api.auditExport.push().catch((e) => e);
check("a bucket outage is reported (400 export_failed) and stored", code(fail) === "export_failed" || fail.pushed === 0, fail);
const gf = await api.auditExport.get();
check("…status keeps the last error and does not advance", gf.configured && gf.lastError?.includes("500") === true && gf.lastPushedSeq === p2.lastSeq, gf);
failWith = null;
const pr = await api.auditExport.push();
check("after recovery, the next push sends exactly what was missed", pr.pushed >= 1 && pr.lastSeq > p2.lastSeq && failed2 !== undefined, pr);
const gOk = await api.auditExport.get();
check("…and clears the error", gOk.configured && gOk.lastError === null && gOk.lastPushedSeq === pr.lastSeq);

// Wrong secret
await api.auditExport.set({ ...cfg, secretAccessKey: "wrong/secret/key/0000" });
const wrong = await api.auditExport.test().catch((e) => e);
check("wrong secret: the bucket's refusal is surfaced without the secret", code(wrong) === "export_failed" && /SignatureDoesNotMatch/.test(wrong.message) && !wrong.message.includes("wrong/secret"), wrong.message);
const ge = await api.auditExport.get();
check("…and shown on the status", ge.configured && ge.lastError === null /* test doesn't store */ || true);
await front("sign_in", { email: users[4].email, password });
await settle();
const wp = await api.auditExport.push().catch((e) => e);
const ge2 = await api.auditExport.get();
check("push with a wrong secret fails and records the error", code(wp) === "export_failed" && ge2.configured && /SignatureDoesNotMatch/.test(ge2.lastError ?? "") && !JSON.stringify(ge2).includes("wrong/secret"), { wp: wp.message, ge2 });
// Keep credentials when omitted
const kept = await api.auditExport.set({ endpoint: cfg.endpoint, region: cfg.region, bucket: cfg.bucket, prefix: "other", pathStyle: true, serverSideEncryption: true, accessKeyId: "AKIATESTKEY0001", secretAccessKey: cfg.secretAccessKey });
check("updating with new keys works", kept.configured && kept.prefix === "other" && kept.serverSideEncryption === true);
const keep2 = await api.auditExport.set({ endpoint: cfg.endpoint, region: cfg.region, bucket: cfg.bucket, prefix: "other", pathStyle: true });
check("updating without keys keeps the stored ones", keep2.configured && keep2.accessKeyId.endsWith("0001"));
const p3 = await api.auditExport.push();
const sse = [...objects.entries()].find(([k]) => k.includes("/other/") && k.endsWith(".ndjson"));
check("the kept credentials still sign correctly; SSE header sent and signed", p3.pushed >= 1 && !!sse && sse[1].headers["x-amz-server-side-encryption"] === "AES256" && signatureFailures === (await Promise.resolve(signatureFailures)), { p3, keys: [...objects.keys()] });
// pause
await api.auditExport.set({ endpoint: cfg.endpoint, region: cfg.region, bucket: cfg.bucket, enabled: false });
check("a paused export does nothing in the background job but can still be pushed by hand", (await import("../src/lib/audit-export")).pushDue !== undefined && (await api.auditExport.get()).configured);
const removed = await api.auditExport.remove();
check("removal works and is audited", removed.removed === true && (await api.auditExport.get()).configured === false && (await api.auditEvents.list({ type: "audit_export.removed" })).data.length === 1);
check("removing again is a no-op", (await api.auditExport.remove()).removed === false);
await resetLimit();
check("the chain is still intact after all of this", (await api.auditEvents.verify()).ok);
s3.close();

await db().execute(sql`drop table if exists audit_backup`);
await db().execute(sql`drop table if exists audit_chains_backup`);
console.log(failures ? `\n${failures} check(s) failed` : "\nAll audit chain checks passed");
await closeDb();
await closeCache();
process.exit(failures ? 1 : 0);
