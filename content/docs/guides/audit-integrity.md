---
title: Tamper-evident audit log
description: Prove your audit log hasn't been edited, export it, and copy it to your own bucket.
---

# Tamper-evident audit log

Every audit event is linked to the one before it by a SHA-256 hash, like a ledger. Changing, reordering, inserting or deleting any entry breaks every link after it, and the break is found by a check you can run any time.

Each entry stores a sequence number (`seq`), the previous entry's hash (`prevHash`) and its own `hash`, which covers the instance, sequence number, previous hash, id, type, actor, target, time and a keyed digest of the event's details. The details stay encrypted in the database. The digest means the log can still be verified after an account is erased or the master key is rotated.

## Verify integrity

In the dashboard, open **Audit log** and choose **Verify integrity**. From your backend:

```ts
const result = await daywalker.auditEvents.verify();
if (!result.ok) console.error(result.problem); // { seq, id, reason, message }
```

Or `GET /v1/audit_events/verify` with your secret key. Verification is limited to 10 requests a minute per instance.

| `problem.reason` | What happened |
| --- | --- |
| `hash_mismatch` | An entry's fields were changed |
| `prev_hash_mismatch` | An entry doesn't follow from the one before it (reordered, or the link was edited) |
| `missing_entry` | An entry in the middle was deleted |
| `truncated` / `head_mismatch` | Newest entries were removed, or the chain head was altered |
| `unchained_entries` | A row was inserted that skips the chain |
| `data_modified` / `data_removed` / `undecryptable` | An entry's encrypted details were changed, stripped or corrupted |

Events written while a check is running are tolerated; the check covers everything up to the head it read at the start.

## Retention and erasure

The 90-day purge records the last removed entry as an anchor, so what remains still verifies from that point. When a user deletes their account, the personal details in their audit entries are erased and the entries are flagged `dataErased`; the digest is kept, so the chain stays valid.

## Export

```ts
const ndjson = await daywalker.auditEvents.exportText({ from, to });
```

`GET /v1/audit_events/export?from=&to=` streams newline-delimited JSON: a header line, one line per event (details decrypted), and a footer line with the count. The dashboard has a **Download NDJSON** link. Downloading is recorded as `audit.exported`, and is limited to 12 per hour.

Check a file offline, with no key and no network:

```ts
import { verifyAuditExport } from "@daywalker/auth/server";

const check = verifyAuditExport(ndjson, {
  expectedHead: "…hash you stored earlier…", // optional: catches a file cut short
  after: { seq: 120, hash: "…" },            // optional: a continuation of an earlier file
});
```

Store the head hash somewhere the log's operator can't write to if you need to detect a full rewrite.

## Push to your own bucket

Send the log to any S3-compatible bucket (AWS S3, Cloudflare R2, MinIO, Backblaze B2). Open **Audit log** and fill in **Bucket export**, or use the API:

```ts
await daywalker.auditExport.set({
  region: "us-east-1", bucket: "my-audit-logs", prefix: "daywalker/prod",
  accessKeyId: "…", secretAccessKey: "…",
  // endpoint: "https://<account>.r2.cloudflarestorage.com", pathStyle: true,
});
await daywalker.auditExport.test(); // writes a small test object
await daywalker.auditExport.push(); // upload now
```

- Requests are signed with AWS Signature V4 and sent through the same SSRF guard as webhooks, so endpoints on private networks are refused.
- The access key and secret are encrypted at rest and never returned; the dashboard shows a masked key. Leave them out when updating to keep the stored ones.
- A background job pushes new entries every 15 minutes, one NDJSON object per push under `prefix/<instanceId>/`. Each file continues from the previous one, so you can verify them in order with the `after` option.
- The position only advances once the bucket accepts the object. Failures are shown as the last error and retried on the next run.
- Give the key write-only access to the prefix, and enable object lock on the bucket for an immutable copy.

Configuring and removing the export are themselves audited (`audit_export.configured`, `audit_export.removed`).
