# Backup, restore and the restore drill (operator runbook)

A backup you have never restored is a hope, not a backup. This page says what to back up, how to restore, and how to prove on a schedule that the backup works **and** that the restored data is still readable.

## What a complete backup is

| Piece | Where it lives | Backed up how | If you lose it |
|---|---|---|---|
| **Postgres** (all user, session, organization, audit and webhook data) | DigitalOcean managed database `daywalker-prod-db-cluster` | Managed daily backups (7 days) and point-in-time recovery; see the cluster's **Backups** tab | Everything is gone |
| **`MASTER_KEY`** | App Platform secret | **Not in the database.** Keep it in two independent places (your password manager and an offline copy, for example a printed sheet in a safe) | The database backup is ciphertext nobody can read. Every encrypted value (names, emails, signing keys, webhook secrets...) is lost for good |
| **`INDEX_KEY`** | App Platform secret | Same as `MASTER_KEY` (`npm run keys:print-index-key` prints the one your `MASTER_KEY` implies) | Nobody can sign in: email lookups no longer find users |
| **`PASSKEY_RP_ID`** | `.do/app.yaml` (`daywalker.dev`) | In git | Every passkey and security key stops working if it differs; restore exactly `daywalker.dev` |
| Valkey | DigitalOcean managed Valkey | **Not backed up, by design** | Harmless: caches, rate-limit counters and short-lived codes rebuild or expire; people may have to request a new sign-in code |
| Audit export bucket (optional) | Your S3-compatible bucket | Append-only NDJSON the service pushes every 15 minutes | Lose the off-site copy of the audit log (the database copy remains) |

**A backup can be read only with the `MASTER_KEY` it was made under.** After you rotate `MASTER_KEY` (see the rotating-keys guide), older backups still need the *old* key. Keep the old key until every backup made under it has aged out of your retention window, then destroy it. The drill below takes the key as an input for exactly this reason.

## The restore drill

`scripts/backup-drill.ts` (`npm run drill:backup`) proves, end to end, that a backup is restorable and usable:

1. `pg_dump` of the source at one consistent snapshot (read-only; the source is never written to).
2. Restore into a brand-new scratch database `drill_<random>`.
3. Row counts of every table match the snapshot.
4. **Every encrypted field decrypts** with `MASTER_KEY` (all columns in `src/lib/crypto-fields.ts`; AES-GCM also proves nothing was altered or moved), **email blind indexes match** `INDEX_KEY` (sign-in can find the user), and **every instance's audit hash chain verifies** (nothing missing, rewritten or reordered).
5. **`MASTER_KEY` rotation on the restored copy** with the real `keys:rotate-master` script, then step 4 again with the new key, and a check that the old key no longer decrypts. This proves the restored data survives a rotation, which is the operation you will do under pressure after a key leak.
6. The scratch database is dropped and the dump deleted (also on failure).

### Run it

Prerequisites: a checkout with `npm ci`; PostgreSQL client tools (`pg_dump`, `pg_restore`) of the same major version as the server or newer; the keys the backup was made under.

```bash
# Drill the live database (read-only snapshot), with the scratch copy on a throwaway local Postgres:
docker run -d --name drill-pg -e POSTGRES_PASSWORD=drill -p 55432:5432 postgres:16
export MASTER_KEY=...            # the key in production (from your secret store)
export INDEX_KEY=...             # optional; defaults to the one MASTER_KEY implies
export SOURCE_DATABASE_URL='postgres://...?sslmode=require'   # a read-only role is enough
export DATABASE_CA_CERT="$(cat do-ca.pem)"                      # for verified TLS to DigitalOcean
export DRILL_ADMIN_URL='postgres://postgres:drill@localhost:55432/postgres'
npm run drill:backup
docker rm -f drill-pg
```

To drill an actual backup rather than the live database, restore it to a *new* cluster from the DigitalOcean **Backups** tab and point `SOURCE_DATABASE_URL` at that. That also tests the platform's restore path, not just `pg_dump`.

Options: `DRILL_SKIP_ROTATION=1`, `DRILL_SAMPLE_PER_COLUMN=1000` (spot-check very large tables), `DRILL_KEEP=1` (keep the scratch database and dump for debugging; delete them yourself).

### Handling the data

The scratch copy is a full copy of production: encrypted personal data, password hashes and blind indexes. So:

- Run the drill on a machine you trust with it (encrypted disk). Do not host the scratch database on the production cluster if you can avoid it: use `DRILL_ADMIN_URL` on a throwaway server.
- The dump is written to a private temp directory (mode 0700, file 0600) and deleted at the end. Keys reach child processes through the environment, never a command line, and passwords go to `pg_dump` through `PG*` variables, so they don't show in a process list.
- The script prints counts and row IDs only, never plaintext. Don't paste the output anywhere that wouldn't take "the database has 8012 rows".

### Cadence

- **Monthly**, against the newest managed backup restored to a fresh cluster.
- **After every `MASTER_KEY` rotation** (run it with the *new* key against a backup taken after the rotation, and once with the old key against an older backup).
- **Before and after** a Postgres major version upgrade, and after any migration that adds an encrypted column (the registry test catches a forgotten column; the drill proves real data).
- Record the date, the duration printed at the end (your measured restore-plus-verify time for the current data size, the honest input for an RTO) and the result.

### When it fails

| Failing step | Most likely cause | What to do |
|---|---|---|
| `pg_dump` / `restore` | Client older than server; network/TLS; role lacks read on a table | Use matching tools; fix connectivity; use a role that can read everything |
| Row counts differ | Should not happen (same snapshot). Possible extension/trigger side effects | Treat as a real failure; inspect the named table |
| Encrypted fields do not decrypt | Wrong `MASTER_KEY` for this backup (a rotation happened, or the wrong secret was exported), or data corruption | Try the previous key. If a few IDs fail and the rest pass, suspect corruption or a column added without the right AAD context; the failing `table.column (count: ids)` is printed |
| Email blind indexes mismatch | `INDEX_KEY` isn't the one the data was indexed with | Use the pinned production value (`keys:print-index-key` with the key *at the time*) |
| Audit chain fails | Tampering, a bad restore point, or a bug. The reason (`hash_mismatch`, `missing_entry`, `truncated`...) and sequence number are printed | Treat as a security incident until explained. Compare with the audit export bucket and the heads you saved with the dashboard's verify button |
| Rotation fails on the copy | A new encrypted column is not in the rotation registry, or data is already damaged | Fix the registry (`masterkey-e2e` should have caught it) and re-run |

## Restoring for real (disaster procedure)

1. **Stop writes.** Scale the `web` service to zero instances (or put the app in maintenance) so nothing writes to a half-restored system. Decide the restore point: the latest backup, or point-in-time just before the incident.
2. **Restore the database** to a **new** managed cluster from the Backups tab (do not restore over the damaged one: keep it for forensics). Add the app as a trusted source; create the same database and user the spec expects (`daywalker_auth_db` / `daywalker_auth_usr`, no access to other databases).
3. **Keep every secret the same:** `MASTER_KEY` (the one the backup was made under), `INDEX_KEY`, and `PASSKEY_RP_ID=daywalker.dev`. Change nothing else at the same time.
4. **Point the app at the new cluster:** update `databases` in `.do/app.yaml` (`cluster_name`) and apply the spec. The `PRE_DEPLOY` job runs `node migrate.mjs`, which brings an older backup up to the current schema.
5. **Verify before reopening traffic:** run the drill with `SOURCE_DATABASE_URL` set to the restored database (read-only), then check `GET /v1/health` (database, signing keys, jobs), `/status`, and a sign-in with a test account. Verify each important instance's audit chain from the dashboard.
6. **Reopen,** scale the service back up, and watch `/v1/health` for a few minutes (jobs report degraded until the first job-loop tick).
7. **Account for the gap.** Anything after the restore point is gone from Postgres: sign-ups and password changes (users may need to reset), audit entries (compare the chain head with the last export in your bucket), and webhook deliveries (use replay for events your receivers missed, `POST /v1/webhooks/deliveries/replay`, and expect receivers to de-duplicate by event ID).
8. **If compromise is suspected,** also rotate `MASTER_KEY` (rotating-keys guide), rotate signing keys per instance, and revoke sessions. Write the post-incident notes while it is fresh.

## What is not covered

The drill proves the database backup and the keys work together. It does not test the DigitalOcean restore UI, your DNS, the Resend/Twilio accounts, or that the people on call know this page. Rehearse the disaster procedure end to end at least once a year, on a staging copy.
