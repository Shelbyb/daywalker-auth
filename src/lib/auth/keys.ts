import { and, desc, eq, lt } from "drizzle-orm";
import { generateKeyPair, exportJWK, importJWK, SignJWT, type CryptoKey, type JWK } from "jose";
import { db, schema } from "../db";
import { cached, cache } from "../cache";
import { encrypt, decrypt } from "../crypto";
import { newId } from "../ids";
import { env } from "../env";

const ALG = "ES256";

export const issuerFor = (instanceId: string) => `${env().APP_URL}/i/${instanceId}`;

export async function createSigningKey(instanceId: string) {
  const { publicKey, privateKey } = await generateKeyPair(ALG, { extractable: true });
  const kid = newId("key");
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: ALG, use: "sig" };
  const privateJwk = await exportJWK(privateKey);
  await db().insert(schema.signingKeys).values({
    id: kid,
    instanceId,
    alg: ALG,
    publicJwk,
    privateKeyEnc: encrypt(JSON.stringify(privateJwk), `signing_keys.private:${kid}`),
  });
  await cache().del(`jwks:${instanceId}`, `signer:${instanceId}`);
  return kid;
}

/** Public keys for the instance (active + recently retired, so in-flight tokens still verify). */
export async function getJwks(instanceId: string) {
  return cached(`jwks:${instanceId}`, 300, async () => {
    const rows = await db()
      .select({ jwk: schema.signingKeys.publicJwk })
      .from(schema.signingKeys)
      .where(eq(schema.signingKeys.instanceId, instanceId));
    return { keys: rows.map((r) => r.jwk) };
  });
}

/**
 * Rotates the key that signs session tokens: a new key becomes the signer, and the old one is
 * retired but stays in the JWKS so tokens already issued (and apps that cached the key set)
 * keep working. Nobody is signed out. Retired keys are removed later by `purgeRetiredKeys`.
 */
export async function rotateSigningKey(instanceId: string) {
  const { publicKey, privateKey } = await generateKeyPair(ALG, { extractable: true });
  const kid = newId("key");
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: ALG, use: "sig" };
  const privateJwk = await exportJWK(privateKey);
  const retired = await db().transaction(async (tx) => {
    const old = await tx
      .update(schema.signingKeys)
      .set({ active: false, retiredAt: new Date() })
      .where(and(eq(schema.signingKeys.instanceId, instanceId), eq(schema.signingKeys.active, true)))
      .returning({ id: schema.signingKeys.id });
    await tx.insert(schema.signingKeys).values({
      id: kid,
      instanceId,
      alg: ALG,
      publicJwk,
      privateKeyEnc: encrypt(JSON.stringify(privateJwk), `signing_keys.private:${kid}`),
    });
    return old.length;
  });
  signers.delete(instanceId); // this process signs with the new key straight away
  await cache().del(`jwks:${instanceId}`);
  return { kid, retired };
}

/** Public details of an instance's signing keys (never the private key). */
export async function listSigningKeys(instanceId: string) {
  const rows = await db().select().from(schema.signingKeys).where(eq(schema.signingKeys.instanceId, instanceId)).orderBy(desc(schema.signingKeys.createdAt));
  return rows.map((k) => ({ id: k.id, alg: k.alg, active: k.active, createdAt: k.createdAt, retiredAt: k.retiredAt }));
}

/** Tokens live 60 seconds and apps cache the key set for 10 minutes, so a day is generous. */
const RETIRED_KEY_GRACE_MS = 24 * 3_600_000;

/** Removes keys retired longer ago than the grace period. Never touches an active key. */
export async function purgeRetiredKeys() {
  const rows = await db()
    .delete(schema.signingKeys)
    .where(and(eq(schema.signingKeys.active, false), lt(schema.signingKeys.retiredAt, new Date(Date.now() - RETIRED_KEY_GRACE_MS))))
    .returning({ instanceId: schema.signingKeys.instanceId });
  const ids = [...new Set(rows.map((r) => r.instanceId))];
  if (ids.length) await cache().del(...ids.map((i) => `jwks:${i}`));
  return rows.length;
}

// Decrypted private keys live only in process memory, never in Valkey.
const signers = new Map<string, { kid: string; key: CryptoKey; at: number }>();

async function getSigner(instanceId: string) {
  const mem = signers.get(instanceId);
  if (mem && Date.now() - mem.at < 300_000) return mem;
  const [row] = await db()
    .select()
    .from(schema.signingKeys)
    .where(and(eq(schema.signingKeys.instanceId, instanceId), eq(schema.signingKeys.active, true)))
    .orderBy(desc(schema.signingKeys.createdAt)) // newest active key wins, deterministically
    .limit(1);
  if (!row) throw new Error(`No active signing key for ${instanceId}`);
  const key = (await importJWK(JSON.parse(decrypt(row.privateKeyEnc, `signing_keys.private:${row.id}`)) as JWK, ALG)) as CryptoKey;
  const signer = { kid: row.id, key, at: Date.now() };
  signers.set(instanceId, signer);
  return signer;
}

export type SessionClaims = { sub: string; sid: string; azp?: string; org?: { org_id: string; org_role: string }; custom?: Record<string, string> };

/** Short-lived session JWT. Apps verify it locally against the JWKS. */
export async function mintSessionToken(instanceId: string, claims: SessionClaims, ttlSeconds: number) {
  const { kid, key } = await getSigner(instanceId);
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ ...(claims.custom ?? {}), sid: claims.sid, ...(claims.azp ? { azp: claims.azp } : {}), ...(claims.org ?? {}) })
    .setProtectedHeader({ alg: ALG, kid, typ: "JWT" })
    .setIssuer(issuerFor(instanceId))
    .setSubject(claims.sub)
    .setIssuedAt(now)
    .setNotBefore(now - 5) // tolerate small clock skew
    .setExpirationTime(now + ttlSeconds)
    .sign(key);
}
