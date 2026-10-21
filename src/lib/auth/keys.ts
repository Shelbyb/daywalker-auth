import { and, eq } from "drizzle-orm";
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

// Decrypted private keys live only in process memory, never in Valkey.
const signers = new Map<string, { kid: string; key: CryptoKey; at: number }>();

async function getSigner(instanceId: string) {
  const mem = signers.get(instanceId);
  if (mem && Date.now() - mem.at < 300_000) return mem;
  const [row] = await db()
    .select()
    .from(schema.signingKeys)
    .where(and(eq(schema.signingKeys.instanceId, instanceId), eq(schema.signingKeys.active, true)))
    .limit(1);
  if (!row) throw new Error(`No active signing key for ${instanceId}`);
  const key = (await importJWK(JSON.parse(decrypt(row.privateKeyEnc, `signing_keys.private:${row.id}`)) as JWK, ALG)) as CryptoKey;
  const signer = { kid: row.id, key, at: Date.now() };
  signers.set(instanceId, signer);
  return signer;
}

export type SessionClaims = { sub: string; sid: string; azp?: string };

/** Short-lived session JWT. Apps verify it locally against the JWKS. */
export async function mintSessionToken(instanceId: string, claims: SessionClaims, ttlSeconds: number) {
  const { kid, key } = await getSigner(instanceId);
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sid: claims.sid, ...(claims.azp ? { azp: claims.azp } : {}) })
    .setProtectedHeader({ alg: ALG, kid, typ: "JWT" })
    .setIssuer(issuerFor(instanceId))
    .setSubject(claims.sub)
    .setIssuedAt(now)
    .setNotBefore(now - 5) // tolerate small clock skew
    .setExpirationTime(now + ttlSeconds)
    .sign(key);
}
