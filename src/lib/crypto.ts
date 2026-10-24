import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from "node:crypto";
import { hash, verify } from "@node-rs/argon2";
import { env } from "./env";

// ---------- Passwords ----------
// OWASP argon2id baseline (19 MiB, t=2, p=1). Hash strings embed params, so raising these later is safe.
const ARGON = { memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;

export const hashPassword = (pw: string) => hash(pw, ARGON);
export const verifyPassword = (digest: string, pw: string) => verify(digest, pw).catch(() => false);

/** Verified against when an account doesn't exist, so timing doesn't reveal which emails are registered. */
let dummy: Promise<string> | undefined;
export const dummyHash = () => (dummy ??= hashPassword(randomBytes(24).toString("hex")));

// ---------- Key hierarchy ----------
// MASTER_KEY never encrypts data directly. Purpose-specific subkeys are derived with HKDF,
// so a bug in one use can't be turned against another.
//
// Encryption and lookup indexes use SEPARATE keys. Blind indexes (email lookups, OAuth identities,
// backup-code hashes) can't be recomputed after the fact, because some of their inputs are never
// stored. So INDEX_KEY can be pinned: rotating MASTER_KEY then re-encrypts data without
// invalidating any index. When INDEX_KEY is unset, it's derived from MASTER_KEY as before.
const KEY_VERSION = "v1";
/** MASTER_KEY is 48 random bytes (`openssl rand -base64 48`); HKDF derives the 32-byte subkeys from it. */
export const MASTER_KEY_BYTES = 48;

const b64key = (v: string, name: string, bytes: number) => {
  const k = Buffer.from(v, "base64");
  if (k.length !== bytes) throw new Error(`${name} must be ${bytes} random bytes, base64-encoded`);
  return k;
};
const derive = (master: Buffer, purpose: "enc" | "index") =>
  Buffer.from(hkdfSync("sha256", master, Buffer.alloc(0), `daywalker-auth/${KEY_VERSION}/${purpose}`, 32));

/** The index key MASTER_KEY currently implies. Print it, then set it as INDEX_KEY before rotating. */
export const deriveIndexKey = (masterKeyB64: string) => derive(b64key(masterKeyB64, "MASTER_KEY", MASTER_KEY_BYTES), "index").toString("base64");

/**
 * A cipher bound to specific keys. The app uses one built from the environment; the rotation
 * script builds two (old and new) to re-encrypt data.
 */
export function createCipher(masterKeyB64: string, indexKeyB64?: string) {
  const master = b64key(masterKeyB64, "MASTER_KEY", MASTER_KEY_BYTES);
  const encKey = derive(master, "enc");
  const indexKey = indexKeyB64 ? b64key(indexKeyB64, "INDEX_KEY", 32) : derive(master, "index");

  /**
   * AES-256-GCM. Output: "v1.<base64(iv|tag|ciphertext)>".
   * `context` is bound as AAD, typically "<table>.<column>:<row id>", so a ciphertext copied
   * into another row or column fails to decrypt instead of silently revealing data.
   */
  function encrypt(plaintext: string, context: string) {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", encKey, iv);
    c.setAAD(Buffer.from(context));
    const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
    return `${KEY_VERSION}.${Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64")}`;
  }

  function decrypt(payload: string, context: string) {
    const [version, body] = payload.split(".", 2);
    if (version !== KEY_VERSION || !body) throw new Error("Unsupported ciphertext version");
    const buf = Buffer.from(body, "base64");
    const d = createDecipheriv("aes-256-gcm", encKey, buf.subarray(0, 12));
    d.setAAD(Buffer.from(context));
    d.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString("utf8");
  }

  /**
   * Keyed blind index (HMAC-SHA256) for exact-match lookups on encrypted fields such as email.
   * Without the key, the index can't be brute-forced from a list of known emails.
   */
  const blindIndex = (value: string, purpose: string) => createHmac("sha256", indexKey).update(`${purpose}\0${value}`).digest("hex");

  return { encrypt, decrypt, blindIndex };
}

let appCipher: ReturnType<typeof createCipher> | undefined;
const app = () => (appCipher ??= createCipher(env().MASTER_KEY, env().INDEX_KEY || undefined));

// ---------- Field encryption (uses the keys from the environment) ----------
export const encrypt = (plaintext: string, context: string) => app().encrypt(plaintext, context);
export const decrypt = (payload: string, context: string) => app().decrypt(payload, context);
export const encryptNullable = (v: string | null | undefined, ctx: string) => (v ? encrypt(v, ctx) : null);
export const decryptNullable = (v: string | null | undefined, ctx: string) => (v ? decrypt(v, ctx) : null);
export const blindIndex = (value: string, purpose: string) => app().blindIndex(value, purpose);
