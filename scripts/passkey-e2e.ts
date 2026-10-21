/**
 * Passkey checks with a software authenticator: real P-256 keys, CBOR attestation objects
 * and ECDSA assertions, verified by the same server code a real device would hit.
 * Needs the service on :3000 (RP ID "localhost").
 */
import { createHash, generateKeyPairSync, sign, randomBytes, type KeyObject } from "node:crypto";
import { Encoder } from "cbor-x";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { sha256 } from "../src/lib/ids";
import { totpAt, currentCounter } from "../src/lib/auth/totp";

const AUTH = "http://localhost:3000";
const RP_ID = "localhost";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};

// ---------- Software authenticator ----------
const cbor = new Encoder({ mapsAsObjects: false, useRecords: false });
const b64u = (b: Buffer | Uint8Array) => Buffer.from(b).toString("base64url");
const h256 = (b: Buffer | string) => createHash("sha256").update(b).digest();
const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 };

class SoftAuthenticator {
  credId = randomBytes(32);
  keys = generateKeyPairSync("ec", { namedCurve: "P-256" });
  counter = 0;
  userHandle: string | null = null;
  constructor(public synced = false) {}

  private coseKey() {
    const jwk = this.keys.publicKey.export({ format: "jwk" });
    return cbor.encode(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")]]));
  }

  register(options: { challenge: string; user: { id: string } }, o: { origin?: string; uv?: boolean; challenge?: string } = {}) {
    this.userHandle = options.user.id;
    const flags = FLAG.UP | FLAG.AT | (o.uv === false ? 0 : FLAG.UV) | (this.synced ? FLAG.BE | FLAG.BS : 0);
    const credLen = Buffer.alloc(2);
    credLen.writeUInt16BE(this.credId.length);
    const authData = Buffer.concat([h256(RP_ID), Buffer.from([flags]), u32(0), Buffer.alloc(16), credLen, this.credId, this.coseKey()]);
    const clientData = JSON.stringify({ type: "webauthn.create", challenge: o.challenge ?? options.challenge, origin: o.origin ?? AUTH, crossOrigin: false });
    return {
      id: b64u(this.credId),
      rawId: b64u(this.credId),
      type: "public-key",
      response: {
        clientDataJSON: b64u(Buffer.from(clientData)),
        attestationObject: b64u(cbor.encode(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]))),
        transports: ["internal"],
      },
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
    };
  }

  assert(challenge: string, o: { counter?: number; uv?: boolean; signWith?: KeyObject; userHandle?: string | null; tamper?: boolean; origin?: string } = {}) {
    this.counter = o.counter ?? this.counter + 1;
    const flags = FLAG.UP | (o.uv === false ? 0 : FLAG.UV) | (this.synced ? FLAG.BE | FLAG.BS : 0);
    const authData = Buffer.concat([h256(RP_ID), Buffer.from([flags]), u32(this.counter)]);
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: o.origin ?? AUTH, crossOrigin: false }));
    const signature = sign("sha256", Buffer.concat([authData, h256(clientData)]), o.signWith ?? this.keys.privateKey); // DER, as authenticators produce
    if (o.tamper) authData[authData.length - 1] ^= 0xff; // flip a counter byte after signing
    const handle = o.userHandle === undefined ? this.userHandle : o.userHandle;
    return {
      id: b64u(this.credId),
      rawId: b64u(this.credId),
      type: "public-key",
      response: { clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(signature), ...(handle ? { userHandle: handle } : {}) },
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
    };
  }
}

// ---------- Browser helper ----------
const { publishableKey: pk, instanceId } = await seedInstance("Passkey E2E", []);
const other = await seedInstance("Passkey E2E other", []);

class Browser {
  cookies = new Map<string, string>();
  constructor(public key = pk) {}
  async call(method: string, path: string, body?: unknown) {
    const res = await fetch(`${AUTH}/v1/client/${path}`, {
      method,
      headers: { "content-type": "application/json", "x-publishable-key": this.key, origin: AUTH, cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ") },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) {
      const kv = c.split(";")[0];
      const k = kv.slice(0, kv.indexOf("=")), v = kv.slice(kv.indexOf("=") + 1);
      if (/max-age=0/i.test(c) || !v) this.cookies.delete(k);
      else this.cookies.set(k, v);
    }
    return { status: res.status, body: await res.json() };
  }
  post = (p: string, b?: unknown) => this.call("POST", p, b);
  refreshToken = () => [...this.cookies].find(([k]) => k.startsWith("__dw_rt_"))?.[1];
}

const email = `pk.${Date.now()}@example.com`;
const me = new Browser();
const signup = await me.post("sign_up", { email, password: "a decent password" });
const userId = signup.body.user.id;
const device = new SoftAuthenticator(true);

// ---------- Registration ----------
check("registration needs a session", (await new Browser().post("passkeys/register/options")).status === 401);
const opts = (await me.post("passkeys/register/options")).body;
check("options: RP ID, discoverable credential, user verification required",
  opts.rp?.id === RP_ID && opts.authenticatorSelection?.residentKey === "required" && opts.authenticatorSelection?.userVerification === "required" && opts.attestation === "none", opts);
check("options carry the user handle (user ID bytes)", Buffer.from(opts.user.id, "base64url").toString() === userId);

const reg = await me.post("passkeys/register/verify", { response: device.register(opts), name: "Test laptop" });
check("registration verified and stored", reg.status === 201 && !!reg.body.id, reg.body);
check("a registration challenge is single-use", (await me.post("passkeys/register/verify", { response: new SoftAuthenticator().register(opts) })).body.error?.code === "challenge_expired");

const list1 = (await me.call("GET", "passkeys")).body.passkeys;
check("listed with name + synced flag", list1.length === 1 && list1[0].name === "Test laptop" && list1[0].synced === true, list1);

const opts2 = (await me.post("passkeys/register/options")).body;
check("same device is excluded from re-registering", opts2.excludeCredentials?.[0]?.id === b64u(device.credId), opts2.excludeCredentials);
check("registration from a foreign origin rejected",
  (await me.post("passkeys/register/verify", { response: new SoftAuthenticator().register(opts2, { origin: "https://evil.example" }) })).body.error?.code === "passkey_invalid");
const opts3 = (await me.post("passkeys/register/options")).body;
check("registration without user verification rejected",
  (await me.post("passkeys/register/verify", { response: new SoftAuthenticator().register(opts3, { uv: false }) })).body.error?.code === "passkey_invalid");
const opts4 = (await me.post("passkeys/register/options")).body;
check("registration answering a different challenge rejected",
  (await me.post("passkeys/register/verify", { response: new SoftAuthenticator().register(opts4, { challenge: b64u(randomBytes(32)) }) })).body.error?.code === "passkey_invalid");

const stored = JSON.stringify(await db().execute(sql`select public_key, credential_id from passkeys where user_id = ${userId}`));
const privJwk = device.keys.privateKey.export({ format: "jwk" });
check("only the public key is stored", stored.includes(b64u(device.credId)) && !stored.includes(privJwk.d!));

// Fresh-session rule: age the session past 15 minutes
const stale = new Browser();
await stale.post("sign_in", { email, password: "a decent password" });
await db().execute(sql`update sessions set created_at = now() - interval '20 minutes' where refresh_token_hash = ${sha256(stale.refreshToken()!)}`);
await cache().del(`sess:${sha256(stale.refreshToken()!)}`);
const staleRes = await stale.post("passkeys/register/options");
check("old session can't add a passkey (reauth_required)", staleRes.status === 403 && staleRes.body.error?.code === "reauth_required", staleRes.body);
check("…but can still use the account normally", (await stale.post("session/token")).status === 200);

// ---------- Sign-in ----------
const anon = new Browser();
const aopts = (await anon.post("passkeys/authenticate/options")).body;
check("sign-in options require user verification, list no credentials (usernameless)", aopts.userVerification === "required" && !(aopts.allowCredentials?.length), aopts);
const ok = await anon.post("passkeys/authenticate/verify", { response: device.assert(aopts.challenge) });
check("passkey sign-in completes", ok.status === 200 && ok.body.status === "complete" && ok.body.user.id === userId && !!anon.refreshToken(), ok.body);
check("…and the session works", (await anon.post("session/token")).body.userId === userId);
check("assertion replay rejected (challenge single-use)", (await new Browser().post("passkeys/authenticate/verify", { response: device.assert(aopts.challenge, { counter: 50 }) })).body.error?.code === "passkey_invalid");

const fresh = async () => (await new Browser().post("passkeys/authenticate/options")).body.challenge as string;
check("counter going backwards rejected (cloned authenticator)", (await new Browser().post("passkeys/authenticate/verify", { response: device.assert(await fresh(), { counter: 1 }) })).body.error?.code === "passkey_invalid");
check("counter moving forward accepted", (await new Browser().post("passkeys/authenticate/verify", { response: device.assert(await fresh(), { counter: 60 }) })).status === 200);
check("signature from a different key rejected", (await new Browser().post("passkeys/authenticate/verify", { response: device.assert(await fresh(), { signWith: generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey }) })).body.error?.code === "passkey_invalid");
check("tampered authenticator data rejected", (await new Browser().post("passkeys/authenticate/verify", { response: device.assert(await fresh(), { tamper: true }) })).body.error?.code === "passkey_invalid");
check("assertion without user verification rejected", (await new Browser().post("passkeys/authenticate/verify", { response: device.assert(await fresh(), { uv: false }) })).body.error?.code === "passkey_invalid");
check("mismatched user handle rejected", (await new Browser().post("passkeys/authenticate/verify", { response: device.assert(await fresh(), { userHandle: b64u(Buffer.from("user_someoneelse")) }) })).body.error?.code === "passkey_invalid");
check("assertion for a foreign origin rejected", (await new Browser().post("passkeys/authenticate/verify", { response: device.assert(await fresh(), { origin: "https://evil.example" }) })).body.error?.code === "passkey_invalid");
check("unknown credential rejected", (await new Browser().post("passkeys/authenticate/verify", { response: new SoftAuthenticator().assert(await fresh()) })).body.error?.code === "passkey_invalid");
const foreign = (await new Browser(other.publishableKey).post("passkeys/authenticate/options")).body.challenge;
check("challenge from another instance rejected", (await new Browser().post("passkeys/authenticate/verify", { response: device.assert(foreign) })).body.error?.code === "passkey_invalid");

// A user-verified passkey counts as two factors: no TOTP step afterwards
const enr = await anon.post("mfa/totp");
await anon.post("mfa/totp/verify", { code: totpAt(enr.body.secret, currentCounter()) });
check("password sign-in now needs 2FA", (await new Browser().post("sign_in", { email, password: "a decent password" })).body.status === "needs_second_factor");
check("passkey sign-in completes without a TOTP step", (await new Browser().post("passkeys/authenticate/verify", { response: device.assert(await fresh()) })).body.status === "complete");

// ---------- Management ----------
const pkId = list1[0].id;
check("rename", (await me.call("PATCH", `passkeys/${pkId}`, { name: "Work MacBook" })).status === 200 && (await me.call("GET", "passkeys")).body.passkeys[0].name === "Work MacBook");
const stranger = new Browser();
await stranger.post("sign_up", { email: `x.${email}`, password: "stranger password" });
check("another user can't rename or delete it (404)", (await stranger.call("PATCH", `passkeys/${pkId}`, { name: "pwned" })).status === 404 && (await stranger.call("DELETE", `passkeys/${pkId}`)).status === 404);
check("delete", (await me.call("DELETE", `passkeys/${pkId}`)).status === 200 && (await me.call("GET", "passkeys")).body.passkeys.length === 0);
check("deleted passkey can't sign in", (await new Browser().post("passkeys/authenticate/verify", { response: device.assert(await fresh()) })).body.error?.code === "passkey_invalid");
check("junk credential body rejected with 422", (await new Browser().post("passkeys/authenticate/verify", { response: { id: "x" } })).status === 422);
void instanceId;

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll passkey checks passed");
process.exit(failures ? 1 : 0);
