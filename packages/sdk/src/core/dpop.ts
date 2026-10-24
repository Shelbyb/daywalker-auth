/**
 * Device-bound sessions (DPoP, RFC 9449). The browser makes an ECDSA P-256 key pair that cannot be
 * exported (`extractable: false`), keeps it in IndexedDB (structured clone keeps it non-extractable),
 * and signs a tiny proof JWT per request. A stolen refresh cookie is useless without the key.
 */

export type DeviceKey = { privateKey: CryptoKey; publicJwk: { kty: "EC"; crv: "P-256"; x: string; y: string } };

/** Where device keys live. IndexedDB in browsers; tests and non-browser runtimes can pass their own. */
export type DeviceKeyStore = {
  get(instanceId: string): Promise<DeviceKey | undefined>;
  put(instanceId: string, key: DeviceKey): Promise<void>;
  delete(instanceId: string): Promise<void>;
};

const DB = "daywalker-auth";
const STORE = "device-keys";

const b64url = (buf: ArrayBuffer | Uint8Array) => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const text = (v: unknown) => b64url(new TextEncoder().encode(JSON.stringify(v)));

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx<T>(mode: IDBTransactionMode, run: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const r = run(db.transaction(STORE, mode).objectStore(STORE));
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  } finally {
    db.close();
  }
}

export const indexedDbKeyStore: DeviceKeyStore = {
  get: (id) => tx("readonly", (s) => s.get(id) as IDBRequest<DeviceKey | undefined>),
  put: async (id, key) => void (await tx("readwrite", (s) => s.put(key, id))),
  delete: async (id) => void (await tx("readwrite", (s) => s.delete(id))),
};

/** Can this runtime hold a non-extractable key? (WebCrypto and IndexedDB.) */
export const deviceKeysSupported = () => typeof crypto !== "undefined" && !!crypto.subtle && typeof indexedDB !== "undefined";

export async function generateDeviceKey(): Promise<DeviceKey> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey); // public keys are always exportable
  return { privateKey: pair.privateKey, publicJwk: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! } };
}

/** A proof for one request: method and URL (without query or fragment) are signed in. Valid for about a minute, single use. */
export async function createDpopProof(key: DeviceKey, method: string, url: string): Promise<string> {
  const u = new URL(url);
  const head = text({ typ: "dpop+jwt", alg: "ES256", jwk: key.publicJwk });
  const body = text({ jti: b64url(crypto.getRandomValues(new Uint8Array(16))), htm: method.toUpperCase(), htu: `${u.origin}${u.pathname}`, iat: Math.floor(Date.now() / 1000) });
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, new TextEncoder().encode(`${head}.${body}`));
  return `${head}.${body}.${b64url(sig)}`; // WebCrypto returns r||s, which is the JWS ES256 format
}

/**
 * Plain-JS twin of `createDpopProof` + the IndexedDB lookup, for pages that can't import the SDK
 * (the inline refresh page of `authProxy`). Defines `dwProof(instanceId, method, url)`, which
 * resolves to a proof or null when this browser has no key.
 */
export const INLINE_PROOF_SOURCE = `async function dwProof(i,m,u){try{
var d=await new Promise(function(o,e){var r=indexedDB.open(${JSON.stringify(DB)},1);r.onupgradeneeded=function(){r.result.createObjectStore(${JSON.stringify(STORE)})};r.onsuccess=function(){o(r.result)};r.onerror=function(){e(r.error)}});
var k=await new Promise(function(o){var q=d.transaction(${JSON.stringify(STORE)}).objectStore(${JSON.stringify(STORE)}).get(i);q.onsuccess=function(){o(q.result)};q.onerror=function(){o(null)}});d.close();
if(!k||!k.privateKey)return null;
var b=function(x){x=x instanceof Uint8Array?x:new Uint8Array(x);var s="";for(var n=0;n<x.length;n++)s+=String.fromCharCode(x[n]);return btoa(s).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,"")};
var t=function(v){return b(new TextEncoder().encode(JSON.stringify(v)))};
var l=new URL(u);var h=t({typ:"dpop+jwt",alg:"ES256",jwk:k.publicJwk});
var p=t({jti:b(crypto.getRandomValues(new Uint8Array(16))),htm:m,htu:l.origin+l.pathname,iat:Math.floor(Date.now()/1e3)});
var s=await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},k.privateKey,new TextEncoder().encode(h+"."+p));
return h+"."+p+"."+b(s)}catch(e){return null}}`;
