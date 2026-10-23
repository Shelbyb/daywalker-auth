/**
 * A software WebAuthn authenticator for tests: real P-256 keys, CBOR attestation objects and
 * ECDSA assertions, so the server's verification code runs exactly as it would for a real device.
 */
import { createHash, generateKeyPairSync, sign, randomBytes, type KeyObject } from "node:crypto";
import { Encoder } from "cbor-x";

export const AUTH = "http://localhost:3000";
export const RP_ID = "localhost";

const cbor = new Encoder({ mapsAsObjects: false, useRecords: false });
export const b64u = (b: Buffer | Uint8Array) => Buffer.from(b).toString("base64url");
const h256 = (b: Buffer | string) => createHash("sha256").update(b).digest();
const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 };

export class SoftAuthenticator {
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

