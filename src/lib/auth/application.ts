/**
 * Applications and their environments. An application has at most one development and one production
 * instance; they share nothing at runtime (separate users, publishable and secret keys, signing keys,
 * JWKS, sessions). The only bridge is `cloneConfig`, which copies *configuration* from development to
 * production when the developer asks, using the production instance's secret key.
 */
import { and, count, eq, inArray } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "../db";
import { cache } from "../cache";
import { decrypt, encrypt } from "../crypto";
import { errors } from "../http";
import { newId, newToken, sha256 } from "../ids";
import { record, type Actor } from "../audit";
import { assertSafeUrl, newSecret } from "../webhooks";
import { forgetRoles } from "./org-roles";
import { createSigningKey } from "./keys";
import { invalidateInstance, publishableKey } from "./instance";
import type { Instance } from "../db/schema";

export type Environment = "development" | "production";

/** A new secret key for the environment (`sk_test_` for development, `sk_live_` for production). */
export const newSecretKey = (environment: Environment) => `sk_${environment === "production" ? "live" : "test"}_${newToken(32)}`;

/**
 * Creates an instance (with its own signing key and first secret key) in an application. Without
 * `applicationId` a new application is created for it. Returns the secret key once.
 */
export async function createEnvironmentInstance(accountId: string, input: { name: string; environment: Environment; applicationId?: string }) {
  let applicationId = input.applicationId;
  if (applicationId) {
    const [app] = await db().select().from(schema.applications).where(and(eq(schema.applications.id, applicationId), eq(schema.applications.accountId, accountId)));
    if (!app) throw errors.notFound("Application not found");
    const [taken] = await db().select({ id: schema.instances.id }).from(schema.instances).where(and(eq(schema.instances.applicationId, applicationId), eq(schema.instances.environment, input.environment)));
    if (taken) throw errors.conflict("environment_exists", `This application already has a ${input.environment} instance`);
  } else {
    applicationId = newId("app");
    await db().insert(schema.applications).values({ id: applicationId, accountId, name: input.name });
  }
  const id = newId("ins");
  const [inst] = await db().insert(schema.instances).values({ id, accountId, name: input.name, environment: input.environment, applicationId }).returning();
  await createSigningKey(id);
  const secret = newSecretKey(input.environment);
  await db().insert(schema.apiKeys).values({ id: newId("sk"), instanceId: id, name: "Default", keyHash: sha256(secret), keyPrefix: secret.slice(0, 12) });
  return { instance: inst, publishableKey: publishableKey(inst), secretKey: secret };
}

/** The instances of an application, development first. Empty for legacy instances without one. */
export async function siblingsOf(inst: Pick<Instance, "applicationId">) {
  if (!inst.applicationId) return [];
  const rows = await db().select().from(schema.instances).where(eq(schema.instances.applicationId, inst.applicationId));
  return rows.sort((a, b) => (a.environment === b.environment ? 0 : a.environment === "development" ? -1 : 1));
}

/** What the backend API and dashboard show about an instance's place in its application. Publishable keys are public. */
export async function environmentsView(inst: Instance) {
  const [app] = inst.applicationId ? await db().select().from(schema.applications).where(eq(schema.applications.id, inst.applicationId)) : [];
  const sibs = await siblingsOf(inst);
  return {
    instanceId: inst.id,
    environment: inst.environment,
    application: app ? { id: app.id, name: app.name } : null,
    environments: sibs.map((s) => ({ instanceId: s.id, environment: s.environment, name: s.name, publishableKey: publishableKey(s), current: s.id === inst.id })),
  };
}

// ---------- Cloning configuration ----------

export const CLONE_PARTS = ["settings", "providers", "templates", "roles", "webhooks", "origins"] as const;
export type ClonePart = (typeof CLONE_PARTS)[number];
/** Parts that hold secrets. Only copied when listed in `copySecrets`, and always re-encrypted for the target. */
export const SECRET_PARTS = ["providers", "webhooks"] as const;

export const cloneInput = z
  .object({
    /** Which parts to copy. Webhook endpoints and origins are off unless asked for. */
    include: z.object({ settings: z.boolean(), providers: z.boolean(), templates: z.boolean(), roles: z.boolean(), webhooks: z.boolean(), origins: z.boolean() }).partial().default({}),
    /** Copy the secrets of these parts (social provider client secrets, webhook signing secrets). Default: none. */
    copySecrets: z.array(z.enum(SECRET_PARTS)).max(2).default([]),
  })
  .strict();
export type CloneInput = z.input<typeof cloneInput>;

/**
 * Settings that are safe to carry over. An allow-list on purpose: a setting added later is not cloned
 * until someone decides it should be. Left out: `redirects` and `captchaSiteKey` (tied to development URLs and
 * keys), `requireTwoFactor` (could lock out existing production users), and anything environment-specific
 * such as test mode, which can never reach production.
 */
const SETTING_KEYS = [
  "passwordMinLength", "sessionLifetimeDays", "tokenTtlSeconds", "emailCodeSignIn", "passkeySignUp", "breachedPasswordCheck", "emailAccentColor",
  "smsSecondFactor", "smsCountries", "accountDeletion", "signUpAllowedDomains", "signUpBlockedDomains", "blockDisposableEmails", "branding", "organizations", "sessions",
] as const;
const SKIPPED_SETTINGS: Record<string, string> = {
  redirects: "points at development URLs",
  captchaSiteKey: "belongs to the development Turnstile secret",
  requireTwoFactor: "could lock out existing production users; set it on production deliberately",
  twoFactorGraceUntil: "belongs to requireTwoFactor",
};

export type CloneReport = {
  from: { instanceId: string; environment: "development" };
  to: { instanceId: string; environment: "production" };
  copied: Record<string, unknown>;
  skipped: { what: string; reason: string }[];
  secretsCopied: SecretPartName[];
  /** Signing secrets of webhook endpoints created without copying secrets. Shown only now. */
  webhookSecrets: { id: string; secret: string }[];
};
type SecretPartName = (typeof SECRET_PARTS)[number];

const isLocal = (origin: string) => {
  try {
    const h = new URL(origin).hostname;
    return h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h.endsWith(".localhost");
  } catch {
    return true;
  }
};

/**
 * Copies configuration from the development instance of `target`'s application into `target` (which must be the
 * production instance). Never copies users, sessions, API keys, signing keys, SSO connections, domains or the audit
 * log. Secrets are copied only when listed in `copySecrets`, and are decrypted with the source's context and
 * re-encrypted for the target. Everything happens in one transaction.
 */
export async function cloneConfig(target: Instance, raw: CloneInput, actor: Actor): Promise<CloneReport> {
  const input = cloneInput.parse(raw);
  if (target.environment !== "production") throw errors.badRequest("clone_target_not_production", "Configuration is cloned into a production instance; use the production instance's secret key");
  const source = (await siblingsOf(target)).find((s) => s.environment === "development");
  if (!source) throw errors.badRequest("no_development_instance", "This application has no development instance to clone from");
  if (source.id === target.id || source.applicationId !== target.applicationId) throw errors.badRequest("no_development_instance", "No development instance to clone from");

  const want = (p: ClonePart) => input.include[p] ?? !["webhooks", "origins"].includes(p);
  const secrets = new Set<SecretPartName>(input.copySecrets);
  for (const s of secrets) if (!want(s)) throw errors.badRequest("secrets_without_part", `copySecrets lists ${s}, but ${s} isn't being copied`);
  const copied: Record<string, unknown> = {};
  const skipped: CloneReport["skipped"] = [];
  const webhookSecrets: CloneReport["webhookSecrets"] = [];

  // Webhook URLs are checked before the transaction (DNS lookups), so the transaction stays short.
  const srcEndpoints = want("webhooks") ? await db().select().from(schema.webhookEndpoints).where(eq(schema.webhookEndpoints.instanceId, source.id)) : [];
  const safeUrls = new Map<string, string | null>();
  for (const e of srcEndpoints) {
    const url = decrypt(e.urlEnc, `webhook_endpoints.url:${e.id}`);
    safeUrls.set(e.id, await assertSafeUrl(url).then(() => url, () => null));
  }

  await db().transaction(async (tx) => {
    const [src] = await tx.select().from(schema.instances).where(eq(schema.instances.id, source.id));
    const [tgt] = await tx.select().from(schema.instances).where(eq(schema.instances.id, target.id)).for("update");

    if (want("settings")) {
      const next: Record<string, unknown> = { ...tgt.settings };
      const taken: string[] = [];
      for (const k of SETTING_KEYS) if ((src.settings as Record<string, unknown>)[k] !== undefined) { next[k] = (src.settings as Record<string, unknown>)[k]; taken.push(k); }
      for (const [k, why] of Object.entries(SKIPPED_SETTINGS)) if ((src.settings as Record<string, unknown>)[k] !== undefined) skipped.push({ what: `settings.${k}`, reason: why });
      // Organization roles named in the settings must exist in production, or the copied values would break sign-up.
      const orgs = next.organizations as { creatorRole?: string; defaultRole?: string } | undefined;
      if (orgs && !want("roles")) {
        const have = new Set(["admin", "member", ...(await tx.select({ k: schema.orgRoles.key }).from(schema.orgRoles).where(eq(schema.orgRoles.instanceId, tgt.id))).map((r) => r.k)]);
        const before = (tgt.settings as { organizations?: Record<string, unknown> }).organizations ?? {};
        for (const f of ["creatorRole", "defaultRole"] as const)
          if (orgs[f] && !have.has(orgs[f]!)) {
            skipped.push({ what: `settings.organizations.${f}`, reason: `role "${orgs[f]}" doesn't exist in production` });
            if (before[f] === undefined) delete (orgs as Record<string, unknown>)[f];
            else (orgs as Record<string, unknown>)[f] = before[f];
          }
      }
      await tx.update(schema.instances).set({ settings: next as Instance["settings"], legal: src.legal, updatedAt: new Date() }).where(eq(schema.instances.id, tgt.id));
      copied.settings = [...taken, "legal"];
    }

    if (want("origins")) {
      const keep = src.allowedOrigins.filter((o) => !isLocal(o));
      for (const o of src.allowedOrigins.filter(isLocal)) skipped.push({ what: `origin ${o}`, reason: "localhost isn't allowed on a production instance" });
      const merged = [...new Set([...tgt.allowedOrigins, ...keep])].slice(0, 20);
      await tx.update(schema.instances).set({ allowedOrigins: merged, updatedAt: new Date() }).where(eq(schema.instances.id, tgt.id));
      copied.origins = keep;
    }

    if (want("providers")) {
      const rows = await tx.select().from(schema.oauthProviders).where(eq(schema.oauthProviders.instanceId, src.id));
      const have = new Map((await tx.select().from(schema.oauthProviders).where(eq(schema.oauthProviders.instanceId, tgt.id))).map((r) => [r.provider, r]));
      const out: { provider: string; result: string }[] = [];
      for (const r of rows) {
        if (r.provider === "saml") continue;
        const ctxTo = `oauth_providers.client_secret:${tgt.id}:${r.provider}`;
        if (secrets.has("providers")) {
          const secret = decrypt(r.clientSecretEnc, `oauth_providers.client_secret:${src.id}:${r.provider}`);
          await tx.insert(schema.oauthProviders).values({ instanceId: tgt.id, provider: r.provider, clientId: r.clientId, clientSecretEnc: encrypt(secret, ctxTo), enabled: r.enabled, settings: r.settings })
            .onConflictDoUpdate({ target: [schema.oauthProviders.instanceId, schema.oauthProviders.provider], set: { clientId: r.clientId, clientSecretEnc: encrypt(secret, ctxTo), enabled: r.enabled, settings: r.settings, updatedAt: new Date() } });
          out.push({ provider: r.provider, result: "copied_with_secret" });
        } else if (have.has(r.provider)) {
          // Overwriting the client ID without its secret would break a working production provider.
          out.push({ provider: r.provider, result: "kept_existing" });
          skipped.push({ what: `provider ${r.provider}`, reason: "already configured in production; left as is" });
        } else {
          // No secret: created disabled with an empty secret, so nothing signs in through it until a real one is set.
          await tx.insert(schema.oauthProviders).values({ instanceId: tgt.id, provider: r.provider, clientId: r.clientId, clientSecretEnc: encrypt("", ctxTo), enabled: false, settings: r.settings });
          out.push({ provider: r.provider, result: "created_disabled" });
        }
      }
      copied.providers = out;
    }

    if (want("templates")) {
      const rows = await tx.select().from(schema.emailTemplates).where(eq(schema.emailTemplates.instanceId, src.id));
      for (const r of rows)
        await tx.insert(schema.emailTemplates).values({ instanceId: tgt.id, kind: r.kind, subject: r.subject, body: r.body })
          .onConflictDoUpdate({ target: [schema.emailTemplates.instanceId, schema.emailTemplates.kind], set: { subject: r.subject, body: r.body, updatedAt: new Date() } });
      copied.templates = rows.map((r) => r.kind);
    }

    if (want("roles")) {
      const rows = await tx.select().from(schema.orgRoles).where(eq(schema.orgRoles.instanceId, src.id));
      for (const r of rows)
        await tx.insert(schema.orgRoles).values({ instanceId: tgt.id, key: r.key, name: r.name, description: r.description, permissions: r.permissions })
          .onConflictDoUpdate({ target: [schema.orgRoles.instanceId, schema.orgRoles.key], set: { name: r.name, description: r.description, permissions: r.permissions, updatedAt: new Date() } });
      copied.roles = rows.map((r) => r.key); // merged: roles that exist only in production are kept
    }

    if (want("webhooks")) {
      const existing = await tx.select().from(schema.webhookEndpoints).where(eq(schema.webhookEndpoints.instanceId, tgt.id));
      const existingUrls = new Set(existing.map((e) => decrypt(e.urlEnc, `webhook_endpoints.url:${e.id}`)));
      let room = 10 - existing.length;
      const made: string[] = [];
      for (const e of srcEndpoints) {
        const url = safeUrls.get(e.id);
        if (!url) { skipped.push({ what: `webhook ${e.id}`, reason: "its URL isn't a public https address" }); continue; }
        if (existingUrls.has(url)) { skipped.push({ what: `webhook ${e.id}`, reason: "an endpoint with that URL already exists in production" }); continue; }
        if (room <= 0) { skipped.push({ what: `webhook ${e.id}`, reason: "production is at the 10 endpoint limit" }); continue; }
        room--;
        const id = newId("we");
        const secret = secrets.has("webhooks") ? decrypt(e.secretEnc, `webhook_endpoints.secret:${e.id}`) : newSecret();
        if (!secrets.has("webhooks")) webhookSecrets.push({ id, secret });
        // Created disabled: production shouldn't start sending to a development receiver by accident.
        await tx.insert(schema.webhookEndpoints).values({ id, instanceId: tgt.id, urlEnc: encrypt(url, `webhook_endpoints.url:${id}`), secretEnc: encrypt(secret, `webhook_endpoints.secret:${id}`), events: e.events, description: e.description, enabled: false });
        made.push(id);
      }
      copied.webhooks = made;
    }
  });

  await Promise.all([invalidateInstance(target.id), cache().del(`oauth:enabled:${target.id}`), forgetRoles(target.id)]);
  void record(target.id, "instance.config_cloned", {
    actor,
    data: { fromInstance: source.id, parts: Object.keys(copied), secretsCopied: [...secrets], skipped: skipped.length },
  });
  return {
    from: { instanceId: source.id, environment: "development" },
    to: { instanceId: target.id, environment: "production" },
    copied,
    skipped,
    secretsCopied: [...secrets],
    webhookSecrets,
  };
}

/** Number of instances an account has (for the per-account limit). */
export async function instanceCount(accountId: string) {
  const [{ n }] = await db().select({ n: count() }).from(schema.instances).where(eq(schema.instances.accountId, accountId));
  return n;
}

/** The accounts' applications with their instances, for the dashboard home. */
export async function applicationsFor(accountIds: string[]) {
  if (!accountIds.length) return [];
  const apps = await db().select().from(schema.applications).where(inArray(schema.applications.accountId, accountIds));
  const inst = await db().select().from(schema.instances).where(inArray(schema.instances.accountId, accountIds));
  return apps
    .map((a) => ({ ...a, instances: inst.filter((i) => i.applicationId === a.id) }))
    .sort((a, b) => +b.createdAt - +a.createdAt);
}
