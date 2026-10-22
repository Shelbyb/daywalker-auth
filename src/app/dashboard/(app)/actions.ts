"use server";

import { revalidatePath } from "next/cache";
import { ZodError } from "zod";
import { ApiError } from "@/lib/http";
import {
  banUser, createInstance, rotateKeys, createKey, deleteInstance, ownedInstance, removeUser, requireDashboardUser,
  revokeKey, saveProvider, setProviderEnabled, updateLegal, updateSettings,
  saveTemplateFor, resetTemplateFor, sendTestEmail, setAccentColor,
  createSsoConnection, updateSsoConnection, deleteSsoConnection,
} from "@/lib/dashboard";
import {
  EVENT_TYPES, createEndpoint, deleteEndpoint, retryDelivery, rotateSecret, sendTest, updateEndpoint,
} from "@/lib/webhooks";

export type ActionState = {
  ok: boolean;
  error?: string;
  message?: string;
  /** Shown once by <RevealOnce>. */
  secret?: string;
  publishableKey?: string;
  instanceId?: string;
  /** Always a fixed internal path set here, never user input. */
  redirectTo?: string;
};

const GENERIC = "Something went wrong. Please try again.";

async function run(fn: () => Promise<Omit<ActionState, "ok"> | void>): Promise<ActionState> {
  try {
    return { ok: true, ...(await fn()) };
  } catch (e) {
    if (e instanceof ApiError) return { ok: false, error: e.message };
    if (e instanceof ZodError) return { ok: false, error: e.issues[0]?.message ?? "Invalid input" };
    console.error("[dashboard action]", e instanceof Error ? e.message : "unknown error");
    return { ok: false, error: GENERIC };
  }
}

const str = (fd: FormData, k: string, max = 2000) => {
  const v = fd.get(k);
  return typeof v === "string" ? v.slice(0, max) : "";
};
const flag = (fd: FormData, k: string) => fd.get(k) === "on" || fd.get(k) === "true";
const instancePath = (id: string) => `/dashboard/instances/${id}`;
const refresh = (id: string) => revalidatePath(instancePath(id), "layout");

// ---------- Instances ----------

export async function createInstanceAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const env = str(fd, "environment") === "production" ? "production" : "development";
    const r = await createInstance(userId, { name: str(fd, "name", 200), environment: env });
    revalidatePath("/dashboard");
    return { message: "Instance created.", instanceId: r.id, publishableKey: r.publishableKey, secret: r.secretKey };
  });
}

export async function deleteInstanceAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    await deleteInstance(userId, str(fd, "instanceId", 200), str(fd, "confirmName", 200));
    revalidatePath("/dashboard");
    return { message: "Instance deleted.", redirectTo: "/dashboard" };
  });
}

// ---------- Keys ----------

export async function createKeyAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    const secret = await createKey(userId, id, str(fd, "name", 200));
    refresh(id);
    return { message: "Key created.", secret };
  });
}

export async function revokeKeyAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await revokeKey(userId, id, str(fd, "keyId", 200));
    refresh(id);
    return { message: "Key revoked." };
  });
}

export async function rotateSigningKeyAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await rotateKeys(userId, id);
    refresh(id);
    return { message: "Now signing with a new key. Nobody was signed out." };
  });
}

// ---------- Settings & terms ----------

export async function updateSettingsAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await updateSettings(userId, id, {
      name: str(fd, "name", 200),
      allowedOrigins: str(fd, "allowedOrigins", 10_000).split(/\r?\n/),
      passwordMinLength: Number(str(fd, "passwordMinLength", 10)),
      sessionLifetimeDays: Number(str(fd, "sessionLifetimeDays", 10)),
      emailCodeSignIn: fd.get("emailCodeSignIn") === "on",
      breachedPasswordCheck: fd.get("breachedPasswordCheck") === "on",
      smsSecondFactor: fd.get("smsSecondFactor") === "on",
    });
    refresh(id);
    return { message: "Settings saved." };
  });
}

export async function updateLegalAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await updateLegal(userId, id, {
      required: flag(fd, "required"),
      termsUrl: str(fd, "termsUrl").trim() || null,
      privacyUrl: str(fd, "privacyUrl").trim() || null,
      version: str(fd, "version", 100),
    });
    refresh(id);
    return { message: "Terms settings saved." };
  });
}

// ---------- Social providers ----------

export async function saveProviderAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await saveProvider(userId, id, str(fd, "provider", 50), {
      clientId: str(fd, "clientId", 1000),
      clientSecret: str(fd, "clientSecret", 4096),
      enabled: flag(fd, "enabled"),
      settings: { issuer: str(fd, "issuer", 500), tenant: str(fd, "tenant", 100), teamId: str(fd, "teamId", 20), keyId: str(fd, "keyId", 20), displayName: str(fd, "displayName", 60) },
    });
    refresh(id);
    return { message: "Saved. The client secret is encrypted and won't be shown again." };
  });
}

export async function setProviderEnabledAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    const enabled = flag(fd, "enabled");
    await setProviderEnabled(userId, id, str(fd, "provider", 50), enabled);
    refresh(id);
    return { message: enabled ? "Enabled." : "Disabled." };
  });
}

// ---------- Users ----------

export async function banUserAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    const banned = flag(fd, "banned");
    await banUser(userId, id, str(fd, "targetId", 200), banned);
    refresh(id);
    return { message: banned ? "User suspended." : "User restored." };
  });
}

export async function removeUserAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await removeUser(userId, id, str(fd, "targetId", 200));
    refresh(id);
    return { message: "User deleted." };
  });
}

// ---------- Webhooks (every call checks ownership first) ----------

const SELECTABLE = (EVENT_TYPES as readonly string[]).filter((e) => e !== "webhook.test");

export async function createWebhookAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await ownedInstance(userId, id);
    const events = flag(fd, "allEvents") ? ["*"] : fd.getAll("events").filter((e): e is string => typeof e === "string" && SELECTABLE.includes(e));
    if (!events.length) throw new ApiError(400, "invalid_request", "Pick at least one event, or tick All events.");
    const r = await createEndpoint(id, { url: str(fd, "url", 2100).trim(), events, description: str(fd, "description", 200).trim() || null }, { type: "developer", id: userId });
    refresh(id);
    return { message: "Endpoint created.", secret: r.secret };
  });
}

export async function toggleWebhookAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await ownedInstance(userId, id);
    const enabled = flag(fd, "enabled");
    await updateEndpoint(id, str(fd, "endpointId", 200), { enabled }, { type: "developer", id: userId });
    refresh(id);
    return { message: enabled ? "Endpoint enabled." : "Endpoint disabled." };
  });
}

export async function rotateWebhookSecretAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await ownedInstance(userId, id);
    const r = await rotateSecret(id, str(fd, "endpointId", 200), { type: "developer", id: userId });
    refresh(id);
    return { message: "Secret rotated. The old one no longer works.", secret: r.secret };
  });
}

export async function sendTestWebhookAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await ownedInstance(userId, id);
    await sendTest(id, str(fd, "endpointId", 200));
    refresh(id);
    return { message: "Test event queued. Refresh in a moment to see the result." };
  });
}

export async function deleteWebhookAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await ownedInstance(userId, id);
    await deleteEndpoint(id, str(fd, "endpointId", 200), { type: "developer", id: userId });
    refresh(id);
    return { message: "Endpoint deleted." };
  });
}

export async function retryDeliveryAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await ownedInstance(userId, id);
    await retryDelivery(id, str(fd, "deliveryId", 200));
    refresh(id);
    return { message: "Queued for retry." };
  });
}

// ---------- Email templates ----------

export async function saveTemplateAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await saveTemplateFor(userId, id, str(fd, "kind", 50), { subject: str(fd, "subject", 300), body: str(fd, "body", 6000) });
    refresh(id);
    return { message: "Email saved. New emails use this wording." };
  });
}

export async function resetTemplateAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await resetTemplateFor(userId, id, str(fd, "kind", 50));
    refresh(id);
    return { message: "Back to the default wording." };
  });
}

export async function testTemplateAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const to = await sendTestEmail(userId, str(fd, "instanceId", 200), str(fd, "kind", 50));
    return { message: `Test email sent to ${to}.` };
  });
}

export async function accentColorAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    const reset = fd.get("reset") === "1";
    await setAccentColor(userId, id, reset ? null : str(fd, "accentColor", 20));
    refresh(id);
    return { message: reset ? "Default color restored." : "Color saved." };
  });
}

// ---------- SSO ----------

const lines = (v: string) => v.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

export async function createSsoAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    const metadataXml = str(fd, "metadataXml", 200_000);
    const cert = str(fd, "certificate", 20_000);
    await createSsoConnection(userId, id, {
      name: str(fd, "name", 200),
      domains: lines(str(fd, "domains", 2000)),
      organizationId: str(fd, "organizationId", 100) || null,
      ...(metadataXml.trim()
        ? { metadataXml }
        : { idpEntityId: str(fd, "idpEntityId", 1000), ssoUrl: str(fd, "ssoUrl", 2000), certificates: cert ? [cert] : [] }),
    });
    refresh(id);
    return { message: "Connection created. Give your identity provider the details shown on the card." };
  });
}

export async function toggleSsoAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    const enabled = fd.get("enabled") === "true";
    await updateSsoConnection(userId, id, str(fd, "connectionId", 100), { enabled });
    refresh(id);
    return { message: enabled ? "Connection enabled." : "Connection disabled." };
  });
}

export async function deleteSsoAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const { userId } = await requireDashboardUser();
    const id = str(fd, "instanceId", 200);
    await deleteSsoConnection(userId, id, str(fd, "connectionId", 100));
    refresh(id);
    return { message: "Connection deleted." };
  });
}
