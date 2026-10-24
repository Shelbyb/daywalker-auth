"use server";

import { revalidatePath } from "next/cache";
import { ZodError } from "zod";
import { ApiError } from "@/lib/http";
import { endImpersonation, removeStaff, setStaff, startImpersonation, updatePlatformSettings } from "@/lib/platform";
import type { ActionState } from "../actions";

const GENERIC = "Something went wrong. Please try again.";

// Every function in @/lib/platform re-checks the platform role itself; these only parse forms.
async function run(fn: () => Promise<Omit<ActionState, "ok"> | void>): Promise<ActionState> {
  try {
    return { ok: true, ...(await fn()) };
  } catch (e) {
    if (e instanceof ApiError) return { ok: false, error: e.status === 404 && e.code === "not_found" && e.message === "Not found" ? "Not allowed." : e.message };
    if (e instanceof ZodError) return { ok: false, error: e.issues[0]?.message ?? "Invalid input" };
    console.error("[platform action]", e instanceof Error ? e.message : "unknown error");
    return { ok: false, error: GENERIC };
  }
}

const str = (fd: FormData, k: string, max = 2000) => {
  const v = fd.get(k);
  return typeof v === "string" ? v.slice(0, max) : "";
};

export async function impersonateAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const r = await startImpersonation(str(fd, "instanceId", 100), str(fd, "userId", 100), str(fd, "reason", 600));
    revalidatePath("/dashboard/platform", "layout");
    return { message: "Impersonation started. Open the account page, or the customer's app, in this browser.", redirectTo: r.accountUrl };
  });
}

export async function endImpersonationAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    await endImpersonation(str(fd, "sessionId", 100));
    revalidatePath("/dashboard/platform", "layout");
    return { message: "Impersonation ended." };
  });
}

export async function setStaffAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    await setStaff(str(fd, "email", 300), str(fd, "role", 10));
    revalidatePath("/dashboard/platform/staff");
    return { message: "Staff updated." };
  });
}

export async function removeStaffAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    await removeStaff(str(fd, "userId", 100));
    revalidatePath("/dashboard/platform/staff");
    return { message: "Removed from the staff." };
  });
}

export async function platformSettingsAction(_prev: ActionState, fd: FormData): Promise<ActionState> {
  return run(async () => {
    const changed = await updatePlatformSettings({
      mailFrom: str(fd, "mailFrom", 300).trim(),
      resendApiKey: str(fd, "resendApiKey", 300).trim(),
      clearResendApiKey: fd.get("clearResendApiKey") === "on",
      twilioAccountSid: str(fd, "twilioAccountSid", 100).trim(),
      twilioAuthToken: str(fd, "twilioAuthToken", 300).trim(),
      clearTwilioAuthToken: fd.get("clearTwilioAuthToken") === "on",
      twilioVerifyServiceSid: str(fd, "twilioVerifyServiceSid", 100).trim(),
    });
    revalidatePath("/dashboard/platform/settings");
    return { message: changed.length ? "Platform settings saved. Every instance uses them within a few seconds." : "Nothing changed." };
  });
}
