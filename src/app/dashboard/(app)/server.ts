import { cache } from "react";
import { notFound } from "next/navigation";
import { ApiError } from "@/lib/http";
import { instanceDetails } from "@/lib/dashboard";

/** Turns the lib's "not yours / doesn't exist" 404 into a real Next.js 404. Other errors propagate. */
export async function guarded<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
}

/** Per-request memo so the layout and the page share one lookup. */
export const details = cache((userId: string, instanceId: string) => guarded(() => instanceDetails(userId, instanceId)));

type D = Date | string | number | null | undefined;
export const fmtDate = (d: D) => (d ? new Date(d).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" }) : "Never");
export const fmtDateTime = (d: D) =>
  d ? new Date(d).toLocaleString("en-US", { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }) : "Never";
