import { NextResponse } from "next/server";
import { handleSlo } from "@/lib/auth/saml-logout";

/** Single logout: the identity provider's LogoutRequest, or its LogoutResponse to ours. Both bindings. */
const respond = (r: { status: number; location?: string; text?: string }) =>
  r.location
    ? NextResponse.redirect(r.location, 302)
    : new NextResponse(r.text ?? "", { status: r.status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const url = new URL(req.url);
  if (url.search.length > 300_000) return respond({ status: 413, text: "Too large" });
  return respond(await handleSlo(id, url.searchParams, null));
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (Number(req.headers.get("content-length") ?? 0) > 300_000) return respond({ status: 413, text: "Too large" });
  const form = await req.formData().catch(() => null);
  if (!form) return respond({ status: 400, text: "Missing SAML message" });
  return respond(await handleSlo(id, new URLSearchParams(), form));
}
