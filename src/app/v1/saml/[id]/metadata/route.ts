import { connectionById, spMetadata } from "@/lib/auth/saml";

/** Service provider metadata to upload to the identity provider. */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const c = /^saml_[a-z0-9]+$/.test(id) ? await connectionById(id) : null;
  if (!c) return new Response("Not found", { status: 404 });
  return new Response(spMetadata(c), { headers: { "content-type": "application/samlmetadata+xml; charset=utf-8", "cache-control": "public, max-age=300" } });
}
