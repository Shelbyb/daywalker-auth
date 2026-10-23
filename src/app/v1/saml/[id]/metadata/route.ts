import { connectionById, spMetadata } from "@/lib/auth/saml";

/** Service provider metadata to upload to the identity provider. */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const c = /^saml_[a-z0-9]+$/.test(id) ? await connectionById(id) : null;
  if (!c) return new Response("Not found", { status: 404 });
  // Advertise both logout bindings (the library only writes HTTP-POST).
  const xml = (await spMetadata(c)).replace(/<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-POST" Location="([^"]+)"\/>/, (m, loc) => `<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${loc}"/>${m}`);
  return new Response(xml, { headers: { "content-type": "application/samlmetadata+xml; charset=utf-8", "cache-control": "public, max-age=300" } });
}
