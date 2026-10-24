import { loadDoc } from "@/lib/docs";

/** Rendered doc page as JSON, for the dashboard's help sidebar. Docs are public, so no auth. */
export async function GET(_req: Request, { params }: { params: Promise<{ slug: string[] }> }) {
  const slug = (await params).slug.join("/");
  const doc = await loadDoc(slug);
  if (!doc) return Response.json({ error: "not_found" }, { status: 404 });
  return Response.json({ title: doc.title, description: doc.description, html: doc.html }, { headers: { "cache-control": "public, max-age=300" } });
}
