import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ALL_PAGES, loadDoc } from "@/lib/docs";

// Every docs page is prerendered at build time; unknown slugs 404 without hitting the server.
export const dynamicParams = false;
export const generateStaticParams = () => ALL_PAGES.map((p) => ({ slug: p.slug ? p.slug.split("/") : [] }));

type Props = { params: Promise<{ slug?: string[] }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const doc = await loadDoc((await params).slug?.join("/") ?? "");
  return doc ? { title: `${doc.title} · Daywalker Auth Docs`, description: doc.description } : {};
}

export default async function DocPage({ params }: Props) {
  const slug = (await params).slug?.join("/") ?? "";
  const doc = await loadDoc(slug);
  if (!doc) notFound();
  const i = ALL_PAGES.findIndex((p) => p.slug === slug);
  const prev = ALL_PAGES[i - 1];
  const next = ALL_PAGES[i + 1];
  const href = (s: string) => `/docs${s ? `/${s}` : ""}`;

  return (
    <div className="flex gap-10 py-10">
      <article className="min-w-0 max-w-3xl flex-1">
        <h1 className="text-3xl font-semibold tracking-tight">{doc.title}</h1>
        {doc.description && <p className="mt-2 text-lg text-stone-500">{doc.description}</p>}
        {/* Content is our own markdown, rendered at build time. */}
        <div className="docs-prose mt-8" dangerouslySetInnerHTML={{ __html: doc.html }} />
        <nav className="mt-16 flex justify-between border-t border-stone-200 pt-6 text-sm">
          {prev ? <Link href={href(prev.slug)} className="text-stone-500 hover:text-ink">← {prev.title}</Link> : <span />}
          {next ? <Link href={href(next.slug)} className="font-medium hover:underline">{next.title} →</Link> : <span />}
        </nav>
      </article>
      {doc.toc.length > 1 && (
        <aside className="sticky top-24 hidden h-fit w-52 shrink-0 xl:block">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-stone-400">On this page</p>
          <ul className="space-y-1.5 text-sm">
            {doc.toc.map((t) => (
              <li key={t.id}><a href={`#${t.id}`} className="text-stone-500 hover:text-ink">{t.text}</a></li>
            ))}
          </ul>
        </aside>
      )}
    </div>
  );
}
