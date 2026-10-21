import Link from "next/link";
import { NAV } from "@/lib/docs";
import { SidebarLink } from "./sidebar-link";

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-dvh bg-white">
      <header className="sticky top-0 z-20 border-b border-stone-200 bg-white/90 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-7xl items-center gap-3 px-4">
          <Link href="/docs" className="flex items-center gap-2 font-semibold">
            <span className="h-2.5 w-2.5 rounded-full bg-gradient-to-br from-dawn to-ember" />
            Daywalker Auth <span className="font-normal text-stone-400">Docs</span>
          </Link>
        </div>
      </header>
      <div className="mx-auto flex max-w-7xl gap-10 px-4">
        <nav aria-label="Docs" className="sticky top-14 hidden h-[calc(100dvh-3.5rem)] w-60 shrink-0 overflow-y-auto py-8 lg:block">
          {NAV.map((s) => (
            <div key={s.section} className="mb-6">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-stone-400">{s.section}</p>
              <ul className="space-y-0.5">
                {s.pages.map((p) => (
                  <li key={p.slug}>
                    <SidebarLink href={`/docs${p.slug ? `/${p.slug}` : ""}`}>{p.title}</SidebarLink>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
        <div className="min-w-0 flex-1">{children}</div>
      </div>
    </div>
  );
}
