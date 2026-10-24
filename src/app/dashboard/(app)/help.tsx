"use client";

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { usePathname } from "next/navigation";

type Doc = { slug: string; title: string };

/** Docs related to each dashboard page, matched by path (first match wins). */
const RELATED: [RegExp, Doc[]][] = [
  [/\/instances\/[^/]+\/hosted/, [{ slug: "guides/account-portal", title: "Account Portal" }, { slug: "sdk/react", title: "SDK links to the portal" }, { slug: "guides/account-page", title: "Account page" }]],
  [/\/instances\/[^/]+\/users/, [{ slug: "guides/manage-users", title: "Manage users" }, { slug: "guides/read-user", title: "Read the current user" }]],
  [/\/instances\/[^/]+\/keys/, [{ slug: "guides/rotating-keys", title: "Rotating keys" }, { slug: "guides/call-your-api", title: "Call your API" }]],
  [/\/instances\/[^/]+\/social/, [{ slug: "guides/social-sign-in", title: "Social sign-in" }]],
  [/\/instances\/[^/]+\/sso/, [{ slug: "guides/enterprise-sso", title: "Enterprise SSO" }]],
  [/\/instances\/[^/]+\/webhooks/, [{ slug: "guides/webhooks", title: "Webhooks" }]],
  [/\/instances\/[^/]+\/emails/, [{ slug: "guides/email-templates", title: "Email templates" }, { slug: "guides/email-verification", title: "Email verification" }]],
  [/\/instances\/[^/]+\/organizations/, [{ slug: "guides/organizations", title: "Organizations" }]],
  [/\/instances\/[^/]+\/terms/, [{ slug: "guides/terms-acceptance", title: "Terms acceptance" }]],
  [/\/instances\/[^/]+\/audit/, [{ slug: "guides/audit-logs", title: "Audit logs" }]],
  [/\/instances\/[^/]+\/settings/, [{ slug: "guides/sign-up-protection", title: "Sign-up protection" }, { slug: "guides/two-factor", title: "Two-factor" }, { slug: "guides/passkeys", title: "Passkeys" }, { slug: "guides/breached-passwords", title: "Breached passwords" }]],
  [/\/instances\/[^/]+/, [{ slug: "quickstart", title: "Quickstart" }, { slug: "guides/dashboard", title: "Dashboard" }]],
  [/\/settings/, [{ slug: "guides/account-page", title: "Account page" }, { slug: "guides/two-factor", title: "Two-factor" }, { slug: "guides/passkeys", title: "Passkeys" }]],
  [/\/platform/, [{ slug: "security", title: "Security" }, { slug: "guides/audit-logs", title: "Audit logs" }]],
  [/^\/dashboard\/?$/, [{ slug: "quickstart", title: "Quickstart" }, { slug: "guides/dashboard", title: "Dashboard" }]],
];

const Ctx = createContext<(slug?: string) => void>(() => {});

/** Help sidebar for the dashboard: lists docs related to the current page and shows them inline. */
export function HelpProvider({ children }: { children: ReactNode }) {
  const path = usePathname();
  const related = RELATED.find(([re]) => re.test(path))?.[1] ?? [{ slug: "", title: "Docs home" }];
  const [open, setOpen] = useState(false);
  const [slug, setSlug] = useState<string | null>(null);
  const [doc, setDoc] = useState<{ title: string; html: string } | null>(null);

  const show = useCallback((s?: string) => { setSlug(s ?? null); setOpen(true); }, []);
  useEffect(() => { setOpen(false); setSlug(null); }, [path]);
  useEffect(() => {
    if (slug === null) return setDoc(null);
    let live = true;
    fetch(`/docs-help/${slug || "index"}`).then((r) => (r.ok ? r.json() : null)).then((d) => live && setDoc(d));
    return () => { live = false; };
  }, [slug]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <Ctx.Provider value={show}>
      {children}
      <button type="button" onClick={() => (open ? setOpen(false) : show())} aria-expanded={open}
        className="fixed bottom-5 right-5 z-40 flex h-11 w-11 items-center justify-center rounded-full bg-ink text-lg font-semibold text-white shadow-lg hover:bg-dusk" aria-label="Help and related docs">?</button>
      {open && (
        <aside role="dialog" aria-label="Related docs" className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-stone-200 bg-white shadow-xl">
          <div className="flex items-center gap-2 border-b border-stone-200 px-4 py-3">
            {slug !== null && <button type="button" onClick={() => setSlug(null)} className="text-sm text-stone-600 hover:text-ink">← Related</button>}
            <span className="font-semibold">{slug === null ? "Related docs" : doc?.title ?? "Loading…"}</span>
            <button type="button" onClick={() => setOpen(false)} className="ml-auto text-stone-500 hover:text-ink" aria-label="Close">✕</button>
          </div>
          <div className="flex-1 overflow-y-auto px-4 py-4">
            {slug === null ? (
              <ul className="space-y-2">
                {related.map((d) => (
                  <li key={d.slug}><button type="button" onClick={() => setSlug(d.slug)} className="text-left text-sm font-medium underline decoration-dawn decoration-2 underline-offset-4">{d.title}</button></li>
                ))}
              </ul>
            ) : doc ? (
              <>
                <div className="docs-prose text-sm" dangerouslySetInnerHTML={{ __html: doc.html }} />
                <a href={`/docs/${slug}`} target="_blank" rel="noreferrer" className="mt-6 inline-block text-sm underline">Open full page ↗</a>
              </>
            ) : <p className="text-sm text-stone-500">Loading…</p>}
          </div>
        </aside>
      )}
    </Ctx.Provider>
  );
}

/** "?" icon that opens the help sidebar on the current page's related docs (used by every PageHeader). */
export function PageHelp({ label = "Related docs" }: { label?: string }) {
  const show = useContext(Ctx);
  return (
    <button type="button" onClick={() => show()} title={label} aria-label={label}
      className="ml-1 inline-flex h-5 w-5 items-center justify-center rounded-full border border-stone-300 align-middle text-xs font-normal text-stone-600 hover:border-ink hover:text-ink">?</button>
  );
}

/** Inline "?" icon that opens the help sidebar on a specific doc. */
export function HelpLink({ slug, label = "Help" }: { slug: string; label?: string }) {
  const show = useContext(Ctx);
  return (
    <button type="button" onClick={() => show(slug)} title={label} aria-label={label}
      className="ml-1 inline-flex h-5 w-5 items-center justify-center rounded-full border border-stone-300 align-middle text-xs text-stone-600 hover:border-ink hover:text-ink">?</button>
  );
}
