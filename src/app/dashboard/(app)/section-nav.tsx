"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";

/** One sidebar entry; `href` is absolute. */
export type NavItem = { href: string; label: string };
/** A collapsible sidebar group. */
export type NavGroup = { label: string; items: NavItem[] };
/** A top tab. Tabs with `groups` get the left "Configure"-style sidebar. */
export type NavTab = { label: string; href: string; match?: string[]; groups?: NavGroup[] };

const isAt = (path: string, href: string, exact: boolean) => (exact ? path === href : path === href || path.startsWith(href + "/"));

function tabActive(path: string, t: NavTab, base: string) {
  const hrefs = [t.href, ...(t.match ?? []), ...(t.groups?.flatMap((g) => g.items.map((i) => i.href)) ?? [])];
  return hrefs.some((h) => isAt(path, h, h === base));
}

/** Clerk-style layout: top tab bar, plus a searchable, grouped sidebar for tabs that have sub-pages. */
export function SectionNav({ tabs, base, children }: { tabs: NavTab[]; base: string; children: React.ReactNode }) {
  const path = usePathname();
  const active = tabs.find((t) => tabActive(path, t, base));
  return (
    <div className="space-y-6">
      <nav aria-label="Sections" className="-mx-4 overflow-x-auto px-4">
        <ul className="flex gap-6 border-b border-stone-200">
          {tabs.map((t) => {
            const on = t === active;
            return (
              <li key={t.label}>
                <Link href={t.href} aria-current={on ? "page" : undefined}
                  className={`-mb-px block whitespace-nowrap border-b-2 py-2.5 text-sm font-medium focus-visible:outline-2 focus-visible:outline-dawn ${on ? "border-ink text-ink" : "border-transparent text-stone-500 hover:text-ink"}`}>
                  {t.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
      {active?.groups ? (
        <div className="grid gap-8 md:grid-cols-[14rem_minmax(0,1fr)]">
          <Sidebar heading={active.label} groups={active.groups} path={path} />
          <div className="min-w-0">{children}</div>
        </div>
      ) : (
        <div>{children}</div>
      )}
    </div>
  );
}

function Sidebar({ heading, groups, path }: { heading: string; groups: NavGroup[]; path: string }) {
  const [q, setQ] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(groups.map((g) => [g.label, g.items.some((i) => isAt(path, i.href, false))])),
  );
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); input.current?.focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const needle = q.trim().toLowerCase();
  const shown = groups
    .map((g) => ({ ...g, items: needle ? g.items.filter((i) => (g.label + " " + i.label).toLowerCase().includes(needle)) : g.items }))
    .filter((g) => g.items.length);

  return (
    <aside className="md:sticky md:top-6 md:self-start">
      <label className="relative block">
        <span className="sr-only">Find a setting</span>
        <input ref={input} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Find…"
          className="w-full rounded-lg border border-stone-200 bg-stone-50 py-1.5 pl-3 pr-14 text-sm placeholder:text-stone-400 focus:border-ink focus:outline-none" />
        <kbd className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 rounded border border-stone-200 bg-white px-1 text-[10px] text-stone-400">⌘K</kbd>
      </label>
      <p className="mb-1 mt-5 px-2 text-xs font-medium text-stone-500">{heading}</p>
      <ul className="space-y-0.5">
        {shown.map((g) => {
          const expanded = needle ? true : open[g.label] ?? false;
          const single = g.items.length === 1 && g.items[0].label === g.label;
          if (single) return <li key={g.label}><Item item={g.items[0]} path={path} /></li>;
          return (
            <li key={g.label}>
              <button type="button" onClick={() => setOpen((o) => ({ ...o, [g.label]: !expanded }))} aria-expanded={expanded}
                className="flex w-full items-center justify-between rounded-md px-2 py-1.5 text-sm font-medium text-stone-700 hover:bg-stone-100 hover:text-ink">
                {g.label}<span className={`text-xs text-stone-400 transition-transform ${expanded ? "rotate-180" : ""}`}>⌄</span>
              </button>
              {expanded && (
                <ul className="ml-3 space-y-0.5 border-l border-stone-200 pl-2">
                  {g.items.map((i) => <li key={i.href}><Item item={i} path={path} /></li>)}
                </ul>
              )}
            </li>
          );
        })}
        {!shown.length && <li className="px-2 py-1.5 text-sm text-stone-500">No matches</li>}
      </ul>
    </aside>
  );
}

function Item({ item, path }: { item: NavItem; path: string }) {
  const on = isAt(path, item.href, false);
  return (
    <Link href={item.href} aria-current={on ? "page" : undefined}
      className={`block rounded-md px-2 py-1.5 text-sm focus-visible:outline-2 focus-visible:outline-dawn ${on ? "bg-stone-100 font-medium text-ink" : "text-stone-600 hover:bg-stone-50 hover:text-ink"}`}>
      {item.label}
    </Link>
  );
}
