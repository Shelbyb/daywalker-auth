"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const TABS = [
  ["", "Overview"],
  ["/keys", "API keys"],
  ["/settings", "Settings"],
  ["/social", "Social sign-in"],
  ["/terms", "Terms"],
  ["/users", "Users"],
  ["/webhooks", "Webhooks"],
  ["/audit", "Audit log"],
] as const;

export function Tabs({ base }: { base: string }) {
  const path = usePathname();
  return (
    <nav aria-label="Instance sections" className="-mx-4 overflow-x-auto px-4">
      <ul className="flex gap-1 border-b border-stone-200">
        {TABS.map(([suffix, label]) => {
          const href = base + suffix;
          const active = suffix ? path === href || path.startsWith(href + "/") : path === href;
          return (
            <li key={href}>
              <Link
                href={href}
                aria-current={active ? "page" : undefined}
                className={`-mb-px block whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium focus-visible:outline-2 focus-visible:outline-dawn ${active ? "border-dawn text-ink" : "border-transparent text-stone-500 hover:text-ink"}`}
              >
                {label}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
