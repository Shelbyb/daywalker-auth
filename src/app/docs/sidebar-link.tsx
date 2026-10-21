"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

/** Tiny client island: only the active-state highlight needs the browser. */
export function SidebarLink({ href, children }: { href: string; children: React.ReactNode }) {
  const active = usePathname() === href;
  return (
    <Link
      href={href}
      aria-current={active ? "page" : undefined}
      className={`block rounded-md px-2 py-1.5 text-sm transition ${active ? "bg-stone-100 font-medium text-ink" : "text-stone-600 hover:text-ink"}`}
    >
      {children}
    </Link>
  );
}
