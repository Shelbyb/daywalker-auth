import Link from "next/link";
import { requirePlatformPage } from "../guard";
import { Badge } from "../ui";

export const metadata = { title: { default: "Platform", template: "%s · Platform · Daywalker Auth" } };

/** The platform console: only platform staff get past the guard (everyone else sees a 404). */
export default async function PlatformLayout({ children }: { children: React.ReactNode }) {
  const { role } = await requirePlatformPage("/dashboard/platform");
  const tabs = [
    { href: "/dashboard/platform", label: "Overview" },
    { href: "/dashboard/platform/instances", label: "Instances" },
    { href: "/dashboard/platform/audit", label: "Audit log" },
    ...(role === "admin"
      ? [
          { href: "/dashboard/platform/settings", label: "Settings" },
          { href: "/dashboard/platform/staff", label: "Staff" },
        ]
      : []),
  ];
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold tracking-tight">Platform console</h1>
        <Badge tone={role === "admin" ? "warn" : "neutral"}>{role === "admin" ? "Platform admin" : "Platform user"}</Badge>
      </div>
      <nav aria-label="Platform" className="flex flex-wrap gap-1 border-b border-stone-200">
        {tabs.map((t) => (
          <Link key={t.href} href={t.href} className="rounded-t-lg px-3 py-2 text-sm font-medium text-stone-600 hover:bg-stone-100 hover:text-ink focus-visible:outline-2 focus-visible:outline-dawn">
            {t.label}
          </Link>
        ))}
      </nav>
      {children}
    </div>
  );
}
