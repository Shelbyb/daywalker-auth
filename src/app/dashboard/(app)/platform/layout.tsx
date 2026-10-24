import { requirePlatformPage } from "../guard";
import { Badge } from "../ui";
import { SectionNav, type NavTab } from "../section-nav";

export const metadata = { title: { default: "Platform", template: "%s · Platform · Daywalker Auth" } };

/** The platform console: only platform staff get past the guard (everyone else sees a 404). */
export default async function PlatformLayout({ children }: { children: React.ReactNode }) {
  const { role } = await requirePlatformPage("/dashboard/platform");
  const p = "/dashboard/platform";
  const tabs: NavTab[] = [
    { href: p, label: "Overview" },
    { href: `${p}/instances`, label: "Instances" },
    { href: `${p}/audit`, label: "Logs" },
    ...(role === "admin"
      ? [{
          href: `${p}/signin`, label: "Configure",
          groups: [
            { label: "User & authentication", items: [{ href: `${p}/signin`, label: "Platform sign-in" }] },
            { label: "Providers", items: [{ href: `${p}/settings`, label: "Email & SMS" }] },
            { label: "Access", items: [{ href: `${p}/staff`, label: "Staff" }] },
          ],
        }]
      : []),
  ];
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold tracking-tight">Platform console</h1>
        <Badge tone={role === "admin" ? "warn" : "neutral"}>{role === "admin" ? "Platform admin" : "Platform user"}</Badge>
      </div>
      <SectionNav tabs={tabs} base={p}>{children}</SectionNav>
    </div>
  );
}
