"use client";

import { SectionNav, type NavTab } from "../../section-nav";

/** Overview / Users / Logs on top; everything configurable lives under Configure with a grouped sidebar. */
export function Tabs({ base, children }: { base: string; children: React.ReactNode }) {
  const tabs: NavTab[] = [
    { label: "Overview", href: base },
    { label: "Users", href: `${base}/users` },
    { label: "Logs", href: `${base}/audit` },
    {
      label: "Configure",
      href: `${base}/settings`,
      groups: [
        { label: "User & authentication", items: [
          { href: `${base}/settings`, label: "Sign-in & security" },
          { href: `${base}/social`, label: "Social sign-in" },
          { href: `${base}/sso`, label: "SSO connections" },
          { href: `${base}/terms`, label: "Legal" },
        ] },
        { label: "Customization", items: [
          { href: `${base}/hosted`, label: "Account Portal" },
          { href: `${base}/emails`, label: "Emails" },
        ] },
        { label: "Developers", items: [
          { href: `${base}/keys`, label: "API keys" },
          { href: `${base}/webhooks`, label: "Webhooks" },
        ] },
      ],
    },
  ];
  return <SectionNav tabs={tabs} base={base}>{children}</SectionNav>;
}
