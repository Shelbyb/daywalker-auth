import { readFile } from "node:fs/promises";
import path from "node:path";
import { Marked } from "marked";
import { createHighlighter, type Highlighter } from "shiki";

/** Sidebar order. Each slug maps to content/docs/<slug>.md ("" is the docs home). */
export const NAV: { section: string; pages: { slug: string; title: string }[] }[] = [
  {
    section: "Getting started",
    pages: [
      { slug: "", title: "Introduction" },
      { slug: "quickstart", title: "Quickstart: Next.js" },
      { slug: "how-it-works", title: "How it works" },
    ],
  },
  {
    section: "Guides",
    pages: [
      { slug: "guides/protect-routes", title: "Protect pages and APIs" },
      { slug: "guides/read-user", title: "Read the current user" },
      { slug: "guides/call-your-api", title: "Call your own API" },
      { slug: "guides/email-verification", title: "Email verification" },
      { slug: "guides/password-reset", title: "Password reset" },
      { slug: "guides/social-sign-in", title: "Social sign-in" },
      { slug: "guides/two-factor", title: "Two-factor authentication" },
      { slug: "guides/passkeys", title: "Passkeys" },
      { slug: "guides/account-lockout", title: "Account lockout" },
      { slug: "guides/account-deletion", title: "Account deletion and export" },
      { slug: "guides/terms-acceptance", title: "Require terms at sign-up" },
      { slug: "guides/environments", title: "Development and production" },
      { slug: "guides/machine-auth", title: "Machine auth and API keys" },
      { slug: "guides/test-mode", title: "Test mode and e2e tests" },
      { slug: "guides/satellite-domains", title: "Satellite domains" },
      { slug: "guides/dashboard", title: "The developer dashboard" },
      { slug: "guides/organizations", title: "Organizations" },
      { slug: "guides/organization-roles", title: "Roles, permissions and domains" },
      { slug: "guides/sessions", title: "Sessions" },
      { slug: "guides/device-binding", title: "Device-bound sessions" },
      { slug: "guides/step-up-auth", title: "Step-up authentication" },
      { slug: "guides/audit-integrity", title: "Tamper-evident audit log" },
      { slug: "guides/enterprise-sso", title: "Enterprise SSO (SAML)" },
      { slug: "guides/webhooks", title: "Webhooks" },
      { slug: "guides/rotating-keys", title: "Rotating keys" },
      { slug: "guides/audit-logs", title: "Audit logs" },
      { slug: "guides/email-codes", title: "Email codes and magic links" },
      { slug: "guides/breached-passwords", title: "Breached passwords" },
      { slug: "guides/sign-up-protection", title: "Sign-up protection" },
      { slug: "guides/email-templates", title: "Email templates" },
      { slug: "guides/account-portal", title: "Account Portal" },
      { slug: "guides/account-page", title: "Account page" },
      { slug: "guides/components", title: "Drop-in components" },
      { slug: "guides/custom-ui", title: "Build your own sign-in form" },
      { slug: "guides/other-backends", title: "Express, Hono and other servers" },
      { slug: "guides/manage-users", title: "Manage users from your server" },
    ],
  },
  {
    section: "SDK reference",
    pages: [
      { slug: "sdk/react", title: "@daywalker/auth/react" },
      { slug: "sdk/nextjs", title: "@daywalker/auth/nextjs" },
      { slug: "sdk/server", title: "@daywalker/auth/server" },
      { slug: "sdk/client", title: "@daywalker/auth (browser)" },
    ],
  },
  {
    section: "API reference",
    pages: [
      { slug: "api/frontend", title: "Frontend API" },
      { slug: "api/backend", title: "Backend API" },
      { slug: "api/errors", title: "Errors" },
    ],
  },
  {
    section: "Operating it",
    pages: [
      { slug: "security", title: "Security model" },
      { slug: "status", title: "Status and health checks" },
      { slug: "troubleshooting", title: "Troubleshooting" },
      { slug: "roadmap", title: "Roadmap" },
    ],
  },
  {
    section: "Legal",
    pages: [{ slug: "legal/terms", title: "Terms of Service" }],
  },
];

export const ALL_PAGES = NAV.flatMap((s) => s.pages);

let highlighter: Promise<Highlighter> | undefined;
const getHighlighter = () =>
  (highlighter ??= createHighlighter({
    themes: ["github-light", "github-dark"],
    langs: ["ts", "tsx", "bash", "json", "http", "text"],
  }));

const slugify = (s: string) => s.toLowerCase().replace(/<[^>]+>/g, "").replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");

export type DocPage = { plan?: string; title: string; description: string; html: string; toc: { id: string; text: string }[] };

/** Renders at build time (pages are statically generated), so readers download plain HTML. */
export async function loadDoc(slug: string): Promise<DocPage | null> {
  if (!ALL_PAGES.some((p) => p.slug === slug)) return null;
  const file = path.join(process.cwd(), "content/docs", `${slug || "index"}.md`);
  const raw = await readFile(file, "utf8");
  const fm = raw.match(/^---\n([\s\S]*?)\n---\n/);
  const meta = Object.fromEntries((fm?.[1] ?? "").split("\n").map((l) => [l.slice(0, l.indexOf(":")).trim(), l.slice(l.indexOf(":") + 1).trim()]));
  const body = fm ? raw.slice(fm[0].length) : raw;

  const hl = await getHighlighter();
  const toc: DocPage["toc"] = [];
  const marked = new Marked({
    renderer: {
      code({ text, lang }) {
        const language = lang && hl.getLoadedLanguages().includes(lang) ? lang : "text";
        const html = hl.codeToHtml(text, { lang: language, themes: { light: "github-light", dark: "github-dark" } });
        const label = lang ? `<span class="code-lang">${lang}</span>` : "";
        return `<div class="code-block">${label}${html}</div>`;
      },
      heading({ tokens, depth }) {
        const text = this.parser.parseInline(tokens);
        const id = slugify(text);
        if (depth === 2) toc.push({ id, text: text.replace(/<[^>]+>/g, "") });
        return `<h${depth} id="${id}"><a href="#${id}" class="anchor">${text}</a></h${depth}>`;
      },
      // Callouts: blockquotes starting with **Note**, **Tip** or **Warning**.
      blockquote({ tokens }) {
        const inner = this.parser.parse(tokens);
        const kind = inner.match(/^<p><strong>(Note|Tip|Warning)<\/strong>/)?.[1]?.toLowerCase() ?? "note";
        return `<div class="callout callout-${kind}">${inner}</div>`;
      },
      link({ href, tokens }) {
        const text = this.parser.parseInline(tokens);
        const external = /^https?:\/\//.test(href);
        return `<a href="${href}"${external ? ' rel="noopener noreferrer" target="_blank"' : ""}>${text}</a>`;
      },
    },
  });
  const html = await marked.parse(body);
  return { plan: meta.plan || undefined, title: meta.title ?? "Docs", description: meta.description ?? "", html, toc };
}
