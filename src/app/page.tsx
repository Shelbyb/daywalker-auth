import Link from "next/link";
import { dashboardEnabled, getDashboardUser } from "@/lib/dashboard";
import { PLAN_FEATURES, listPlans } from "@/lib/plans";

export const dynamic = "force-dynamic";

const features = [
  {
    title: "Every way to sign in",
    description: "Email, social providers, passkeys, magic links, and multi-factor authentication in one hosted flow.",
    detail: "Passwordless and enterprise-ready",
  },
  {
    title: "Sessions you can trust",
    description: "Short-lived ES256 tokens verified locally, with refresh cookies and fast revocation.",
    detail: "No network hop on each request",
  },
  {
    title: "Built for real teams",
    description: "Organizations, invitations, roles, SAML single sign-on, and SCIM provisioning.",
    detail: "From first user to enterprise",
  },
  {
    title: "A useful developer dashboard",
    description: "Manage instances, keys, users, allowed origins, webhooks, email, and audit events.",
    detail: "The controls you need in one place",
  },
  {
    title: "A complete API and SDK",
    description: "Use the browser and React SDKs, Next.js helpers, or a backend API for your own services.",
    detail: "Fits your app and stack",
  },
  {
    title: "Security at the foundation",
    description: "Encrypted personal data, hashed secrets, origin checks, rate limits, and signed webhooks.",
    detail: "Careful defaults, not add-ons",
  },
];

const apiSurfaces = [
  {
    name: "Frontend API",
    route: "/v1/client/*",
    access: "Publishable key + secure session cookie",
  },
  {
    name: "Backend API",
    route: "/v1/users · /v1/sessions · /v1/organizations",
    access: "Secret key for your server",
  },
  {
    name: "Token verification",
    route: "/i/:instanceId/.well-known/jwks.json",
    access: "Public keys; verify sessions locally",
  },
];

export default async function Home() {
  const plans = await listPlans().catch(() => []);
  const signedIn = dashboardEnabled() ? Boolean(await getDashboardUser().catch(() => null)) : false;
  return (
    <main className="overflow-hidden bg-white text-ink">
      <header className="border-b border-stone-200">
        <nav aria-label="Main navigation" className="mx-auto flex h-16 max-w-7xl items-center px-6">
          <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
            <span className="h-3 w-3 rounded-full bg-gradient-to-br from-dawn to-ember" />
            Daywalker Auth
          </Link>
          <div className="ml-auto flex items-center gap-6 text-sm font-medium">
            <Link href="/docs" className="text-stone-600 hover:text-ink">
              Docs
            </Link>
            <Link href="/dashboard" className="rounded-lg bg-ink px-4 py-2 text-white hover:bg-dusk">
              {signedIn ? "Dashboard" : "Log in"}
            </Link>
          </div>
        </nav>
      </header>

      <section className="relative border-b border-stone-200 bg-gradient-to-b from-dawn/10 to-white">
        <div className="mx-auto grid max-w-7xl gap-14 px-6 py-20 sm:py-28 lg:grid-cols-[1.1fr_0.9fr] lg:items-center lg:py-32">
          <div>
            <p className="mb-5 inline-flex items-center gap-2 rounded-full border border-dawn/40 bg-white px-3 py-1 text-xs font-semibold uppercase tracking-wide text-dusk">
              Authentication for the apps you build
            </p>
            <h1 className="max-w-3xl text-5xl font-semibold leading-[1.08] tracking-tight sm:text-6xl">
              Identity infrastructure, <span className="text-dusk">without the busywork.</span>
            </h1>
            <p className="mt-6 max-w-2xl text-lg leading-8 text-stone-600">
              Give your users secure sign-in, sessions, and organizations. Give your team a complete API and dashboard
              to manage it all.
            </p>
            <div className="mt-9 flex flex-wrap items-center gap-3">
              <Link href="/docs" className="rounded-lg bg-ink px-5 py-3 text-sm font-semibold text-white hover:bg-dusk">
                Read the docs <span aria-hidden="true">→</span>
              </Link>
              <Link href="/dashboard" className="rounded-lg border border-stone-300 bg-white px-5 py-3 text-sm font-semibold hover:border-stone-400">
                {signedIn ? "Open dashboard" : "Get started"}
              </Link>
            </div>
            <p className="mt-5 text-sm text-stone-500">Email · passkeys · social sign-in · MFA · SSO</p>
          </div>

          <div className="rounded-2xl border border-stone-200 bg-white p-5 shadow-xl shadow-ink/5 sm:p-7">
            <div className="flex items-center justify-between border-b border-stone-100 pb-4">
              <div>
                <p className="text-sm font-semibold">A safer session by default</p>
                <p className="mt-1 text-xs text-stone-500">Verified locally by your app</p>
              </div>
              <span className="rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-800">ES256</span>
            </div>
            <pre className="mt-5 overflow-x-auto rounded-xl bg-ink p-5 text-sm leading-7 text-stone-100"><code>{`const session = await auth();

if (!session) {
  redirect("/sign-in");
}

// Verified locally against your instance JWKS`}</code></pre>
            <div className="mt-5 grid grid-cols-3 gap-3 text-center">
              {[
                ["60 sec", "token lifetime"],
                ["Local", "verification"],
                ["Secure", "refresh cookie"],
              ].map(([value, label]) => (
                <div key={label} className="rounded-lg bg-stone-50 px-2 py-3">
                  <p className="text-sm font-semibold">{value}</p>
                  <p className="mt-1 text-xs text-stone-500">{label}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section aria-labelledby="features-heading" className="mx-auto max-w-7xl px-6 py-20 sm:py-24">
        <div className="max-w-2xl">
          <p className="text-sm font-semibold uppercase tracking-wide text-dusk">One platform, all the essentials</p>
          <h2 id="features-heading" className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">
            Authentication that grows with your product.
          </h2>
        </div>
        <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((feature) => (
            <article key={feature.title} className="rounded-2xl border border-stone-200 p-6">
              <div className="mb-5 h-1 w-10 rounded-full bg-gradient-to-r from-dawn to-ember" />
              <h3 className="text-lg font-semibold">{feature.title}</h3>
              <p className="mt-3 text-sm leading-6 text-stone-600">{feature.description}</p>
              <p className="mt-5 text-xs font-medium text-dusk">{feature.detail}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="border-y border-stone-200 bg-stone-50">
        <div className="mx-auto grid max-w-7xl gap-12 px-6 py-20 lg:grid-cols-2 lg:items-center">
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide text-dusk">Security by design</p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight">The details matter. They’re covered.</h2>
            <p className="mt-5 leading-7 text-stone-600">
              Personal data is encrypted at rest, while passwords and refresh tokens are never stored in recoverable
              form. Sessions are short-lived and checked against locally cached public keys.
            </p>
            <Link href="/docs" className="mt-6 inline-flex font-semibold text-dusk underline decoration-dawn decoration-2 underline-offset-4 hover:text-ink">
              Explore the security model <span aria-hidden="true" className="ml-1">→</span>
            </Link>
          </div>
          <dl className="grid gap-3 sm:grid-cols-2">
            {[
              ["AES-256-GCM", "Encrypted personal data"],
              ["Argon2id", "Hashed passwords"],
              ["Origin checks", "CSRF and CORS controls"],
              ["HMAC signatures", "Webhook verification"],
            ].map(([value, label]) => (
              <div key={value} className="rounded-xl border border-stone-200 bg-white p-5">
                <dt className="font-mono text-sm font-semibold">{value}</dt>
                <dd className="mt-2 text-sm text-stone-600">{label}</dd>
              </div>
            ))}
          </dl>
        </div>
      </section>

      <section aria-labelledby="api-heading" className="mx-auto max-w-7xl px-6 py-20 sm:py-24">
        <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide text-dusk">Made for your architecture</p>
            <h2 id="api-heading" className="mt-3 text-3xl font-semibold tracking-tight">The right interface for every layer.</h2>
          </div>
          <Link href="/docs/api/frontend" className="font-semibold text-dusk underline decoration-dawn decoration-2 underline-offset-4 hover:text-ink">
            Browse the API reference <span aria-hidden="true">→</span>
          </Link>
        </div>
        <dl className="mt-9 grid gap-4 lg:grid-cols-3">
          {apiSurfaces.map((surface) => (
            <div key={surface.name} className="rounded-2xl border border-stone-200 p-6">
              <dt className="font-semibold">{surface.name}</dt>
              <dd className="mt-3 break-all font-mono text-xs leading-5 text-stone-500">{surface.route}</dd>
              <dd className="mt-4 text-sm text-stone-600">{surface.access}</dd>
            </div>
          ))}
        </dl>
      </section>

      {plans.length > 0 && (
        <section aria-labelledby="pricing-heading" className="mx-auto max-w-7xl px-6 pb-20 sm:pb-24">
          <h2 id="pricing-heading" className="text-3xl font-semibold tracking-tight">Pricing</h2>
          <div className="mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {plans.map((p) => (
              <div key={p.id} className="rounded-2xl border border-stone-200 p-6">
                <h3 className="text-lg font-semibold">{p.name}</h3>
                <p className="mt-1 text-sm text-stone-600">{p.description}</p>
                <p className="mt-4 text-3xl font-semibold">{p.priceCents === 0 ? "Free" : `$${(p.priceCents / 100).toFixed(p.priceCents % 100 ? 2 : 0)}`}{p.priceCents > 0 && <span className="text-sm font-normal text-stone-500"> / {p.interval}</span>}</p>
                <ul className="mt-4 space-y-1 text-sm text-stone-700">
                  {p.features.filter((f) => f in PLAN_FEATURES).map((f) => <li key={f}>✓ {PLAN_FEATURES[f as keyof typeof PLAN_FEATURES]}</li>)}
                </ul>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="px-6 pb-20 sm:pb-24">
        <div className="mx-auto max-w-7xl rounded-3xl bg-ink px-6 py-12 text-white sm:px-12 sm:py-16">
          <div className="flex flex-col justify-between gap-8 sm:flex-row sm:items-center">
            <div className="max-w-2xl">
              <p className="text-sm font-semibold uppercase tracking-wide text-dawn">Start building</p>
              <h2 className="mt-3 text-3xl font-semibold tracking-tight">Your next sign-in flow starts here.</h2>
              <p className="mt-3 leading-7 text-stone-300">Get set up with the quickstart, then manage your instance from the dashboard.</p>
            </div>
            <div className="flex shrink-0 flex-wrap gap-3">
              <Link href="/docs" className="rounded-lg bg-white px-5 py-3 text-sm font-semibold text-ink hover:bg-stone-100">
                Start with the docs
              </Link>
              <Link href="/dashboard" className="rounded-lg border border-white/30 px-5 py-3 text-sm font-semibold hover:bg-white/10">
                {signedIn ? "Open dashboard" : "Get started"}
              </Link>
            </div>
          </div>
        </div>
      </section>

      <footer className="border-t border-stone-200">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-6 py-7 text-sm text-stone-500 sm:flex-row sm:items-center sm:justify-between">
          <p className="font-medium text-stone-700">Daywalker Auth</p>
          <nav aria-label="Footer navigation" className="flex flex-wrap gap-x-6 gap-y-2">
            <Link href="/docs" className="hover:text-ink">Documentation</Link>
            <Link href="/docs/api/frontend" className="hover:text-ink">API reference</Link>
            <Link href="/status" className="hover:text-ink">Status</Link>
            <Link href="/terms" className="hover:text-ink">Terms of Service</Link>
            <Link href="/dashboard" className="hover:text-ink">Dashboard</Link>
          </nav>
        </div>
      </footer>
    </main>
  );
}
