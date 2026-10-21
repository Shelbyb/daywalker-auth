export default function Home() {
  return (
    <main className="mx-auto flex min-h-dvh max-w-2xl flex-col justify-center px-6">
      <div className="mb-6 h-1 w-16 rounded-full bg-gradient-to-r from-dawn to-ember" />
      <h1 className="text-4xl font-semibold tracking-tight">Daywalker Auth</h1>
      <p className="mt-3 text-lg text-stone-600">
        Sign-in, sessions and user management for your applications. Short-lived signed tokens, encrypted user data,
        and a backend API for your servers.
      </p>
      <a href="/docs" className="mt-6 inline-flex w-fit items-center gap-1 rounded-lg bg-ink px-4 py-2 text-sm font-medium text-white hover:bg-dusk">
        Read the docs →
      </a>
      <dl className="mt-10 grid gap-6 text-sm sm:grid-cols-3">
        {[
          ["Frontend API", "/v1/client/*", "Publishable key"],
          ["Backend API", "/v1/users, /v1/sessions", "Secret key"],
          ["Token verification", "/i/{instance}/.well-known/jwks.json", "Public"],
        ].map(([t, p, a]) => (
          <div key={t} className="rounded-xl border border-stone-200 bg-white p-4">
            <dt className="font-medium">{t}</dt>
            <dd className="mt-1 break-all font-mono text-xs text-stone-500">{p}</dd>
            <dd className="mt-2 text-xs text-stone-400">{a}</dd>
          </div>
        ))}
      </dl>
    </main>
  );
}
