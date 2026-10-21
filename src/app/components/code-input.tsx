"use client";

/** Single field for a 6-digit code: numeric keypad on phones and one-time-code autofill. */
export function CodeInput({ name = "code", error }: { name?: string; error?: string }) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-stone-700">Verification code</span>
      <input
        name={name}
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern="\d{6}"
        maxLength={6}
        required
        aria-invalid={!!error}
        className="w-full rounded-lg border border-stone-300 bg-white px-3 py-2 text-center font-mono text-lg tracking-[0.4em] outline-none focus:border-dawn focus:ring-2 focus:ring-dawn/30 aria-[invalid=true]:border-ember"
      />
      {error && <span className="mt-1 block text-xs text-ember">{error}</span>}
    </label>
  );
}

export function Submit({ busy, children }: { busy: boolean; children: React.ReactNode }) {
  return (
    <button
      disabled={busy}
      className="w-full rounded-lg bg-ink px-4 py-2.5 text-sm font-medium text-white transition hover:bg-dusk disabled:opacity-60"
    >
      {busy ? "Please wait…" : children}
    </button>
  );
}

export function Alert({ children, tone = "error" }: { children: React.ReactNode; tone?: "error" | "info" }) {
  return (
    <p role={tone === "error" ? "alert" : "status"} className={`rounded-lg px-3 py-2 text-sm ${tone === "error" ? "bg-ember/10 text-ember" : "bg-stone-100 text-stone-600"}`}>
      {children}
    </p>
  );
}
