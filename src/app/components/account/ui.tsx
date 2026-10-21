"use client";

import { useState } from "react";

/** Small shared building blocks for the account page. */
export function Card({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return (
    <section className="rounded-2xl border border-stone-200 bg-white p-6 shadow-sm">
      <h2 className="text-base font-semibold">{title}</h2>
      {description && <p className="mt-1 text-sm text-stone-500">{description}</p>}
      <div className="mt-5">{children}</div>
    </section>
  );
}

export function Field(props: React.InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const { label, ...rest } = props;
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-stone-700">{label}</span>
      <input
        {...rest}
        className="w-full rounded-lg border border-stone-300 bg-white px-3 py-2 text-sm outline-none focus:border-dawn focus:ring-2 focus:ring-dawn/30"
      />
    </label>
  );
}

export function Button({ variant = "primary", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" }) {
  const styles = {
    primary: "bg-ink text-white hover:bg-dusk",
    secondary: "border border-stone-300 bg-white hover:bg-stone-50",
    danger: "border border-ember/40 bg-white text-ember hover:bg-ember/5",
  }[variant];
  return <button {...props} className={`rounded-lg px-4 py-2 text-sm font-medium transition disabled:opacity-60 ${styles} ${props.className ?? ""}`} />;
}

export function Notice({ tone, children }: { tone: "error" | "success"; children: React.ReactNode }) {
  return (
    <p role={tone === "error" ? "alert" : "status"} className={`rounded-lg px-3 py-2 text-sm ${tone === "error" ? "bg-ember/10 text-ember" : "bg-emerald-50 text-emerald-700"}`}>
      {children}
    </p>
  );
}

export function Badge({ children, tone = "neutral" }: { children: React.ReactNode; tone?: "neutral" | "good" | "warn" }) {
  const t = { neutral: "bg-stone-100 text-stone-600", good: "bg-emerald-50 text-emerald-700", warn: "bg-amber-50 text-amber-700" }[tone];
  return <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${t}`}>{children}</span>;
}

/** Runs an async action with busy/error/success state. */
export function useAction() {
  const [state, setState] = useState<{ busy: boolean; error: string | null; ok: string | null }>({ busy: false, error: null, ok: null });
  async function run(fn: () => Promise<string | void>) {
    setState({ busy: true, error: null, ok: null });
    try {
      const ok = await fn();
      setState({ busy: false, error: null, ok: ok ?? null });
    } catch (e) {
      setState({ busy: false, error: e instanceof Error ? e.message : "Something went wrong", ok: null });
    }
  }
  return { ...state, run };
}

