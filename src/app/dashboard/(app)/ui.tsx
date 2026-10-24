"use client";

import { createContext, useContext, useState } from "react";
import { useFormStatus } from "react-dom";
import type { ActionState } from "./actions";
import { HelpLink, PageHelp } from "./help";

/** Shared look-and-feel primitives for the dashboard. */

import { btnCls, inputCls, type Tone } from "./styles";
export { btnCls, inputCls, type Tone };

export function PageHeader({ title, description }: { title: string; description: React.ReactNode }) {
  return (
    <header className="mb-6">
      <h1 className="text-xl font-semibold tracking-tight">{title} <PageHelp label={`Docs for ${title}`} /></h1>
      <p className="mt-1 max-w-2xl text-sm text-stone-600">{description}</p>
    </header>
  );
}

export function Card({ title, description, children, tone, help }: { title?: string; description?: React.ReactNode; children: React.ReactNode; tone?: "danger"; /** Doc slug for a "?" icon next to the title. */ help?: string }) {
  return (
    <section className={`rounded-xl border bg-white p-5 shadow-sm ${tone === "danger" ? "border-ember/40" : "border-stone-200"}`}>
      {title && <h2 className={`text-base font-semibold ${tone === "danger" ? "text-ember" : ""}`}>{title}{help && <HelpLink slug={help} label={`Help: ${title}`} />}</h2>}
      {description && <p className="mt-1 text-sm text-stone-600">{description}</p>}
      <div className={title || description ? "mt-4" : ""}>{children}</div>
    </section>
  );
}

const badgeTones = {
  neutral: "bg-stone-100 text-stone-700",
  good: "bg-emerald-50 text-emerald-700",
  warn: "bg-dawn/20 text-amber-800",
  bad: "bg-ember/10 text-ember",
};
export function Badge({ tone = "neutral", children }: { tone?: keyof typeof badgeTones; children: React.ReactNode }) {
  return <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${badgeTones[tone]}`}>{children}</span>;
}

export function Field({ label, hint, children }: { label: string; hint?: React.ReactNode; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-stone-700">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-stone-500">{hint}</span>}
    </label>
  );
}

export function Skeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="animate-pulse space-y-3 rounded-xl border border-stone-200 bg-white p-5" aria-busy="true" aria-label="Loading">
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="h-4 rounded bg-stone-100" style={{ width: `${90 - i * 15}%` }} />
      ))}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-dashed border-stone-300 bg-white p-8 text-center">
      <h3 className="font-semibold">{title}</h3>
      <p className="mx-auto mt-1 max-w-md text-sm text-stone-600">{children}</p>
    </div>
  );
}

/** Lets a form that submits through a transition (ActionForm) tell its buttons it is busy. */
export const PendingContext = createContext(false);

export function SubmitButton({ children, tone = "primary", pendingText = "Please wait…" }: { children: React.ReactNode; tone?: Tone; pendingText?: string }) {
  const { pending } = useFormStatus();
  const busy = pending || useContext(PendingContext);
  return (
    <button type="submit" disabled={busy} className={btnCls[tone]}>
      {busy ? pendingText : children}
    </button>
  );
}

/** Always mounted so screen readers announce changes. */
export function FormMessage({ state }: { state: ActionState }) {
  return (
    <div aria-live="polite" className="text-sm">
      {state.error ? (
        <p role="alert" className="rounded-lg bg-ember/10 px-3 py-2 text-ember">{state.error}</p>
      ) : state.ok && state.message ? (
        <p className="rounded-lg bg-emerald-50 px-3 py-2 text-emerald-700">{state.message}</p>
      ) : null}
    </div>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [status, setStatus] = useState<"idle" | "ok" | "fail">("idle");
  return (
    <button
      type="button"
      className={`${btnCls.ghost} !px-2.5 !py-1 text-xs`}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setStatus("ok");
        } catch {
          setStatus("fail");
        }
        setTimeout(() => setStatus("idle"), 2500);
      }}
    >
      <span aria-live="polite">{status === "ok" ? "Copied" : status === "fail" ? "Copy failed, select it by hand" : label}</span>
    </button>
  );
}

export function CodeBlock({ value, label }: { value: string; label?: string }) {
  return (
    <div>
      {label && <p className="mb-1 text-sm font-medium text-stone-700">{label}</p>}
      <div className="flex items-start gap-2 rounded-lg border border-stone-200 bg-stone-50 p-2.5">
        <pre className="min-w-0 flex-1 overflow-x-auto whitespace-pre font-mono text-[13px] leading-6" tabIndex={0}>{value}</pre>
        <CopyButton value={value} />
      </div>
    </div>
  );
}

/** A secret that is shown exactly once: kept only in this component's memory. */
export function RevealOnce({ label, value }: { label: string; value: string }) {
  const [hidden, setHidden] = useState(false);
  if (hidden) return <p className="rounded-lg bg-stone-100 px-3 py-2 text-sm text-stone-600">{label} hidden. It can't be shown again.</p>;
  return (
    <div role="status" className="rounded-lg border-2 border-dawn bg-dawn/10 p-3">
      <p className="text-sm font-semibold">{label}</p>
      <p className="mt-0.5 text-sm text-stone-700">Copy it now, you won&apos;t see it again. Store it somewhere safe, like a password manager or your host&apos;s secret settings.</p>
      <div className="mt-2 flex items-start gap-2 rounded-lg bg-white p-2.5">
        <code className="min-w-0 flex-1 select-all break-all font-mono text-[13px]">{value}</code>
        <CopyButton value={value} />
      </div>
      <button type="button" onClick={() => setHidden(true)} className="mt-2 text-xs font-medium text-stone-600 underline underline-offset-2 hover:text-ink">
        I&apos;ve saved it, hide
      </button>
    </div>
  );
}
