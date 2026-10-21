"use client";

import { useActionState, useEffect, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import type { ActionState } from "./actions";
import { FormMessage, PendingContext, RevealOnce, SubmitButton, btnCls, type Tone } from "./ui";

type Action = (prev: ActionState, fd: FormData) => Promise<ActionState>;

/**
 * Wraps a server action. Submits through a transition (not the form's `action`) so React
 * doesn't wipe what the person typed when the server returns a validation error.
 */
export function ActionForm({
  action, children, submit, tone = "primary", className = "space-y-4", resetOnSuccess, extra, secretLabel = "Secret", showKeys = false,
}: {
  action: Action;
  children?: React.ReactNode;
  submit: string;
  tone?: Tone;
  className?: string;
  resetOnSuccess?: boolean;
  extra?: React.ReactNode;
  secretLabel?: string;
  showKeys?: boolean;
}) {
  const [state, formAction] = useActionState<ActionState, FormData>(action, { ok: false });
  const [pending, start] = useTransition();
  const ref = useRef<HTMLFormElement>(null);
  const router = useRouter();
  useEffect(() => {
    if (!state.ok) return;
    if (resetOnSuccess) ref.current?.reset();
    if (state.redirectTo) router.replace(state.redirectTo);
  }, [state, resetOnSuccess, router]);
  return (
    <PendingContext.Provider value={pending}>
      <form
        ref={ref}
        className={className}
        onSubmit={(e) => {
          e.preventDefault();
          const fd = new FormData(e.currentTarget);
          start(() => formAction(fd));
        }}
      >
        {children}
        <div className="flex flex-wrap items-center gap-2">
          <SubmitButton tone={tone}>{submit}</SubmitButton>
          {extra}
        </div>
        <FormMessage state={state} />
        {state.ok && showKeys && state.publishableKey && (
          <div className="space-y-1 text-sm">
            <p className="font-medium">Publishable key (safe to put in your frontend)</p>
            <code className="block break-all rounded-lg bg-stone-100 px-3 py-2 font-mono text-[13px]">{state.publishableKey}</code>
          </div>
        )}
        {state.ok && state.secret && <RevealOnce label={secretLabel} value={state.secret} />}
        {state.ok && showKeys && state.instanceId && (
          <a href={`/dashboard/instances/${encodeURIComponent(state.instanceId)}`} className="inline-block text-sm font-medium underline decoration-dawn decoration-2 underline-offset-4">
            Open your new instance
          </a>
        )}
      </form>
    </PendingContext.Provider>
  );
}

/** A button that asks "are you sure?" with a second click before the action runs. */
export function ConfirmAction({
  action, label, confirmLabel, prompt, children, tone = "danger", secretLabel,
}: {
  action: Action;
  label: string;
  confirmLabel: string;
  prompt: string;
  children?: React.ReactNode;
  tone?: Tone;
  secretLabel?: string;
}) {
  const [armed, setArmed] = useState(false);
  if (!armed)
    return (
      <button type="button" onClick={() => setArmed(true)} className={`${btnCls.ghost} !px-2.5 !py-1 text-xs ${tone === "danger" ? "!text-ember" : ""}`}>
        {label}
      </button>
    );
  return (
    <ActionForm
      action={action}
      submit={confirmLabel}
      tone={tone}
      secretLabel={secretLabel}
      className="space-y-2 rounded-lg border border-stone-200 bg-stone-50 p-2.5"
      extra={
        <button type="button" autoFocus onClick={() => setArmed(false)} className={`${btnCls.ghost} !px-2.5 !py-1 text-xs`}>
          Cancel
        </button>
      }
    >
      <p className="text-xs text-stone-700">{prompt}</p>
      {children}
    </ActionForm>
  );
}
