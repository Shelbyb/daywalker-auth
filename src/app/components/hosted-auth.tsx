"use client";

import { AuthProvider, SignIn, SignUp, type EnvironmentInfo } from "@daywalker/auth/react";

/**
 * The hosted sign-in / sign-up pages render the same drop-in components customers use,
 * so there is one UI to maintain. Everything here arrives from the server already
 * validated: the redirect has been checked against the instance's allow-list, and the
 * error is only a code that the component maps to a fixed message.
 */
export function HostedAuth(props: {
  mode: "sign-in" | "sign-up";
  pk: string;
  origin: string; // this service's own URL (APP_URL)
  redirect?: string; // allow-listed app URL, if any
  returnTo: string; // where provider/SSO flows come back to
  otherUrl: string; // link to the other hosted page
  environment: EnvironmentInfo;
  error?: string;
  signedIn?: boolean;
}) {
  const common = {
    redirectUrl: props.redirect ?? props.returnTo,
    initialEnvironment: props.environment,
    initialError: props.error,
    signedIn: props.signedIn,
  };
  return (
    <div className="hosted-embed">
      <AuthProvider publishableKey={props.pk} frontendApi={props.origin} syncCookie={false}>
        {props.mode === "sign-in" ? <SignIn {...common} signUpUrl={props.otherUrl} /> : <SignUp {...common} signInUrl={props.otherUrl} />}
      </AuthProvider>
    </div>
  );
}
