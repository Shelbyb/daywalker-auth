"use client";

import { useEffect, type ReactNode } from "react";
import { AuthProvider, CreateOrganization, OrganizationProfile, useAuth } from "@daywalker/auth/react";

/** Sends visitors who aren't signed in to the hosted sign-in page, then back here. */
function Gate({ pk, children }: { pk: string; children: ReactNode }) {
  const { isLoaded, isSignedIn } = useAuth();
  useEffect(() => {
    if (isLoaded && !isSignedIn) {
      const here = window.location.pathname + window.location.search;
      window.location.replace(`/sign-in?pk=${encodeURIComponent(pk)}&redirect_url=${encodeURIComponent(here)}`);
    }
  }, [isLoaded, isSignedIn, pk]);
  if (!isLoaded || !isSignedIn) return <div className="h-64 animate-pulse rounded-2xl bg-white" aria-busy="true" />;
  return <>{children}</>;
}

/** The hosted organization pages render the same components customers embed. */
export function HostedOrg(props: { kind: "profile" | "create"; pk: string; origin: string; organizationId?: string; back?: string; profileUrl: string; createUrl: string }) {
  return (
    <div className="hosted-embed w-full rounded-2xl border border-stone-200 bg-white p-6 shadow-xl shadow-stone-300/40">
      <AuthProvider publishableKey={props.pk} frontendApi={props.origin} syncCookie={false}>
        <Gate pk={props.pk}>
          {props.kind === "create" ? (
            <CreateOrganization afterCreateUrl={props.back ?? props.profileUrl} />
          ) : (
            <OrganizationProfile organizationId={props.organizationId} afterLeaveUrl={props.back ?? props.createUrl} />
          )}
        </Gate>
      </AuthProvider>
    </div>
  );
}
