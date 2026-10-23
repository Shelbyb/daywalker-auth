---
title: Roadmap
description: What's built, and what's planned next, in the order we plan to build it.
---

Everything on the [Overview](/docs) page is built and tested. This page lists what comes next. Items are ordered by how much they help and how much work they are; we ship and test them one at a time.

## Planned next

| # | Feature | Why it matters | Status |
| --- | --- | --- | --- |
| 1 | **Signing-key rotation** | Replace the keys that sign session tokens without signing anyone out | Done |
| 2 | **`MASTER_KEY` rotation** | Re-encrypt stored data under a new master key, with a script | Done |
| 3 | **Audit logs** | A searchable record of sign-ins, key changes and settings changes per instance, in the dashboard and API | Done |
| 4 | **Magic links and email codes** | Passwordless sign-in: click a link or type a code from your email | Done |
| 5 | **Breached-password check** | Reject passwords found in known data breaches (privacy-preserving k-anonymity lookup) | Done |
| 6 | **Custom email templates** | Edit the wording and branding of verification, reset and invitation emails per instance | Done |
| 7 | **More social providers** | Microsoft, Apple, Discord, GitLab and any OpenID Connect provider | Done |
| 8 | **Embeddable components** | Drop-in `<SignIn />`, `<SignUp />`, `<UserButton />` and `<OrganizationSwitcher />` for React | Done |
| 9 | **Enterprise SSO (SAML)** | Let an organization's members sign in with their company identity provider | Done |
| 10 | **SMS codes** | Text-message codes as an opt-in second factor, through Twilio Verify | Done |

## Already done

Email and password, email verification, password reset, social sign-in (Google, GitHub, Microsoft, Apple, Discord, GitLab, OpenID Connect), passkeys, two-factor, organizations and invitations, webhooks, required terms acceptance, the hosted account page, the developer dashboard, signing-key and `MASTER_KEY` rotation, audit logs, magic links and email codes, the breached-password check, custom email templates, more social providers, drop-in React components, enterprise SSO (SAML) with an optional "SSO required" rule and SCIM user provisioning, SMS two-factor with a country allow-list, security keys (WebAuthn) as a second factor, and DigitalOcean deployment. See the [guides](/docs/quickstart).
