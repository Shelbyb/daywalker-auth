---
title: Enterprise SSO (SAML)
description: Let a company's people sign in with their own identity provider, such as Okta, Entra ID or Google Workspace.
---

# Enterprise SSO (SAML)

Larger customers often require **single sign-on**: their employees sign in to your app through the company's identity provider (IdP), such as Okta, Microsoft Entra ID, Google Workspace, JumpCloud or OneLogin. When someone leaves the company, IT switches them off in one place.

Daywalker supports SAML 2.0. Each customer gets a **connection** that's tied to their email domains. Anyone who signs in with an email at those domains goes through that company's IdP.

## 1. Create a connection

In the dashboard, open your instance and choose **SSO → Add a connection**:

- **Name**, for example "Acme Corp (Okta)".
- **Email domains**, for example `acme.com`. Each domain can belong to only one connection.
- **Organization** (optional). People who sign in through this connection join it automatically as members.
- **IdP metadata XML**, which the customer's IT team downloads from their IdP. Or enter the IdP entity ID, sign-in URL and signing certificate by hand.

Then give the customer the two values shown on the connection:

| Daywalker shows | IdP calls it |
|---|---|
| **ACS (reply) URL** `…/v1/saml/<id>/acs` | Assertion Consumer Service URL, Single sign-on URL, Reply URL |
| **Entity ID / Audience** `…/v1/saml/<id>/metadata` | Audience URI, SP Entity ID, Identifier |

Many IdPs can also import the metadata URL directly. Ask them to:

- send the user's email as the **NameID** (format: email address) or as an attribute named `email`, and
- **sign the assertion** (the default almost everywhere).

`firstName` and `lastName` attributes are optional, and are used for new users' names.

## 2. Sign in

**Hosted pages:** once a connection exists, the sign-in page shows **Sign in with SSO**. The user types their work email and is sent to their company's sign-in page.

**Drop-in components:** `<SignIn />` shows the same button.

**Your own UI:**

```ts
const { sso } = await auth.checkSSO(email);   // does this domain use SSO?
if (sso) auth.signInWithSSO(email, "https://app.example.com/dashboard"); // full-page redirect
```

If the user has two-factor turned on in your app, they're still asked for it after SSO.

## From your backend

```bash
curl -X POST https://users.daywalker.dev/v1/saml_connections \
  -H "Authorization: Bearer $DAYWALKER_SECRET_KEY" -H "content-type: application/json" \
  -d '{ "name": "Acme", "domains": ["acme.com"], "organizationId": "org_…", "metadataXml": "<EntityDescriptor …>" }'
```

Also: `GET /v1/saml_connections`, `GET|PATCH|DELETE /v1/saml_connections/{id}`. Instead of `metadataXml` you can send `idpEntityId`, `ssoUrl` and `certificates` (PEM). `PATCH` with `{ "enabled": false }` pauses a connection.

## How it's kept safe

- **Signed assertions only.** Each assertion must be signed by one of the connection's certificates. Signature checks use the maintained `@node-saml/node-saml` library, which rejects signature-wrapping tricks.
- **Must answer our request.** Every sign-in starts at Daywalker. The response has to answer that exact request, from the browser that started it. Replayed responses, responses to a different request, and unsolicited (IdP-initiated) responses are refused.
- **Right audience, issuer, recipient and time.** Assertions for another app, from another issuer, sent to another URL, or expired are refused.
- **The IdP can only vouch for its own domains.** An email is trusted only if it's at one of the connection's domains. A misconfigured or hostile IdP can't sign someone in as `ceo@another-company.com`.
- **Existing accounts.** If someone already signed up with a password at that domain without verifying their email, the password is removed when SSO first links the account. This protects against someone pre-registering an employee's address.
- **Safe metadata parsing.** Metadata with a DOCTYPE is refused (no XML external entities), and certificates must be valid and unexpired.
- Sign-ins (`method: "saml"`) and rejected responses appear in the [audit log](/docs/guides/audit-logs).

## Certificate rotation

IdPs rotate signing certificates every year or two. Before the old one expires, add the new certificate to the connection (it accepts up to three) or paste fresh metadata. Then remove the old one after the IdP switches over. The dashboard shows each certificate's expiry date.
