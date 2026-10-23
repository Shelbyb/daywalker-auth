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

## Require SSO

By default people at a connection's domains can still use a password or any other sign-in method. To make SSO the only way in, open the connection on the **SSO** tab and press **Require SSO** (or send `{ "ssoRequired": true }`).

Then, for addresses at those domains:

- Password sign-in, sign-up, email codes, magic links, passkeys, social sign-in and password reset are all refused with the error code `sso_required`.
- Only the identity provider can open a session. This is enforced where sessions are created, so no sign-in route can skip it.
- `checkSSO(email)` returns `required: true`, so your own form can hide the password field.
- Other domains are unaffected.
- Pausing the connection (`enabled: false`) also pauses the rule, so a broken identity provider never locks everyone out.

When you switch it on, everyone already signed in at those domains is signed out, so they come back through your identity provider. People at other domains are not affected.

Enforcement uses each person's primary email address.

## Automatic provisioning (SCIM)

SSO lets people sign in. **SCIM** lets the company's identity provider also *create, update and deactivate* their accounts here, so new hires are ready on day one and leavers lose access straight away, without anyone touching your dashboard.

**Turn it on**

1. On the **SSO** tab, open the connection and press **Turn on provisioning**. You get a **SCIM base URL** and a **token**. Copy the token now: it's shown once and only a hash is kept.
2. In the identity provider's SCIM settings, paste the base URL (it ends in `/v1/scim/v2/<connection id>`), choose **HTTP header / bearer token** authentication, and paste the token.
3. Assign people to the app in the identity provider. Okta, Microsoft Entra ID and others do the rest.

From your backend: `POST /v1/saml_connections/{id}/scim_token` makes or rotates the token and `DELETE` of the same URL turns provisioning off.

**What it does**

| The identity provider… | Here |
| --- | --- |
| creates a person | An account is made with a verified email, no password, and (if the connection has one) membership of its organization. They sign in through SSO. |
| changes name or email | The account is updated. The email has to stay at one of the connection's domains. |
| deactivates a person (`active: false`) | The account is suspended and **signed out everywhere**. Setting `active: true` restores it. |
| deletes a person | The account is deleted. |
| looks up an email it already knows | An existing account at the connection's domain is adopted, so people who signed up before SCIM aren't duplicated. |

Pair it with **Require SSO** (above) so provisioned people can only ever sign in through the identity provider.

**What it can't do**

- It only manages people at **the connection's own domains**, and only accounts it created or adopted. Nobody else's account can be read, changed or deleted through it, even by guessing an ID.
- If an adopted account's email was never verified (someone signed up with a password first), the password and any sessions are removed, the same protection SAML sign-in gives you.
- Supported: `Users` with `userName`, `externalId`, `name`, `emails`, `active`; `GET`, `POST`, `PUT`, `PATCH`, `DELETE`; and `userName eq` / `externalId eq` filters. Groups, bulk requests and sorting aren't supported. The discovery endpoints (`/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`) say so.
- Rotating the token cuts the old one off at once. Requests are limited to 600 a minute per connection.
- Provisioning events are in the [audit log](/docs/guides/audit-logs) (`scim_user.created`, `scim_user.deactivated`, and so on).

## From your backend

```bash
curl -X POST https://users.daywalker.dev/v1/saml_connections \
  -H "Authorization: Bearer $DAYWALKER_SECRET_KEY" -H "content-type: application/json" \
  -d '{ "name": "Acme", "domains": ["acme.com"], "organizationId": "org_…", "metadataXml": "<EntityDescriptor …>" }'
```

Also: `GET /v1/saml_connections`, `GET|PATCH|DELETE /v1/saml_connections/{id}`. Instead of `metadataXml` you can send `idpEntityId`, `ssoUrl` and `certificates` (PEM). `PATCH` with `{ "enabled": false }` pauses a connection, and `{ "ssoRequired": true }` makes SSO the only sign-in method for its domains.

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
