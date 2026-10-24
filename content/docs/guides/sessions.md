---
title: Sessions
plan: Pro
description: Session lifetime, inactivity timeout, single or multi-session and custom token claims.
---

In the dashboard, open your instance, then **Configure → User & authentication → Sessions**, change the settings and save.

| Setting | What it does |
| --- | --- |
| Maximum lifetime | Ends sessions after the instance's session lifetime (90-day hard cap always applies) |
| Inactivity timeout | Ends a session after this many idle minutes (blank = never) |
| Multi-session | When off, signing in ends the user's other sessions |
| Token lifetime | Seconds a session token is valid (30 to 600) |
| Device binding | Tie sessions to a key held in the browser, see [Device-bound sessions](/docs/guides/device-binding) |
| Custom claims | Extra claims added to the session token |

## Custom claims <span class="plan-badge">Pro</span>

Enter JSON mapping a claim name to a template, for example:

```json
{ "email": "{{user.email}}", "plan": "{{org.role}}" }
```

Variables: `user.id`, `user.email`, `user.first_name`, `user.last_name`, `org.id`, `org.role`. Unknown values become empty strings. Reserved names (`sub`, `iss`, `aud`, `exp`, `nbf`, `iat`, `jti`, `sid`, `azp`, `org_id`, `org_role`, `org_permissions`, `cnf`) are refused, as are more than 10 claims or more than 1 KB in total.

Claims are readable by the user, so never put secrets in them.

## In the SDK

`client.getEnvironment()` returns `sessions` (`multiSession`, `inactivityTimeoutMinutes`). In React, `useAuth().sessionClaims` holds the decoded token, including custom claims. On your server, `verifyToken` returns them as `claims`.

```tsx
const { sessionClaims } = useAuth();
const email = sessionClaims?.email as string | undefined;
```

When multi-session is on, list devices with `listSessions()` and end one with `revokeSession(id)`.
