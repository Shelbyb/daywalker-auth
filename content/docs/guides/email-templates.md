---
title: Email templates
description: Change the wording and color of the emails Daywalker sends your users.
---

# Email templates

Daywalker sends four kinds of email for your app. You can rewrite each one, and set a brand color for buttons and links.

| Email | Sent when | Placeholders (required in **bold**) |
| --- | --- | --- |
| Email verification (`verify_email`) | A new user confirms their address | `{{app_name}}`, **`{{code}}`**, `{{expires_minutes}}` |
| Password reset (`reset_password`) | Someone uses "Forgot password" | `{{app_name}}`, **`{{code}}`**, `{{expires_minutes}}` |
| Sign-in code and link (`sign_in`) | [Passwordless sign-in](/docs/guides/email-codes) | `{{app_name}}`, **`{{code}}`**, **`{{link}}`**, `{{expires_minutes}}` |
| Organization invitation (`invitation`) | Someone is invited to an organization | `{{app_name}}`, `{{org_name}}`, `{{inviter}}`, **`{{link}}`**, `{{expires_days}}` |

## In the dashboard

Open your instance and choose **Emails**. Edit the subject and body, then **Save**. A preview with sample values shows what users will see, and **Send me a test** emails it to your own address. **Reset to default** brings back the built-in wording.

## Writing a template

Write **plain text**. Blank lines separate paragraphs. A few rules keep emails working and safe:

- Only the placeholders listed for that email are allowed, and the required ones must stay in the body. A sign-in email without a code would be useless.
- Put `{{code}}` on a line by itself to show it large, or `{{link}}` on a line by itself to show it as a button.
- The subject must be a single line, up to 200 characters. The body can be up to 5,000.
- **HTML isn't allowed.** Everything you type is escaped, so `<b>` shows up as text. Values like organization names, which your users choose, are escaped too, so nobody can inject markup or links into an email.

Daywalker builds the HTML version for you, with no tracking pixels or remote images, and sends the plain-text version alongside it.

## From your backend

```ts
import { createBackendClient } from "@daywalker/auth/server";

const daywalker = createBackendClient({ secretKey: process.env.DAYWALKER_SECRET_KEY!, apiUrl: "https://users.daywalker.dev" });

await daywalker.emailTemplates.update("verify_email", {
  subject: "Your {{app_name}} code is {{code}}",
  body: "Welcome aboard!\n\n{{code}}\n\nThis code expires in {{expires_minutes}} minutes.",
});

await daywalker.emailTemplates.setAccentColor("#4f46e5"); // or null for the default
await daywalker.emailTemplates.reset("verify_email");     // back to the built-in wording
const { data } = await daywalker.emailTemplates.list();   // current wording of all four
```

Plain HTTP works too: `GET /v1/email_templates`, `GET|PUT|DELETE /v1/email_templates/{kind}` and `PUT /v1/email_templates/branding`. A template with an unknown or missing placeholder gets a `400` with code `invalid_template` and a message saying what to fix; one that is too long gets a `422`.

Changes are recorded in the [audit log](/docs/guides/audit-logs).
