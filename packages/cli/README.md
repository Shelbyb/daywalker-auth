# @daywalker/cli

```bash
export DAYWALKER_SECRET_KEY=sk_test_...   # development instance only
npx @daywalker/cli listen --forward-to http://localhost:3000/api/webhooks
```

Forwards webhook events from a development instance to your local server, signed with a temporary secret printed at start. See the [webhooks guide](https://users.daywalker.dev/docs/guides/webhooks#testing-locally).
