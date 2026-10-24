#!/usr/bin/env node
import { listen } from "../src/listen.mjs";

const HELP = `daywalker: command line for Daywalker Auth

Usage:
  daywalker listen --forward-to <url> [options]

Forwards webhook events from your DEVELOPMENT instance to a local server. Each event is signed
with a temporary secret that is printed at start, so your handler can verify it with
verifyWebhook(). Production instances are refused.

Options:
  --forward-to <url>   Where to POST events, e.g. http://localhost:3000/api/webhooks (required)
  --events <a,b,c>     Only these event types (default: all)
  --secret <whsec_..>  Use this signing secret instead of generating one
  --api-url <url>      Service URL (default https://users.daywalker.dev, or DAYWALKER_API_URL)
  --verbose            Also print each event payload (may contain personal data)
  -h, --help           Show this help

Authentication:
  Set DAYWALKER_SECRET_KEY to your development instance's secret key (sk_test_...).
  The key is read from the environment, not the command line, so it stays out of shell
  history and process lists.
`;

const args = process.argv.slice(2);
const cmd = args[0];
if (!cmd || cmd === "-h" || cmd === "--help" || cmd === "help") { console.log(HELP); process.exit(cmd ? 0 : 1); }
if (cmd !== "listen") { console.error(`Unknown command "${cmd}".\n`); console.error(HELP); process.exit(1); }

const flags = { "--forward-to": "forwardTo", "--events": "events", "--secret": "secret", "--api-url": "apiUrl" };
const opts = {};
for (let i = 1; i < args.length; i++) {
  const a = args[i];
  const [name, inline] = a.startsWith("--") && a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [a, undefined];
  if (name === "--verbose") { opts.verbose = true; continue; }
  if (name === "-h" || name === "--help") { console.log(HELP); process.exit(0); }
  if (name === "--key") { console.error("Pass the key in DAYWALKER_SECRET_KEY, not on the command line."); process.exit(1); }
  const field = flags[name];
  if (!field) { console.error(`Unknown option "${name}".`); process.exit(1); }
  const value = inline ?? args[++i];
  if (value === undefined) { console.error(`${name} needs a value.`); process.exit(1); }
  opts[field] = value;
}

const ac = new AbortController();
for (const s of ["SIGINT", "SIGTERM"]) process.on(s, () => ac.abort());
process.exitCode = await listen(opts, { signal: ac.signal });
