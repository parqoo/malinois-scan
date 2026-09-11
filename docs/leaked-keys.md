# Which keys are safe in a browser bundle, and which one ends your week

This page covers the `supabase_service_role_in_client`, `google_api_key_client`, and the
leaked-secret findings (`stripe_secret`, `openai_key`, `anthropic_key`, `aws_key`,
`private_key`).

Everything in your front-end bundle is public. Not "hard to find" — public. Anyone can open
devtools, or just `curl` the JavaScript file. So the only question that matters is: **which
of these keys were designed to be public?**

| Key | Safe in the browser? | If exposed |
|---|---|---|
| Supabase **anon** key | ✅ Yes, by design | Nothing — RLS is what protects you |
| Firebase **web API key** | ✅ Yes, by design | Nothing — security rules are what protect you |
| Google Maps / Cloud key | ⚠️ Only if restricted | Quota and billing abuse |
| Supabase **service_role** | ❌ Never | Full read/write on your entire database, RLS bypassed |
| `sk_live_…` (Stripe) | ❌ Never | Charges and refunds on your account |
| OpenAI / Anthropic | ❌ Never | Your bill, someone else's usage |
| AWS `AKIA…` | ❌ Never | Storage, servers, databases |
| `-----BEGIN … PRIVATE KEY-----` | ❌ Never | Impersonation of your service |

## The one that actually matters: `service_role`

Supabase gives you two keys. They look similar. They are not.

- **anon** — meant for browsers. Row Level Security still applies to it.
- **service_role** — meant for servers. **It ignores RLS completely.**

If `service_role` is in your bundle, every RLS policy you wrote is decorative. Someone with
that key can read and write every row in every table.

It usually gets there one of two ways: an AI builder wired up "the Supabase key" without
distinguishing them, or someone hit a permissions error and swapped in the key that "just
worked."

**If it is exposed:**

1. Rotate it now — Supabase → Settings → API → regenerate `service_role`.
2. Remove it from all front-end code and from any `NEXT_PUBLIC_` / `VITE_` / `PUBLIC_`
   environment variable. Any prefix like that means "ship this to the browser."
3. Move whatever needed it to a server route, an edge function, or a database function.
4. Assume it was seen. Check your data for anything that shouldn't be there.

Rotating alone is not enough if the code still ships the new key. Fix the code path first.

## Why prefixed env vars leak

Bundlers inline these at build time — that is their entire purpose:

```
NEXT_PUBLIC_*   →  shipped to the browser
VITE_*          →  shipped to the browser
PUBLIC_*        →  shipped to the browser
REACT_APP_*     →  shipped to the browser
```

A secret in any of those is not a secret. Renaming it does not help; it has to move to code
that runs on a server.

## Google / Firebase `AIza…` keys

These are public by design, so this scanner does **not** report them as leaked secrets — that
would be crying wolf on every Firebase app. What it does flag (`google_api_key_client`) is a
bare `AIza…` key with no Firebase config around it, because that pattern is usually a Maps or
Cloud key, and an unrestricted one can be used on someone else's site at your expense.

Fix: Google Cloud Console → Credentials → your key → restrict it to your domain and to only
the APIs it needs.

## Check what your deployment is actually shipping

Reading your own source will not tell you — the bundle is what ships, and it is built from
more than the file you are looking at.

```bash
npx malinois-scan https://your-app.example --i-own-this
```

This fetches your deployed HTML and JavaScript the way a visitor does and pattern-matches for
the keys above. Findings show a **masked** form (`sk_live_…ab12`) and where it was found — the
raw value is never printed or stored.

In CI, so a future deploy can't reintroduce one:

```yaml
- uses: parqoo/malinois-scan@v0
  with:
    url: https://your-app.example
    fail-on: critical
```

Scheduled re-checks with alerting on newly-appeared leaks:
<https://malinois.app/?src=gh_docs_keys>

## Related

- [Supabase RLS](./supabase-rls.md) — the anon key is only safe when RLS is on
- [Exposed `.env` and `.git`](./exposed-files.md) — the other way keys escape
- [Firebase security rules](./firebase-rules.md)
