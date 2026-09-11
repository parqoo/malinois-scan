# malinois-scan

**Passive security check for an app you just shipped.** One command, no signup, no account, no agent installed.

```bash
npx malinois-scan https://my-app.example --i-own-this
```

```
  Grade D  50/100   my-app.example

  3 issues found

  CRITICAL  A database table is open to the public
           What it means: Anyone on the internet can read this table directly — no login
           required. If it holds names, emails, or other customer info, that data is
           exposed right now.
           What to do:    In Supabase, open your table → "Row Level Security" and turn RLS
           ON (there's a one-click button), then add a policy so only the right users can
           read it.

  CRITICAL  Your secret settings file (.env) can be downloaded
           ...
```

It checks what any visitor can already see from outside your app — no exploitation, no
injection, no load testing, no credentials needed.

---

## Why this exists

AI builders (Lovable, Replit, Bolt, v0, Base44) made shipping trivial. They did not make
*day 2* trivial. The most common ways these apps leak are boring and repeatable:

- a Supabase/Firebase table left readable by anyone
- a `service_role` key or API key sitting in the JavaScript bundle
- `.env` or `.git` served publicly
- source maps shipping your original code

Platform scans run when you hit publish. **The leak usually arrives on the redeploy after
that** — which is exactly what a check in CI catches.

## What it checks

| Category | Examples |
|---|---|
| Public databases | Supabase tables readable with the anon key, Firebase Realtime DB / Firestore open rules |
| Leaked secrets | Stripe `sk_live`, OpenAI, Anthropic, AWS, private keys, Supabase `service_role` in client code |
| Exposed files | `.env`, `.env.local`, `.env.production`, `.git`, source maps |
| Transport & headers | Mixed content, permissive CORS, missing CSP / HSTS / X-Frame-Options |

Every finding comes with **what it means** and **what to do**, in plain language — not just
a rule name.

### Fixing what it finds

Longer write-ups for the findings people hit most, including the exact errors you'll see
while fixing them:

- **[Supabase RLS](docs/supabase-rls.md)** — `new row violates row-level security policy`,
  `permission denied for table`, and the silent case where RLS is simply off
- **[Which keys are safe in a browser bundle](docs/leaked-keys.md)** — anon vs
  `service_role`, why `NEXT_PUBLIC_`/`VITE_` secrets aren't secret
- **[Firebase security rules](docs/firebase-rules.md)** — `Missing or insufficient
  permissions`, and open test-mode rules that never error
- **[Exposed `.env`, `.git`, source maps](docs/exposed-files.md)** — what to rotate after

## Use it in CI (the part that actually matters)

Add this and your build fails the moment a deploy introduces a leak:

```yaml
# .github/workflows/security.yml
name: Security
on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: parqoo/malinois-scan@v0
        with:
          url: https://my-app.example
          fail-on: high
```

The job summary shows the grade and every finding. Outputs `grade`, `score`, and
`findings` are available to later steps.

## CLI options

```
npx malinois-scan <url> --i-own-this [options]

  --i-own-this        Required. Confirms you own the app or have permission.
  --json              Machine-readable output (for CI).
  --fail-on <level>   Exit 1 at/above this level. critical|high|medium|low (default: high)
  --no-color          Disable ANSI colour.
```

Exit codes: `0` clean (below threshold) · `1` findings at/above threshold · `2` scan error.

## Use it as a library

```js
import { runScan } from 'malinois-scan';
import { explain } from 'malinois-scan/explain';

const result = await runScan('https://my-app.example');
console.log(result.grade, result.score);

for (const f of result.findings) {
  const help = explain(f.rule_id, 'en'); // also: 'ko'
  console.log(f.severity, help?.title, '→', help?.fix);
}
```

## Boundaries — on purpose

This is a defensive tool and it is built to stay one.

- **Passive only.** Plain GET requests any visitor could make. No exploitation, no
  injection, no brute force, no load testing.
- **Ownership required.** `--i-own-this` is not decoration — this is for apps you control.
  It is not a tool for probing strangers.
- **Private ranges refused.** Loopback, private, link-local and cloud-metadata addresses
  (e.g. `169.254.169.254`) are rejected, so this can't be turned into an SSRF proxy.
- **Never prints a raw secret.** Findings show a masked form (`sk_live_…ab12`) and where it
  was found.
- **A clean grade is not a clean bill of health.** For a browser-rendered app whose backend
  stays invisible to a passive check, the result is marked *limited* and says so.

## A one-time check is not monitoring

This CLI answers "is it leaking right now?". It does not answer "did something break at
3am on Tuesday?".

[**Malinois**](https://malinois.app/?src=gh_readme) is the hosted side: it re-checks your app on a
schedule, keeps the history, and emails you the moment a *new* leak appears that wasn't
there before — including a plain-language report you can hand to someone non-technical.
Free passive check in the browser, no signup: <https://malinois.app/?src=gh_readme>

## FAQ

**Does it need access to my code or accounts?** No. It only reads what your deployment
serves publicly.

**Will it break anything?** No. It makes a bounded number of ordinary GET requests, the
same ones a browser makes when loading your page.

**Can I scan my staging URL?** Yes — anything you own. Prefer staging if you're unsure.

**Why is my SPA graded `A` with no findings?** If your app renders in the browser and never
exposes its backend to a passive request, there may be nothing observable from outside.
The output marks this as a *limited* scan rather than claiming you're safe.

## License

MIT — see [LICENSE](LICENSE).
