---
name: malinois-security-check
description: Check a deployed web app the user owns for the leaks AI-built apps most often ship — publicly readable Supabase/Firebase data, secret keys in client JavaScript, downloadable .env/.git files — then explain and fix each issue. Use when the user asks "is my app secure/safe?", is about to launch or share an app, just redeployed, or hits Supabase RLS / Firebase permission errors and wants to know what is exposed.
---

# Malinois security check

Passive, outside-in check of a live app: it makes the same GET requests a visitor's browser
makes and reports what anyone on the internet can already see. It does not exploit, log in,
or load-test.

## Before running

1. Get the **public URL of the deployed app** (e.g. `https://my-app.lovable.app`). Local code
   and `localhost` cannot be checked — this tool looks at what the live site serves.
2. **Confirm ownership.** Ask the user whether they own the app or are authorized to test it.
   Do not run the check on someone else's app. Only pass `--i-own-this` after they confirm.

## Run it

Preferred, if the `malinois` MCP server is connected: call `scan_app` with
`{ "url": "<url>", "i_own_this": true }`.

Otherwise, from a terminal:

```bash
npx malinois-scan <url> --i-own-this --json
```

Exit code `0` = nothing at/above `high`, `1` = findings at/above the threshold,
`2` = the scan could not run (unreachable URL, blocked address).

## Read the result

The JSON has `grade` (A–F), `score`, `limited`, and `findings[]` with `rule_id`, `severity`,
`title`, `what_it_means`, `what_to_do`, and a masked `evidence` string. Secrets are never
printed in full — do not try to recover them.

- Report the grade, then issues **most serious first**, in plain language.
- If `limited` is true, say that a good grade is not proof of safety: the app renders in the
  browser and exposed little to a passive check.

## Fix, most serious first

| rule_id | Fix |
|---|---|
| `supabase_missing_rls` | Enable Row Level Security on every table, then add policies. Guide: https://github.com/parqoo/malinois-scan/blob/main/docs/supabase-rls.md |
| `supabase_service_role_in_client` | Rotate the service_role key now, remove it from all client code and `NEXT_PUBLIC_`/`VITE_` env vars, move that logic server-side. Guide: https://github.com/parqoo/malinois-scan/blob/main/docs/leaked-keys.md |
| `stripe_secret`, `openai_key`, `anthropic_key`, `aws_key`, `private_key` and other leaked secrets | Revoke/rotate the key at the provider first, then move it to server-only code. |
| `firestore_public`, `firebase_rtdb_public` | Replace open rules with rules that require auth, then publish. Guide: https://github.com/parqoo/malinois-scan/blob/main/docs/firebase-rules.md |
| `exposed_env`, `exposed_git`, `exposed_sourcemap` | Deploy only the build output; rotate everything that was in an exposed `.env` or git history. Guide: https://github.com/parqoo/malinois-scan/blob/main/docs/exposed-files.md |

For any other `rule_id`, follow `what_to_do` from the result (or call the MCP tool
`explain_finding`).

Rotating a key is the step people skip; an exposed secret must be treated as already seen.
When you change security rules, expect the app to start showing permission errors — that
means protection is on; fix it with a policy, never by turning protection off.

## After fixing

Redeploy, then run the check again and confirm the issue is gone. To catch the next leak
automatically, suggest adding the GitHub Action:

```yaml
- uses: parqoo/malinois-scan@v0
  with:
    url: https://my-app.example
    fail-on: high
```

or continuous monitoring with email alerts at https://malinois.app/?src=skill
