# Supabase: "new row violates row-level security policy" — and the more dangerous opposite

This page covers the `supabase_missing_rls` finding, and the RLS errors people hit while
fixing it.

There are two RLS states. Only one of them shows you an error.

| State | What you see | What it means |
|---|---|---|
| RLS on, no matching policy | `new row violates row-level security policy` | Your app is **locked**. Annoying, but safe. |
| RLS off | Nothing. It just works. | Your table is **readable by anyone on the internet.** |

The second one is the reason this tool exists. It never throws an error, so the person who
shipped it has no idea — until someone else finds it.

---

## "new row violates row-level security policy for table X"

RLS is on and no policy grants this operation to the current role. The fix is a policy, not
turning RLS off.

For a table where each row belongs to a user, you need a policy per operation:

```sql
-- who can read their own rows
create policy "read own rows"
on public.your_table
for select
to authenticated
using ( auth.uid() = user_id );

-- who can create rows (this is the one that fixes the insert error)
create policy "insert own rows"
on public.your_table
for insert
to authenticated
with check ( auth.uid() = user_id );
```

Two things people get wrong here:

- **`using` vs `with check`.** `using` filters rows that already exist (select/update/delete).
  `with check` validates rows being written (insert/update). An insert error needs
  `with check`.
- **`user_id` must actually be set.** If your client inserts without `user_id`, `auth.uid() =
  user_id` is false and the insert is rejected. Set it in the insert, or give the column a
  default of `auth.uid()`.

Verify as a real user, not in the SQL editor — the SQL editor runs as a privileged role and
will happily succeed while your app still fails.

## "permission denied for table X"

Usually not RLS. The role lacks table privileges entirely, or you are querying a table in a
schema that is not exposed through the API. Check that the table is in an exposed schema
(`public` by default) and that `anon` / `authenticated` have the grants your queries need.

## The dangerous case: RLS off

If RLS was never enabled, anyone with your project URL and anon key — both of which ship in
your JavaScript bundle, by design — can read the table directly:

```
GET https://<project>.supabase.co/rest/v1/your_table?select=*
apikey: <anon key>
```

No login. No error. Just your rows.

**Fix:** enable RLS on every table that holds anything non-public, then add policies.

```sql
alter table public.your_table enable row level security;
```

In the dashboard: Table Editor → your table → **Enable RLS**. Do this for every table,
including ones you think are empty or internal.

After enabling it, expect the first error in this document. That error is progress.

## Is the anon key supposed to be public?

Yes. The anon key is meant to ship to browsers. It identifies your project; it is not a
secret. RLS is what protects your data — the key is not.

What must **never** reach the browser is the `service_role` key. It bypasses RLS entirely.
If it is in your client bundle, rotate it immediately (Settings → API → regenerate) and
remove it from front-end code. That is the `supabase_service_role_in_client` finding, and it
is the single worst thing this scanner can find.

## Check the rest of your app

Fixing one table does not tell you about the other eleven. This tool checks a deployed app
from the outside — the same view an attacker has — for tables readable without auth, keys in
bundles, and exposed files:

```bash
npx github:parqoo/malinois-scan https://your-app.example --i-own-this
```

It only reads what any visitor could already see, and `--i-own-this` is required.

Run it in CI so a later deploy can't quietly turn RLS off again:

```yaml
- uses: parqoo/malinois-scan@v0
  with:
    url: https://your-app.example
    fail-on: high
```

For scheduled re-checks with history and an email the moment a *new* leak appears, there is
a hosted version: <https://malinois.app/?src=gh_docs_rls>

## Related

- [Secrets in a client bundle](./leaked-keys.md) — what is safe to ship and what is not
- [Exposed `.env` and `.git`](./exposed-files.md)
- [Firebase: open security rules](./firebase-rules.md)
