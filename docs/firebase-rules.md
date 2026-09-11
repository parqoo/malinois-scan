# Firebase: "Missing or insufficient permissions" — and the silent opposite

This page covers the `firestore_public` and `firebase_rtdb_public` findings.

Like Supabase RLS, Firebase has two states and only one of them talks to you:

| State | What you see | What it means |
|---|---|---|
| Rules deny | `FirebaseError: Missing or insufficient permissions.` | Locked. Safe. |
| Rules allow everyone | Nothing. It works. | **Anyone can read your database.** |

## "Missing or insufficient permissions"

Your rules are rejecting the read or write. The fix is a rule that matches your data model —
not `allow read, write: if true`.

Firestore, per-user documents:

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{noteId} {
      allow read, update, delete: if request.auth != null
                                  && request.auth.uid == resource.data.userId;
      allow create: if request.auth != null
                    && request.auth.uid == request.resource.data.userId;
    }
  }
}
```

Two things people get wrong:

- **`resource` vs `request.resource`.** `resource` is the document as it exists now (read,
  update, delete). `request.resource` is the incoming document (create, update). A failing
  create almost always needs `request.resource`.
- **Rules do not filter.** A query that could return documents the rules deny fails entirely
  rather than returning a subset. Constrain the query to match the rule — e.g. a
  `where('userId', '==', uid)` that mirrors the condition.

Realtime Database:

```json
{
  "rules": {
    "notes": {
      "$uid": {
        ".read":  "auth != null && auth.uid == $uid",
        ".write": "auth != null && auth.uid == $uid"
      }
    }
  }
}
```

## The dangerous case: open rules

Test-mode rules are time-limited and say so, but plenty of projects get shipped with them —
or with `if true` pasted in to make an error go away:

```
allow read, write: if true;           // Firestore: world-readable and writable
".read": true                          // RTDB: same
```

With those, your project id is enough. It is in your bundle, by design. Anyone can then read
the database directly over the REST API — no account, no error, no log entry that looks
unusual.

**Fix:** Firebase Console → Firestore/Realtime Database → Rules → require `request.auth`
(Firestore) or `auth` (RTDB), then **Publish**. Rules are not live until you publish.

Expect the "Missing or insufficient permissions" error afterwards. That error is progress.

## The API key is not the problem

The `AIza…` key in your Firebase config is public by design — it identifies your project, it
does not authorise access. Security rules are the access control. Do not spend time hiding
the key; spend it on the rules.

## Check what is actually reachable from outside

Rules can look correct in the console and still leave a collection open — a nested `match`
that never applies, a rule published to the wrong database, a second RTDB instance nobody
remembers.

```bash
npx malinois-scan https://your-app.example --i-own-this
```

This reads your deployed page for a Firebase config and then checks whether the database
answers an unauthenticated request. It reads only what is already public, and only for an app
you confirm you own.

Continuous re-checks with an alert when a rule change opens something up:
<https://malinois.app/?src=gh_docs_firebase>

## Related

- [Which keys are safe in a bundle](./leaked-keys.md)
- [Supabase RLS](./supabase-rls.md) — the same shape of problem, different product
