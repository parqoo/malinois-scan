# `.env`, `.git` and source maps served to the public

This page covers the `exposed_env`, `exposed_git`, and `exposed_sourcemap` findings.

Try this on your own deployment right now:

```bash
curl -s https://your-app.example/.env | head
curl -s https://your-app.example/.git/HEAD
```

If either returns content instead of a 404, anyone can read it.

## Exposed `.env`

`.env` is a local file. It is not supposed to be deployed at all, but it ends up public in a
few predictable ways: it got committed and the whole repo is the web root; a static host is
serving the project directory rather than a build output; a rewrite rule sends unmatched
paths to the file system.

The scanner also checks `.env.local` and `.env.production` for the same reason.

**Fix, in order:**

1. Stop serving it. Set the deploy root to your build output (`dist/`, `build/`, `.next/`),
   not the project root.
2. Add it to `.gitignore` — and if it was ever committed, remember that removing it in a new
   commit does **not** remove it from history.
3. **Rotate everything that was in it.** Assume every value was read. This is the step people
   skip, and it is the only one that actually closes the incident.

## Exposed `.git`

If `/.git/HEAD` responds, the repository is downloadable — including history. That means
source code, and every secret ever committed, even ones deleted later.

**Fix:** remove `.git` from what you deploy (build artefacts only), or block the path at the
host/CDN. Then rotate anything that ever appeared in the history, not just what is in the
current files.

## Source maps

Source maps (`//# sourceMappingURL=…`) let anyone reconstruct your original, unminified
source. This is a much smaller problem than the two above — it is not a credential leak, and
plenty of teams ship them deliberately for error reporting. The scanner reports it as **low**
for that reason.

Turn them off in production if you'd rather not publish your source:

```js
// vite.config.js
export default { build: { sourcemap: false } }
```

```js
// next.config.js
module.exports = { productionBrowserSourceMaps: false }
```

## Why this keeps happening on AI-built apps

The deploy step is usually invisible. You describe an app, the platform builds and hosts it,
and nobody ever decides what the web root should be. When you later export the project or
move it to your own hosting, the default is often "serve this folder" — and the folder has
your `.env` in it.

## Check it from the outside

Your local repo cannot tell you what your host is serving.

```bash
npx github:parqoo/malinois-scan https://your-app.example --i-own-this
```

The check is a plain GET, the same request a browser makes. Findings report that the path
responded — the file's contents are never stored or printed.

In CI, so a hosting change can't silently expose it again:

```yaml
- uses: parqoo/malinois-scan@v0
  with:
    url: https://your-app.example
    fail-on: high
```

Scheduled re-checks with alerts: <https://malinois.app/?src=gh_docs_files>

## Related

- [Which keys are safe in a bundle](./leaked-keys.md) — what to rotate after an exposure
- [Supabase RLS](./supabase-rls.md)
- [Firebase security rules](./firebase-rules.md)
