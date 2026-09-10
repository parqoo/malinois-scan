// scanner.js — passive, non-intrusive external security check for AI-built web apps.
//
// BOUNDARIES (do not relax):
//  - Passive only: plain GET requests a normal browser could make + endpoints that
//    are already publicly reachable without auth. No auth bypass, no injection, no
//    load/DoS, no brute force. We never store a raw secret — only a masked form.
//  - Bounded: capped request count + per-request timeout, the app's own origin/backend
//    only. Probes read data that is ALREADY public with the app's own anon key; we
//    record the class of exposure, never the returned rows.
//
// The grade is DETERMINISTIC (rule weights below). An LLM may later rephrase the
// human-readable text, but never the grade.

const REQ_TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 5;       // hops we follow for the main page before giving up
const MAX_JS_BUNDLES = 6;      // initial <script src> bundles from the HTML
const MAX_EXTRA_CHUNKS = 4;    // second wave: code-split chunks referenced by those bundles (SPA recall)
const MAX_TABLE_PROBES = 12;   // Supabase tables probed for missing RLS (common + app's own names)
const MAX_FIRESTORE_PROBES = 6;
const MAX_RTDB_PROBES = 2;
const UA = 'Malinois-Scanner/1.0 (+https://malinois.app/scanner)';

// ---- severity weights (score starts at 100, subtract) ----
const WEIGHTS = { critical: 45, high: 25, medium: 12, low: 5, info: 0 };

// ---- secret patterns (matched against HTML + JS bundles) ----
// NOTE: Google/Firebase "AIza..." web keys are deliberately NOT here — they are public
// by design in client apps. They are handled separately (see scanGoogleKey) so we don't
// cry wolf on every Firebase app, which would destroy the tool's credibility.
const SECRET_PATTERNS = [
  { id: 'stripe_secret', re: /sk_live_[0-9a-zA-Z]{20,}/g, severity: 'critical', category: 'leaked_secret', label: 'Stripe secret key' },
  { id: 'openai_key', re: /sk-(?:proj-)?[A-Za-z0-9]{20,}/g, severity: 'critical', category: 'leaked_secret', label: 'OpenAI API key' },
  { id: 'anthropic_key', re: /sk-ant-[A-Za-z0-9\-_]{20,}/g, severity: 'critical', category: 'leaked_secret', label: 'Anthropic API key' },
  { id: 'aws_key', re: /AKIA[0-9A-Z]{16}/g, severity: 'critical', category: 'leaked_secret', label: 'AWS access key' },
  { id: 'private_key', re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, severity: 'critical', category: 'leaked_secret', label: 'Private key' },
  // Added for the AI-stack-key coverage expansion (2026-07-25): these fixed, well-documented
  // prefixes were chosen for low false-positive risk. Formats we weren't confident enough
  // about to pattern-match reliably (Cohere, Mistral, Pinecone, LangSmith) were left out
  // rather than guessed — a wrong regex either misses silently or cries wolf, and precision
  // is the thing the eval gate exists to protect.
  { id: 'github_token', re: /gh[pousr]_[A-Za-z0-9]{36,}/g, severity: 'critical', category: 'leaked_secret', label: 'GitHub access token' },
  { id: 'slack_token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/g, severity: 'critical', category: 'leaked_secret', label: 'Slack token' },
  { id: 'huggingface_token', re: /hf_[A-Za-z0-9]{34,}/g, severity: 'critical', category: 'leaked_secret', label: 'Hugging Face access token' },
  { id: 'groq_key', re: /gsk_[A-Za-z0-9]{20,}/g, severity: 'critical', category: 'leaked_secret', label: 'Groq API key' },
  { id: 'replicate_token', re: /r8_[A-Za-z0-9]{20,}/g, severity: 'critical', category: 'leaked_secret', label: 'Replicate API token' },
];

// Every rule id this scanner can emit. Exported so a report can honestly state how many
// distinct checks were run instead of inventing a number. Keep in sync when adding a rule —
// the eval gate only scores secret patterns, so nothing else would catch drift here.
export const SCAN_RULE_IDS = [
  ...SECRET_PATTERNS.map((p) => p.id),
  'google_api_key_client',
  'hdr_csp', 'hdr_hsts', 'hdr_xfo', 'hdr_xcto', 'hdr_referrer_policy', 'hdr_permissions_policy',
  'cors_wildcard', 'csp_weak', 'hsts_short', 'cookie_insecure', 'info_stack_disclosure',
  'no_https_redirect', 'mixed_content', 'insecure_form_action',
  'exposed_env', 'exposed_git', 'exposed_backup', 'exposed_sourcemap',
  'supabase_missing_rls', 'supabase_service_role_in_client', 'firebase_rtdb_public', 'firestore_public',
];

const AIZA_RE = /AIza[0-9A-Za-z\-_]{35}/;
const SUPABASE_URL_RE = /https:\/\/([a-z0-9]{15,30})\.supabase\.co/g;
const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

// Supabase table names referenced by the app's own code (supabase-js `.from('x')` or
// a literal `/rest/v1/x`). Probing these — not guessed names — is what lifts recall.
const SUPABASE_FROM_RE = /\.from\(\s*["'`]([a-zA-Z_][a-zA-Z0-9_]{0,60})["'`]/g;
const SUPABASE_REST_RE = /\/rest\/v1\/([a-zA-Z_][a-zA-Z0-9_]{0,60})/g;
const FIRESTORE_COLL_RE = /\.collection\(\s*["'`]([a-zA-Z0-9_\/-]{1,60})["'`]/g;
const FIRESTORE_COLL2_RE = /\bcollection\(\s*[A-Za-z0-9_$.]+\s*,\s*["'`]([a-zA-Z0-9_\/-]{1,60})["'`]/g;
const FIREBASE_RTDB_RE = /https:\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)?\.(?:firebaseio\.com|firebasedatabase\.app))/gi;
const FIREBASE_PRESENT_RE = /firebaseio\.com|firebasedatabase\.app|firebaseConfig|firestore\.googleapis\.com|["']?apiKey["']?\s*:\s*["']AIza/i;
const CHUNK_JS_RE = /["'(]([^"'()\s]+?\.js)["')]/g;

// Common table names probed for missing RLS even when the app hides its own names.
const COMMON_TABLES = ['users', 'profiles', 'customers', 'orders', 'payments', 'messages', 'todos', 'posts'];

// ---------------- helpers ----------------

// SSRF guard: refuse to fetch anything that isn't a public web host. A passive
// scanner that takes an arbitrary user-supplied URL is otherwise an open proxy /
// internal port-scanner (metadata endpoints, loopback, private ranges). We only
// ever want to reach real, public, HTTP(S) origins.
export function isBlockedHost(host) {
  if (!host) return true;
  let h = String(host).toLowerCase().trim();
  // strip an IPv6 bracket/zone or a trailing dot
  h = h.replace(/^\[|\]$/g, '').replace(/%.*$/, '').replace(/\.$/, '');

  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.lan')) return true;

  // IPv4 literal (incl. metadata, private, loopback, link-local, this-host, CGNAT)
  const m4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m4) {
    const o = m4.slice(1).map(Number);
    if (o.some((n) => n > 255)) return true;              // malformed → refuse
    const [a, b] = o;
    if (a === 0 || a === 127 || a === 10) return true;    // this-host, loopback, private
    if (a === 169 && b === 254) return true;              // link-local + cloud metadata (169.254.169.254)
    if (a === 172 && b >= 16 && b <= 31) return true;     // private
    if (a === 192 && b === 168) return true;              // private
    if (a === 100 && b >= 64 && b <= 127) return true;    // CGNAT (100.64/10)
    if (a >= 224) return true;                            // multicast/reserved
    return false;
  }

  // IPv6 literal — block loopback, unspecified, unique-local (fc00::/7), link-local (fe80::/10),
  // and IPv4-mapped (::ffff:a.b.c.d) which could smuggle a private v4.
  if (h.includes(':')) {
    if (h === '::1' || h === '::') return true;
    if (/^f[cd][0-9a-f]{2}:/.test(h)) return true;        // fc00::/7
    if (/^fe[89ab][0-9a-f]:/.test(h)) return true;        // fe80::/10
    if (h.startsWith('::ffff:')) return true;             // IPv4-mapped — refuse rather than parse
    return false;
  }

  return false; // a normal public hostname
}

export function normalizeUrl(input) {
  let u = String(input || '').trim();
  // Opaque non-http schemes (no "//") — reject before the https:// coercion below can
  // paper over them (e.g. "file:/etc/passwd" must not become a valid https URL).
  if (/^(javascript|data|file|ftp|blob|vbscript|about|mailto|tel|ws|wss|gopher):/i.test(u)) {
    throw new Error('unsupported_protocol');
  }
  // Authority-based scheme ("scheme://…") — must be http(s).
  const am = u.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  if (am) {
    const s = am[1].toLowerCase();
    if (s !== 'http' && s !== 'https') throw new Error('unsupported_protocol');
  } else if (!/^https?:\/\//i.test(u)) {
    u = 'https://' + u; // schemeless (incl. host:port) → assume https
  }
  const url = new URL(u);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('unsupported_protocol');
  }
  url.hash = '';
  return url;
}

export async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function mask(secret) {
  const s = String(secret);
  if (s.length <= 8) return s.slice(0, 2) + '…';
  return s.slice(0, 6) + '…' + s.slice(-4);
}

function detectPlatform(host, html) {
  const h = host.toLowerCase();
  if (h.includes('lovable')) return 'lovable';
  if (h.includes('replit') || h.includes('repl.co')) return 'replit';
  if (h.includes('base44')) return 'base44';
  if (h.includes('bolt')) return 'bolt';
  if (h.includes('firebaseapp.com') || h.endsWith('.web.app')) return 'firebase';
  if (h.includes('vercel.app') && /__NEXT_DATA__/.test(html)) return 'v0';
  if (/supabase/i.test(html)) return 'supabase-backed';
  return 'other';
}

function decodeJwtRole(jwt) {
  try {
    const payload = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const json = atob(payload);
    const obj = JSON.parse(json);
    return obj.role || null;
  } catch {
    return null;
  }
}

async function timedFetch(url, init) {
  try {
    const res = await fetch(url, {
      ...init,
      headers: { 'user-agent': UA, ...(init?.headers || {}) },
      redirect: 'manual',
      signal: AbortSignal.timeout(REQ_TIMEOUT_MS),
    });
    return res;
  } catch {
    return null;
  }
}

// Fetch the main page, following redirects to the FINAL destination so security-header
// checks read the real page — not a redirect hop. A redirect (apex↔www, http→https,
// trailing-slash, locale) returns a sparse header set, so inspecting the hop instead of
// the destination reports headers as "missing" that the real page actually sends. That
// was a live false positive (a "no HSTS" verdict against a site that had it, and the same
// host grading differently as apex vs www). We follow manually rather than redirect:'follow'
// so every hop is re-validated through the SSRF guard — a public URL must not be able to
// bounce us to an internal/metadata host. Returns { res, finalUrl }.
async function fetchMainPage(startUrl, init) {
  let current = startUrl;
  let res = null;
  for (let hop = 0; hop < MAX_REDIRECTS; hop++) {
    res = await timedFetch(current.href, init);
    if (!res) return { res: null, finalUrl: current };
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (!loc) break; // redirect without a target — treat this as the final response
      let next;
      try {
        next = normalizeUrl(new URL(loc, current.href).href);
      } catch {
        break; // opaque/unsupported redirect target — stop, don't chase it
      }
      if (isBlockedHost(next.hostname)) break; // SSRF: never follow into a blocked host
      res.body?.cancel().catch(() => {}); // release the redirect body before the next hop
      current = next;
      continue;
    }
    break; // non-redirect status — this is the final page
  }
  return { res, finalUrl: current };
}

// Anonymized class fingerprint that feeds the shared knowledge base (section B).
// Generalizes identifiers so no tenant-specific value survives.
export async function signatureHash(category, platform, patternToken) {
  const token = COMMON_TABLES.includes(patternToken) ? patternToken : 'custom';
  return (await sha256Hex(`${category}|${platform}|${token}`)).slice(0, 32);
}

// ---- pure extractors (exported for tests) ----

// Table/collection names the app itself references, sanitized. Recall booster.
export function extractTableNames(text) {
  const names = new Set();
  let m;
  SUPABASE_FROM_RE.lastIndex = 0;
  while ((m = SUPABASE_FROM_RE.exec(text))) names.add(m[1]);
  SUPABASE_REST_RE.lastIndex = 0;
  while ((m = SUPABASE_REST_RE.exec(text))) names.add(m[1]);
  names.delete('rpc'); // supabase RPC endpoint, not a table
  return names;
}

export function extractFirestoreCollections(text) {
  const names = new Set();
  let m;
  FIRESTORE_COLL_RE.lastIndex = 0;
  while ((m = FIRESTORE_COLL_RE.exec(text))) names.add(m[1].split('/')[0]);
  FIRESTORE_COLL2_RE.lastIndex = 0;
  while ((m = FIRESTORE_COLL2_RE.exec(text))) names.add(m[1].split('/')[0]);
  return names;
}

export function detectFirebaseConfig(text) {
  const present = FIREBASE_PRESENT_RE.test(text);
  const rtdb = new Set();
  let m;
  FIREBASE_RTDB_RE.lastIndex = 0;
  while ((m = FIREBASE_RTDB_RE.exec(text))) rtdb.add('https://' + m[1]);
  const pm = text.match(/projectId["'\s:]+["']([a-z0-9-]{4,40})["']/i);
  return { present, rtdb, projectId: pm ? pm[1] : null };
}

// ---------------- individual checks ----------------

function checkSecurityHeaders(headers) {
  const findings = [];
  const has = (k) => headers.has(k);
  if (!has('content-security-policy')) findings.push({ rule_id: 'hdr_csp', category: 'missing_header', severity: 'low', label: 'Missing Content-Security-Policy header' });
  if (!has('strict-transport-security')) findings.push({ rule_id: 'hdr_hsts', category: 'missing_header', severity: 'low', label: 'Missing HSTS header' });
  if (!has('x-frame-options') && !has('content-security-policy')) findings.push({ rule_id: 'hdr_xfo', category: 'missing_header', severity: 'low', label: 'Missing clickjacking protection (X-Frame-Options)' });
  if (!has('x-content-type-options')) findings.push({ rule_id: 'hdr_xcto', category: 'missing_header', severity: 'info', label: 'Missing X-Content-Type-Options: nosniff' });
  if (!has('referrer-policy')) findings.push({ rule_id: 'hdr_referrer_policy', category: 'missing_header', severity: 'low', label: 'Missing Referrer-Policy header' });
  if (!has('permissions-policy')) findings.push({ rule_id: 'hdr_permissions_policy', category: 'missing_header', severity: 'low', label: 'Missing Permissions-Policy header' });
  const acao = headers.get('access-control-allow-origin');
  if (acao === '*') findings.push({ rule_id: 'cors_wildcard', category: 'permissive_cors', severity: 'medium', label: 'Wildcard CORS (Access-Control-Allow-Origin: *)' });

  // A CSP that allows inline/eval script gives back most of what CSP exists to prevent.
  // Only checked when a CSP is actually present (otherwise hdr_csp already covers it).
  const csp = headers.get('content-security-policy') || '';
  if (csp) {
    const weak = [];
    if (/'unsafe-inline'/i.test(csp)) weak.push("'unsafe-inline'");
    if (/'unsafe-eval'/i.test(csp)) weak.push("'unsafe-eval'");
    if (/(?:^|;)\s*(?:default|script)-src[^;]*\s\*(?:\s|;|$)/i.test(csp)) weak.push('*');
    if (weak.length) {
      findings.push({
        rule_id: 'csp_weak', category: 'weak_policy', severity: 'low',
        label: 'Content-Security-Policy present but permissive',
        evidence_redacted: `allows ${weak.join(', ')}`,
      });
    }
  }

  // HSTS with a very short max-age barely protects: the browser forgets quickly, leaving
  // the first visit after expiry downgradeable. Under ~6 months is the common threshold.
  const hsts = headers.get('strict-transport-security') || '';
  if (hsts) {
    const m = hsts.match(/max-age\s*=\s*(\d+)/i);
    const maxAge = m ? parseInt(m[1], 10) : 0;
    if (maxAge > 0 && maxAge < 15768000) {
      findings.push({
        rule_id: 'hsts_short', category: 'weak_policy', severity: 'low',
        label: 'HSTS max-age is short', evidence_redacted: `max-age=${maxAge}`,
      });
    }
  }

  // Cookie flags. Only reported for cookies the site sets on a plain public page visit.
  let cookies = [];
  try {
    cookies = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [];
  } catch { cookies = []; }
  if (!cookies.length) {
    const raw = headers.get('set-cookie');
    if (raw) cookies = [raw];
  }
  const badCookies = [];
  for (const c of cookies) {
    const name = (c.split('=')[0] || '').trim().slice(0, 40);
    const missing = [];
    if (!/;\s*secure/i.test(c)) missing.push('Secure');
    if (!/;\s*httponly/i.test(c)) missing.push('HttpOnly');
    if (!/;\s*samesite/i.test(c)) missing.push('SameSite');
    if (missing.length) badCookies.push(`${name} (${missing.join(', ')})`);
  }
  if (badCookies.length) {
    findings.push({
      rule_id: 'cookie_insecure', category: 'weak_policy', severity: 'medium',
      label: 'Cookies set without protective flags',
      evidence_redacted: badCookies.slice(0, 3).join(' · ').slice(0, 160),
    });
  }
  // Stack disclosure. Deliberately `info` (zero score weight): naming your host/framework is
  // not a hole, and many platforms won't let a non-developer remove these headers at all.
  // Reporting it as a scored "threat" would be crying wolf — we surface it as a note only.
  const stack = [];
  const srv = headers.get('server');
  const xpb = headers.get('x-powered-by');
  if (srv) stack.push(`Server: ${srv}`);
  if (xpb) stack.push(`X-Powered-By: ${xpb}`);
  if (stack.length) {
    findings.push({
      rule_id: 'info_stack_disclosure', category: 'info_disclosure', severity: 'info',
      label: 'Server technology named in response headers',
      evidence_redacted: stack.join(' · ').slice(0, 120),
    });
  }
  // NOTE: X-XSS-Protection is intentionally NOT checked. The header is deprecated, Chrome
  // removed the XSS Auditor it controlled, and `1; mode=block` can itself introduce a
  // side-channel — modern guidance is CSP instead. Flagging it would be outdated advice.
  return findings;
}

// Plaintext-HTTP check, done properly: we probe http:// ourselves and only report when the
// site actually SERVES over plaintext. A site that 30x-redirects http→https is behaving
// correctly and must not be flagged — inferring "no HTTPS" from an http:// input, without
// following the redirect, is a false positive we've seen real scanners ship.
async function checkHttpsTransport(finalUrl) {
  const httpUrl = new URL(finalUrl.href);
  httpUrl.protocol = 'http:';
  httpUrl.port = '';
  const { res, finalUrl: httpFinal } = await fetchMainPage(httpUrl, { method: 'GET' });
  if (!res) return null;                       // plaintext port not answering at all — fine
  res.body?.cancel().catch(() => {});
  if (httpFinal.protocol === 'https:') return null; // redirected to HTTPS — correct behavior
  if (res.status >= 200 && res.status < 300) {
    return {
      rule_id: 'no_https_redirect', category: 'insecure_transport', severity: 'high',
      label: 'Site is served over plain HTTP without redirecting to HTTPS',
    };
  }
  return null;
}

function scanTextForSecrets(text, sourceLabel, extra) {
  const findings = [];
  // `extra` = candidate ruleset patterns [{id, re, severity, category, label}], evaluated
  // by the self-improvement gate alongside the built-in patterns. Empty in production.
  const patterns = extra && extra.length ? SECRET_PATTERNS.concat(extra) : SECRET_PATTERNS;
  for (const p of patterns) {
    if (!(p.re instanceof RegExp)) continue;
    p.re.lastIndex = 0;
    const m = p.re.exec(text);
    if (m) {
      findings.push({
        rule_id: p.id,
        category: p.category,
        severity: p.severity,
        label: `${p.label} exposed in ${sourceLabel}`,
        evidence_redacted: `${mask(m[0])} in ${sourceLabel}`,
      });
    }
  }
  return findings;
}

// Network-free detection over provided content — the offline subset of runScan
// (secrets, service_role, Google key, mixed content, source maps). Used by the
// self-improvement eval gate to score a ruleset against fixtures WITHOUT fetching.
// `opts.extraSecretPatterns` lets a candidate ruleset be scored on the same engine.
export function detectOffline(content, opts = {}) {
  const findings = [];
  const headers = content.headers instanceof Headers ? content.headers : new Headers(content.headers || {});
  findings.push(...checkSecurityHeaders(headers));

  const sources = [['page HTML', content.html || ''], ...((content.bundles || []).map((b) => ['JavaScript bundle', b || '']))];
  let firebasePresent = false, aiza = null, sourcemap = false;
  for (const [label, text] of sources) {
    findings.push(...scanTextForSecrets(text, label, opts.extraSecretPatterns));
    findings.push(...scanForSupabase(text, label).findings); // service_role in client
    if (detectFirebaseConfig(text).present) firebasePresent = true;
    if (!aiza) { const m = text.match(AIZA_RE); if (m) aiza = { masked: mask(m[0]), label }; }
    if (/\/\/#\s*sourceMappingURL=.+\.map/.test(text)) sourcemap = true;
  }
  if (sourcemap) findings.push({ rule_id: 'exposed_sourcemap', category: 'exposed_file', severity: 'low' });
  if (/["'(]http:\/\/(?!localhost)/.test(content.html || '')) findings.push({ rule_id: 'mixed_content', category: 'mixed_content', severity: 'low' });
  const gk = scanGoogleKey(aiza, firebasePresent);
  if (gk) findings.push(gk);

  const seen = new Set();
  return findings.filter((f) => (seen.has(f.rule_id) ? false : (seen.add(f.rule_id), true)));
}

// A bare Google "AIza" key in client code is only a real problem if it is a Maps/Cloud
// key left unrestricted (quota/billing theft). When Firebase config is present the same
// key is the public web key and is expected — so we stay silent to avoid a false alarm.
function scanGoogleKey(aiza, firebasePresent) {
  if (!aiza || firebasePresent) return null;
  return {
    rule_id: 'google_api_key_client',
    category: 'exposed_key',
    severity: 'low',
    label: 'Google API key in client code — confirm it is application-restricted',
    evidence_redacted: `${aiza.masked} in ${aiza.label}`,
  };
}

function scanForSupabase(text, sourceLabel) {
  const findings = [];
  const urls = new Set();
  SUPABASE_URL_RE.lastIndex = 0;
  let m;
  while ((m = SUPABASE_URL_RE.exec(text))) urls.add(m[0]);

  JWT_RE.lastIndex = 0;
  const jwts = text.match(JWT_RE) || [];
  for (const jwt of jwts) {
    const role = decodeJwtRole(jwt);
    if (role === 'service_role') {
      findings.push({
        rule_id: 'supabase_service_role_in_client',
        category: 'leaked_secret',
        severity: 'critical',
        label: `Supabase service_role key exposed in ${sourceLabel} (full database access)`,
        evidence_redacted: `service_role JWT ${mask(jwt)} in ${sourceLabel}`,
      });
    }
  }
  return { findings, supabaseUrls: [...urls], anonKey: (jwts.find((j) => decodeJwtRole(j) === 'anon')) || null };
}

// Probe tables for missing RLS using the app's OWN anon key. Reads only what is already
// publicly reachable with that key; records the class of exposure, never the rows.
async function probeSupabaseRls(supabaseUrl, anonKey, tables) {
  const findings = [];
  if (!supabaseUrl || !anonKey) return findings;
  let used = 0;
  for (const table of tables) {
    if (used >= MAX_TABLE_PROBES) break;
    used++;
    const res = await timedFetch(`${supabaseUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, {
      headers: { apikey: anonKey, authorization: `Bearer ${anonKey}` },
    });
    if (res && res.status === 200) {
      let hasRows = false;
      try {
        const body = await res.text();
        hasRows = body.trim().startsWith('[') && body.trim().length > 2; // "[]" => empty
      } catch { /* ignore */ }
      if (hasRows) {
        findings.push({
          rule_id: 'supabase_missing_rls',
          category: 'exposed_table',
          severity: 'critical',
          label: `Table "${table}" is readable by anyone (missing Row Level Security)`,
          evidence_redacted: `table:${table} readable with anon key`,
          patternToken: table,
        });
      }
    }
  }
  return findings;
}

// Firebase Realtime Database open-rules probe. `shallow=true` returns key names only
// (minimal data); locked rules answer 401 "Permission denied". App's own project.
async function probeFirebaseRtdb(dbUrl) {
  const res = await timedFetch(`${dbUrl}/.json?shallow=true`, { method: 'GET' });
  if (res && res.status === 200) {
    const body = (await res.text().catch(() => '')).trim();
    if (body && body !== 'null' && !/permission denied|"error"/i.test(body)) {
      return {
        rule_id: 'firebase_rtdb_public',
        category: 'exposed_database',
        severity: 'critical',
        label: 'Firebase Realtime Database is readable by anyone (open security rules)',
        evidence_redacted: 'RTDB /.json readable without auth',
        patternToken: 'firebase_rtdb',
      };
    }
  }
  return null;
}

// Firestore open-rules probe over the app's own collection names. Locked rules answer 403.
async function probeFirestore(projectId, collections) {
  const findings = [];
  if (!projectId) return findings;
  let used = 0;
  for (const coll of collections) {
    if (used >= MAX_FIRESTORE_PROBES) break;
    used++;
    const res = await timedFetch(
      `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/${encodeURIComponent(coll)}?pageSize=1`,
      { method: 'GET' }
    );
    if (res && res.status === 200) {
      const body = await res.text().catch(() => '');
      if (/"documents"\s*:/.test(body)) {
        findings.push({
          rule_id: 'firestore_public',
          category: 'exposed_database',
          severity: 'critical',
          label: `Firestore collection "${coll}" is readable by anyone (open security rules)`,
          evidence_redacted: `firestore:${coll} readable without auth`,
          patternToken: coll,
        });
      }
    }
  }
  return findings;
}

async function checkExposedFiles(origin) {
  const findings = [];
  const targets = [
    { path: '/.env', rule: 'exposed_env', sev: 'critical', label: 'Exposed .env file', kind: 'env' },
    { path: '/.env.local', rule: 'exposed_env', sev: 'critical', label: 'Exposed .env file', kind: 'env' },
    { path: '/.env.production', rule: 'exposed_env', sev: 'critical', label: 'Exposed .env file', kind: 'env' },
    { path: '/.git/config', rule: 'exposed_git', sev: 'high', label: 'Exposed .git repository', kind: 'git' },
    { path: '/.git/HEAD', rule: 'exposed_git', sev: 'high', label: 'Exposed .git repository', kind: 'git' },
    { path: '/backup.sql', rule: 'exposed_backup', sev: 'critical', label: 'Exposed database backup', kind: 'dump' },
    { path: '/dump.sql', rule: 'exposed_backup', sev: 'critical', label: 'Exposed database backup', kind: 'dump' },
    { path: '/database.sqlite', rule: 'exposed_backup', sev: 'critical', label: 'Exposed database backup', kind: 'dump' },
  ];
  const seen = new Set();
  for (const t of targets) {
    if (seen.has(t.rule)) continue;
    const res = await timedFetch(origin + t.path, { method: 'GET' });
    if (res && res.status === 200) {
      const body = await res.text().catch(() => '');
      // Guard against an SPA catch-all route answering 200 with index.html for everything —
      // without this every client-rendered app would look like it leaks all of these files.
      const looksReal = t.kind === 'env' ? /^\s*[A-Z0-9_]+\s*=/m.test(body) && !/<html/i.test(body)
        : t.kind === 'git' ? /ref:|\[core\]|[0-9a-f]{40}/i.test(body)
        : /(CREATE TABLE|INSERT INTO|SQLite format)/i.test(body);
      if (looksReal) {
        findings.push({ rule_id: t.rule, category: 'exposed_file', severity: t.sev, label: t.label, evidence_redacted: `${t.path} returned 200` });
        seen.add(t.rule);
      }
    }
  }
  return findings;
}

// Forms that submit over plaintext http:// hand whatever the visitor typed — including
// passwords — to anyone on the same network, even when the page itself loaded over HTTPS.
function checkInsecureForms(html) {
  const findings = [];
  const m = html.match(/<form[^>]+action\s*=\s*["']http:\/\/(?!localhost|127\.0\.0\.1)[^"']+["']/i);
  if (m) {
    findings.push({
      rule_id: 'insecure_form_action', category: 'insecure_transport', severity: 'medium',
      label: 'A form submits over plain HTTP',
      evidence_redacted: m[0].slice(0, 120),
    });
  }
  return findings;
}

function extractJsUrls(text, origin, already, limit) {
  const urls = new Set();
  CHUNK_JS_RE.lastIndex = 0;
  let m;
  while ((m = CHUNK_JS_RE.exec(text)) && urls.size < limit) {
    try {
      const abs = new URL(m[1], origin);
      if (abs.origin === origin && !already.has(abs.href)) urls.add(abs.href);
    } catch { /* ignore */ }
  }
  return [...urls];
}

function scoreToGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 45) return 'D';
  if (score >= 25) return 'E';
  return 'F';
}

// Pull every recall signal out of one text source (HTML or a JS file) into `acc`.
function ingest(findings, text, label, acc) {
  findings.push(...scanTextForSecrets(text, label));
  const sb = scanForSupabase(text, label);
  findings.push(...sb.findings);
  sb.supabaseUrls.forEach((u) => acc.supabaseUrls.add(u));
  if (!acc.anonKey) acc.anonKey = sb.anonKey;

  const fb = detectFirebaseConfig(text);
  if (fb.present) acc.firebasePresent = true;
  fb.rtdb.forEach((u) => acc.rtdb.add(u));
  if (!acc.projectId && fb.projectId) acc.projectId = fb.projectId;

  extractTableNames(text).forEach((n) => acc.tables.add(n));
  extractFirestoreCollections(text).forEach((n) => acc.collections.add(n));

  if (!acc.aiza) {
    const m = text.match(AIZA_RE);
    if (m) acc.aiza = { masked: mask(m[0]), label };
  }
  if (/\/\/#\s*sourceMappingURL=.+\.map/.test(text)) acc.sourcemap = true;
}

// ---------------- orchestration ----------------

export async function runScan(rawUrl, opts = {}) {
  let url;
  try {
    url = normalizeUrl(rawUrl);
  } catch {
    return { ok: false, error: 'invalid_url' };
  }
  const host = url.host;
  // SSRF guard — never fetch internal/private/metadata targets. The hostname is what
  // fetch() will use, so blocking it here closes the whole scan path (bundles/chunks/
  // probes are all same-origin-checked downstream).
  if (isBlockedHost(url.hostname)) {
    return { ok: false, error: 'blocked_target', host };
  }
  const started = Date.now();
  const findings = [];
  const checks = [];
  const acc = {
    supabaseUrls: new Set(), anonKey: null, firebasePresent: false, rtdb: new Set(),
    projectId: null, tables: new Set(), collections: new Set(), aiza: null, sourcemap: false,
  };

  // 1. main page (follow redirects → inspect the FINAL page, not a redirect hop)
  const { res: mainRes, finalUrl } = await fetchMainPage(url, { method: 'GET' });
  if (!mainRes) {
    return { ok: false, error: 'unreachable', host, url_hash: await sha256Hex(url.href) };
  }
  const html = await mainRes.text().catch(() => '');
  const finalIsHttps = finalUrl.protocol === 'https:';
  // Redirects between apex/www or a hosting preview and its canonical domain are common.
  // Resolve bundles and exposed-file checks against the page we actually received, not the
  // submitted origin, otherwise a redirect can make us silently skip the app's JavaScript.
  const origin = finalUrl.origin;
  // Only trust header findings when we actually received the final page (2xx). A non-2xx or
  // opaque response means we could not see the real headers, so asserting they are "missing"
  // would be a false positive — mark the scan limited instead of handing out a wrong verdict.
  const gotFinalPage = mainRes.status >= 200 && mainRes.status < 300;

  // 2. security headers + mixed content
  if (gotFinalPage) {
    const hdrFindings = checkSecurityHeaders(mainRes.headers);
    findings.push(...hdrFindings);
    checks.push({ name: 'security_headers', passed: hdrFindings.filter((f) => f.severity !== 'info').length === 0 });
  }
  if (finalIsHttps && /["'(]http:\/\/(?!localhost)/.test(html)) {
    findings.push({ rule_id: 'mixed_content', category: 'mixed_content', severity: 'low', label: 'Page loads insecure http:// resources' });
  }
  findings.push(...checkInsecureForms(html));
  // Plaintext transport: if the page itself resolved to http we already know it's exposed;
  // otherwise probe http:// separately to confirm it redirects rather than serving plaintext.
  const transportFinding = finalIsHttps
    ? await checkHttpsTransport(finalUrl)
    : { rule_id: 'no_https_redirect', category: 'insecure_transport', severity: 'high', label: 'Site is served over plain HTTP without redirecting to HTTPS' };
  if (transportFinding) findings.push(transportFinding);
  checks.push({ name: 'https_only', passed: finalIsHttps && !transportFinding });

  // 3. HTML + JS bundles + one wave of code-split chunks (SPA recall)
  ingest(findings, html, 'page HTML', acc);
  const scanned = new Set([url.href, finalUrl.href]);
  const bundleTexts = [];
  for (const b of extractJsUrls(html, origin, scanned, MAX_JS_BUNDLES).concat(
    // Vite/webpack initial modules are usually <script src>; also honor modulepreload
    [...html.matchAll(/<link[^>]+rel=["']modulepreload["'][^>]+href=["']([^"']+)["']/gi)]
      .map((mm) => { try { const a = new URL(mm[1], origin); return a.origin === origin ? a.href : null; } catch { return null; } })
      .filter(Boolean)
  )) {
    if (scanned.has(b) || scanned.size > MAX_JS_BUNDLES + 1) continue;
    scanned.add(b);
    const res = await timedFetch(b, { method: 'GET' });
    if (!res || res.status !== 200) continue;
    const js = await res.text().catch(() => '');
    bundleTexts.push(js);
    ingest(findings, js, 'JavaScript bundle', acc);
  }
  // second wave: chunks referenced by the initial bundles (lazy-loaded config lives here)
  const extra = [];
  for (const js of bundleTexts) {
    for (const u of extractJsUrls(js, origin, scanned, MAX_EXTRA_CHUNKS - extra.length)) {
      if (extra.length >= MAX_EXTRA_CHUNKS) break;
      extra.push(u); scanned.add(u);
    }
    if (extra.length >= MAX_EXTRA_CHUNKS) break;
  }
  for (const u of extra) {
    const res = await timedFetch(u, { method: 'GET' });
    if (!res || res.status !== 200) continue;
    const js = await res.text().catch(() => '');
    ingest(findings, js, 'JavaScript chunk', acc);
  }
  checks.push({ name: 'no_leaked_secrets', passed: !findings.some((f) => f.category === 'leaked_secret') });

  // 4. derived findings from accumulated signals
  if (acc.sourcemap) findings.push({ rule_id: 'exposed_sourcemap', category: 'exposed_file', severity: 'low', label: 'Source maps exposed (reveals original source)' });
  const gk = scanGoogleKey(acc.aiza, acc.firebasePresent);
  if (gk) findings.push(gk);

  // 5. Supabase RLS probe (app's own anon key; probes the app's own + common table names)
  const firstSb = [...acc.supabaseUrls][0];
  if (firstSb && acc.anonKey && opts.probeEndpoints !== false) {
    const tables = [...new Set([...acc.tables, ...COMMON_TABLES])];
    const rls = await probeSupabaseRls(firstSb, acc.anonKey, tables);
    findings.push(...rls);
    checks.push({ name: 'database_access_control', passed: rls.length === 0 });
  }

  // 6. Firebase probes (RTDB open rules + Firestore open rules on the app's own collections)
  if (acc.firebasePresent && opts.probeEndpoints !== false) {
    let rtdbHits = 0;
    for (const dbUrl of acc.rtdb) {
      if (rtdbHits >= MAX_RTDB_PROBES) break;
      rtdbHits++;
      const f = await probeFirebaseRtdb(dbUrl);
      if (f) findings.push(f);
    }
    const fsFindings = await probeFirestore(acc.projectId, [...acc.collections]);
    findings.push(...fsFindings);
    checks.push({ name: 'firebase_rules', passed: !findings.some((f) => f.category === 'exposed_database') });
  }

  // 7. exposed files
  const fileFindings = await checkExposedFiles(origin);
  findings.push(...fileFindings);
  checks.push({ name: 'no_exposed_files', passed: fileFindings.length === 0 });

  // 8. transparency: a client-rendered shell whose backend we could not observe from
  // fetch alone is a LIMITED scan — say so rather than hand out a falsely clean grade.
  const backendUnknown = acc.supabaseUrls.size === 0 && !acc.firebasePresent;
  const bodyText = html.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<[^>]+>/g, '').trim();
  const isShell = bodyText.length < 400 && /<div[^>]+id=["'](root|app|__next)["']/i.test(html) && /<script/i.test(html);
  // Limited when we can't fully see the app: either a client-rendered shell hiding its
  // backend, or we never reached a real final page (so the header checks above were skipped
  // rather than emitting false "missing" findings).
  const limited = (isShell && backendUnknown) || !gotFinalPage;
  if (limited) {
    findings.push({ rule_id: 'scan_limited_spa', category: 'scan_meta', severity: 'info', label: 'Limited scan: this app renders in the browser and hides its backend from a passive check. A deeper scan can see more.' });
  }

  const platform = (() => {
    const p = detectPlatform(host, html);
    if (p !== 'other') return p;
    if (acc.supabaseUrls.size) return 'supabase-backed';
    if (acc.firebasePresent) return 'firebase-backed';
    return 'other';
  })();

  // ---- dedupe + attach anonymized signatures ----
  const seen = new Set();
  const deduped = [];
  for (const f of findings) {
    const key = f.rule_id + '|' + (f.label || '');
    if (seen.has(key)) continue;
    seen.add(key);
    f.signature_hash = await signatureHash(f.category, platform, f.patternToken);
    delete f.patternToken;
    deduped.push(f);
  }

  // ---- deterministic score + grade ----
  let score = 100;
  for (const f of deduped) score -= (WEIGHTS[f.severity] || 0);
  score = Math.max(0, Math.min(100, score));
  const grade = scoreToGrade(score);

  return {
    ok: true,
    host,
    platform,
    url_hash: await sha256Hex(url.href),
    grade,
    score,
    findings: deduped,
    checks,
    limited,
    browser_ms: 0, // fetch-only path; browser step (SPA) added at scale
    duration_ms: Date.now() - started,
    rule_count: SCAN_RULE_IDS.length,
  };
}
