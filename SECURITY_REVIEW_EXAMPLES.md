# Security review: Peewee examples & Flask helpers

Scope: example apps under `examples/`, `playhouse/flask_utils.py`, `playhouse/fields.py` (PickleField), `playhouse/kv.py`, `playhouse/dataset.py`, `pwiz.py`.

Only **validated MEDIUM / HIGH / CRITICAL** findings with source→sink traces. Rejected candidates are listed at the end.

---

## Finding 1 — HIGH: Stored XSS in blog via ExtraExtension + `Markup()`

**Files:** `examples/blog/app.py:66-80`, `examples/blog/templates/detail.html:15`

**Source → sink**
1. Authenticated author POSTs `content` to `/create/` or `/<slug>/edit/` (`app.py:196-197`, `218-241`).
2. Content stored in `Entry.content`.
3. On view, `Entry.html_content` runs `markdown(..., extensions=[CodeHiliteExtension, ExtraExtension])` then `micawber.parse_html(...)`, then wraps the result in `Markup(...)` (`app.py:66-80`).
4. `detail.html` outputs `{{ entry.html_content }}` without escaping; `Markup` marks the string safe for Jinja.

**Missing controls**
- `markdown.extensions.extra.ExtraExtension` permits raw HTML (`<script>`, event handlers, etc.).
- No HTML sanitizer (e.g. bleach).
- `Markup()` disables autoescaping at the sink.

**Evidence (reproduced)**
Input `<script>alert(document.domain)</script><img src=x onerror=alert(1)>` survives markdown+micawber and renders as executable HTML under Jinja `autoescape=True`.

**Impact if deployed**
Any published entry becomes a stored XSS for all visitors. A logged-in admin viewing the post enables same-origin actions (create/edit) via the admin session (HttpOnly cookie blocks `document.cookie` theft, not XSS-driven state changes). Chains with CSRF (Finding 3).

**Remediation**
- Sanitize HTML after markdown (allowlist tags/attributes), or use a markdown mode that does not pass raw HTML.
- Do not wrap unsanitized HTML in `Markup()`.
- Optionally disable `ExtraExtension` / raw HTML if not required.

---

## Finding 2 — MEDIUM: Open redirect after blog login (`next`)

**Files:** `examples/blog/app.py:150`, `153-167`; `examples/blog/templates/login.html:8`

**Source → sink**
1. `login_required` redirects to `url_for('login', next=request.path)` (`app.py:150`).
2. Attacker can also open `/login/?next=https://evil.example/phish` directly.
3. `login()` sets `next_url = request.args.get('next') or request.form.get('next')` with **no** allowlist / relative-URL check (`app.py:155`).
4. On successful auth: `return redirect(next_url or url_for('index'))` (`app.py:164`).
5. Login form preserves `next` in the form action (`login.html:8`).

**Missing controls**
- No validation that `next` is a relative path / same-origin URL.

**Impact**
Phishing: victim is sent to `/login/?next=https://attacker`, enters the admin password, then is redirected to an attacker page that can mimic a post-login UI.

**Remediation**
Allow only relative paths (e.g. startswith `/` but not `//`), or compare against `url_for` targets.

---

## Finding 3 — MEDIUM: CSRF on blog state-changing routes

**Files:** `examples/blog/app.py:169-174`, `218-241`; templates `create.html`, `edit.html`, `logout.html`

**Source → sink**
- Session auth is a cookie (`session['logged_in']`, `session.permanent = True` at `app.py:161-162`).
- `SESSION_COOKIE_SAMESITE` is unset (cookie emitted without `SameSite`).
- POST `/create/`, POST `/<slug>/edit/`, POST `/logout/` have no CSRF token; forms contain none.

**Missing controls**
- No Flask-WTF / custom CSRF, no `SameSite=Strict/Lax` explicitly set on the session cookie.

**Impact**
Cross-site POST CSRF is partially mitigated on modern browsers by Lax-by-default for cookies lacking `SameSite`, but defense-in-depth is absent; same-site attackers and older clients remain exposed. CSRF → create published entry with Finding 1 payload = stored XSS for all readers.

**Remediation**
CSRF tokens on all state-changing routes; set `SESSION_COOKIE_SAMESITE='Lax'` (or `Strict`); prefer `SameSite` + token.

---

## Finding 4 — HIGH: Analytics `/a.js` reflects `id` into JavaScript

**Files:** `examples/analytics/app.py:39-42`, `116-123`

**Source → sink**
1. Docs instruct sites to embed `<script src=".../a.js?id=<account id>"></script>` (`app.py:17-20`).
2. `script()` reads `account_id = request.args.get('id')` (`app.py:118`).
3. Response body: `JAVASCRIPT % (DOMAIN, account_id)` with `mimetype='text/javascript'` (`app.py:120-122`).
4. Template ends with `})(%s)` — `id` is interpolated **unquoted** into JS.

**Missing controls**
- No allowlist that `id` is an integer / existing `Account.id`.
- No JSON-encoding / quoting of the inserted value.

**Exploit**
Request: `/a.js?id=1);alert(document.domain);//`  
Produces: `...(function...)(1);alert(document.domain);//)`

Any page that loads this script URL executes the attacker payload in **that page’s origin** (third-party script inclusion).

**Impact if deployed as instructed**
The beacon endpoint becomes a JS injection gadget for every embedding site. Attacker-controlled `id` in the script URL yields XSS on the embedding origin (session theft on sites without HttpOnly, DOM access, credentialed same-origin requests).

**Remediation**
- Validate `id` as a positive integer and that `Account.get_or_none(Account.id == id)` exists.
- Emit `})(%d)` / `json.dumps(account_id)` inside the script.
- Reject non-numeric `id` with 404.

---

## Finding 5 — MEDIUM: CSRF on Twitter example state-changing routes

**Files:** `examples/twitter/app.py:230-234`, `265-305`; templates `user_detail.html`, `create.html`

**Source → sink**
- Auth via cookie session (`auth_user` / `login_required`).
- POST `/users/<username>/follow/`, `/unfollow/`, `/create/` — no CSRF tokens.
- GET `/logout/` clears session with no confirmation/token (`app.py:230-234`).

**Missing controls**
- No CSRF tokens; session cookie has no explicit `SameSite` (see Finding 3).
- Logout is a side-effecting GET (exploitable via top-level navigation even under Lax).

**Impact**
Force follow/unfollow, post as the victim, or log the victim out.

**Remediation**
CSRF tokens; change logout to POST+token; set `SameSite` on the session cookie.

---

## Finding 6 — MEDIUM: `get_next_url()` open redirect helper

**Files:** `playhouse/flask_utils.py:80-85`

**Source → sink**
```python
def get_next_url(default='/'):
    if request.args.get('next'):
        return request.args['next']
    elif request.form.get('next'):
        return request.form['next']
    return default
```
Returns attacker-controlled `next` with no validation. Intended for post-login redirects (`redirect(get_next_url())`).

**Impact**
Any app using this helper for redirects inherits an open redirect (phishing), same class as Finding 2.

**Remediation**
Validate relative/same-origin URLs before returning; document the hazard.

---

## Finding 7 — HIGH: `PickleField` / default `KeyValue` unsafe deserialization

**Files:** `playhouse/fields.py:54-59`, `playhouse/kv.py:19-33`

**Source → sink**
1. `PickleField.python_value` calls `pickle.loads(value)` on DB bytes (`fields.py:55-59`).
2. `KeyValue` defaults `value_field` to `PickleField()` (`kv.py:33`).
3. Docs describe transparent pickling with **no security warning** (`docs/peewee/playhouse.rst` PickleField).

**Missing controls**
- No restricted unpickler; any blob in the column is deserialized.

**Impact**
If an attacker can write the value column (compromised DB, shared DB user, SQL injection elsewhere, malicious sync), the next read executes arbitrary Python (`__reduce__`) → RCE in the app process.

**Remediation**
- Prefer JSONField / TextField for untrusted or multi-tenant data.
- Document that `PickleField` must only store trusted data.
- For `KeyValue`, default to a non-pickle field or require explicit opt-in.

---

## Rejected candidates (and why)

| Candidate | Reason |
|-----------|--------|
| **FTS MATCH SQLi** (`Entry.search` / `FTSEntry.match(search)`) | Peewee emits `"ftsentry" MATCH ?` with the user string as a bound parameter. Not classic SQLi. FTS query-language quirks / errors only; `published == True` still applied. |
| **Micawber / oembed SSRF** | `bootstrap_basic()` only HTTP-fetches fixed provider oEmbed endpoints (YouTube, etc.), passing the content URL as a query param. Internal URLs like `http://169.254.169.254/` are linkified only — **no** server fetch. |
| **Hardcoded `SECRET_KEY` / `ADMIN_PASSWORD='secret'`** | Documented example/tutorial apps; blog comments note simplicity; analytics marks secrets with TODO. Treated as demo-only per review bar. |
| **Analytics header / Cookie storage** | `headers=dict(request.headers)` into HStore is intentional telemetry; `reports.py` reads cookies offline. No HTML sink → no XSS chain. |
| **Twitter `/private/` missing `@login_required`** | Unauthenticated access calls `get_current_user()` → `None.following()` → 500. No timeline disclosure. |
| **Reflected XSS in blog search title** | `{{ search }}` is Jinja-autoescaped. |
| **Twitter `message.content\|urlize` XSS** | Content goes through Jinja escaping before `urlize`. |
| **Flask `DEBUG=True` / debugger RCE** | `app.run()` defaults to localhost; analytics docs say use a real WSGI server for deployment. Not a remote default. |
| **diary / graph / hexastore / adjacency_list / reddit_ranking** | CLI / in-process demos; no remote HTTP attacker surface. |
| **pwiz.py / dataset.py** | Local CLI / library APIs; no untrusted web input path in scope. |
| **MD5 password hashing (twitter)** | Weak hashing is real if deployed, but treated as demo crypto hygiene rather than a complete auth-bypass chain for this pass. |
