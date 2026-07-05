# Authenticated Web Scan Design

## Goal

Add an authenticated web testing layer to Osmedeus workflows so scanners can reach private pages, APIs, and parameterized routes after login while preserving cookies and important headers such as `Authorization` and `X-Api-Key`.

The design uses a dedicated auth second pass. Public recon remains unchanged and authenticated scanning writes separate artifacts, so baseline public coverage can be compared against private authenticated coverage without leaking credentials into broad recon.

## Decisions

- Support manual session input, form login, API login, and browser login.
- Store auth artifacts in plaintext under the workspace.
- Require an explicit authenticated scope allowlist.
- Keep unauthenticated baseline scans.
- Apply auth only to selected web phases: spidering, content discovery, nuclei, sqlmap, and Dalfox.
- Do not modify the baseline modules initially; use dedicated `auth-*` modules for isolation.
- Provide an authenticated-only execution path for cases where public recon was already completed.

## Session Artifacts

All auth artifacts live under:

```text
{{Output}}/auth/
```

Core files:

```text
auth/session-{{TargetSpace}}.json
auth/headers-{{TargetSpace}}.txt
auth/cookies-{{TargetSpace}}.txt
auth/scope-{{TargetSpace}}.txt
auth/session-report-{{TargetSpace}}.md
```

`session-*.json` is the source of truth:

```json
{
  "target": "example.com",
  "source": "manual|form-login|api-login|browser-login",
  "created_at": "2026-07-05T00:00:00Z",
  "headers": {
    "Authorization": "Bearer token",
    "X-Api-Key": "key",
    "Cookie": "sid=value"
  },
  "cookies": [
    {"name": "sid", "value": "value", "domain": ".example.com", "path": "/"}
  ],
  "scope": [
    "https://app.example.com",
    "https://api.example.com"
  ],
  "evidence": {
    "login_url": "https://app.example.com/login",
    "whoami_url": "https://app.example.com/me",
    "authenticated_status": 200
  }
}
```

`headers-*.txt` is generated for tools that accept repeated HTTP headers:

```text
Authorization: Bearer token
X-Api-Key: key
Cookie: sid=value
```

`scope-*.txt` is the explicit allowlist. Authenticated scanners only use roots from this file and URLs discovered from those roots.

## Modules

### `common/auth-session.yaml`

Creates the auth directory and normalizes manual, form-login, and API-login inputs into the shared session artifact format.

Inputs:

- `enableAuthScan`
- `authMode`: `manual`, `form`, `api`, or `browser`
- `authScope`, `authScopeFile`
- `authHeader`, `authHeaderFile`
- `authCookie`, `authCookieFile`
- `authLoginUrl`
- `authUsername`
- `authPassword`
- `authApiLoginMethod`
- `authApiLoginBody`
- `authTokenJsonPath`
- `authCheckUrl`
- `authCheckStatus`
- `authCheckRegex`

Outputs:

- `auth/session-*.json`
- `auth/headers-*.txt`
- `auth/cookies-*.txt`
- `auth/scope-*.txt`
- `auth/session-report-*.md`

Behavior:

- Skips unless `enableAuthScan=true`.
- When `authMode=browser`, delegates session creation to `auth-browser-login` and validates the files it produces.
- Fails closed if scope is empty.
- If `authCheckUrl` is set, verifies the session before downstream auth modules run.
- Writes plaintext auth files to workspace.
- Does not print raw secrets in normal logs or reports.

### `common/auth-browser-login.yaml`

Optional advanced module for JS-heavy login flows. It is disabled by default with `enableBrowserLogin=false`.

Behavior:

- Uses Playwright/headless browser.
- Navigates to `authLoginUrl`.
- Fills configured username/password selectors.
- Captures browser cookies.
- Optionally extracts localStorage/sessionStorage values by key regex.
- Optionally maps extracted values into headers, for example `Authorization=localStorage.access_token`.
- Writes the same `session-*.json`, `headers-*.txt`, `cookies-*.txt`, and `scope-*.txt` format used by `auth-session`.

### `common/auth-spider.yaml`

Authenticated crawl against `auth/scope-*.txt`.

Inputs:

- `authScopeFile`
- `authHeaderFile`
- `authHeaderArgs`

Outputs:

- `auth/links-{{TargetSpace}}.txt`
- `auth/parameterized-urls-{{TargetSpace}}.txt`
- `auth/spider-records-{{TargetSpace}}.jsonl`

Tools:

- `katana`
- Vigolium/Spitolas headless crawling is not part of the first implementation unless its installed version supports explicit header injection in this workflow environment.

### `common/auth-content.yaml`

Authenticated content discovery against the explicit auth scope.

Outputs:

- `auth/content-discovery-url-{{TargetSpace}}.txt`
- `auth/content-records-{{TargetSpace}}.jsonl`
- `auth/content-discovery-report-{{TargetSpace}}.md`

Tools:

- `ffuf`
- Vigolium discover mode is not part of the first implementation unless its installed version supports explicit header injection in this workflow environment.

### `common/auth-vuln.yaml`

Authenticated nuclei scan against `auth/scope-*.txt` and optionally authenticated discovered URLs.

Outputs:

- `vulnscan/auth/nuclei-jsonl-{{TargetSpace}}.txt`
- `vulnscan/auth/clean-jsonl-{{TargetSpace}}.txt`
- `vulnscan/auth/nuclei-overview-report-{{TargetSpace}}.md`

Behavior:

- Passes auth headers to nuclei.
- Imports authenticated findings separately but still into the vulnerability DB.

### `common/auth-injection.yaml`

Authenticated sqlmap and Dalfox scan from private parameterized URLs.

Inputs:

- `auth/parameterized-urls-*.txt`
- `auth/content-discovery-url-*.txt`

Outputs:

- `vulnscan/auth-injection/injectable-urls-{{TargetSpace}}.txt`
- `vulnscan/auth-injection/sqlmap-findings-{{TargetSpace}}.jsonl`
- `vulnscan/auth-injection/dalfox-findings-{{TargetSpace}}.jsonl`
- `vulnscan/auth-injection/injection-findings-{{TargetSpace}}.jsonl`
- `vulnscan/auth-injection/injection-findings-{{TargetSpace}}.md`

Behavior:

- Passes auth headers/cookies to sqlmap and Dalfox.
- Keeps authenticated injection findings separate from public injection findings.

## Header Propagation

`auth-session` generates helper formats from `headers-*.txt`:

```text
auth/header-args-{{TargetSpace}}.txt
auth/sqlmap-headers-{{TargetSpace}}.txt
```

`authHeaderArgs` is the newline-joined content of `header-args-*.txt` rendered as repeated `-H "Name: value"` arguments. `authSqlmapHeaders` is the content of `sqlmap-headers-*.txt` rendered as CRLF-separated headers for sqlmap's `--headers` option.

Examples:

```bash
katana ... {{authHeaderArgs}}
nuclei ... {{authHeaderArgs}}
dalfox ... {{authHeaderArgs}}
ffuf ... {{authHeaderArgs}}
pd-httpx ... {{authHeaderArgs}}
sqlmap ... --headers="{{authSqlmapHeaders}}"
```

Each auth module should read these generated helper files rather than reconstructing headers differently.

## Flow Placement

### `auth-only`

Add a standalone flow for authenticated testing against an existing workspace or explicit target scope:

```text
auth-session
  -> auth-spider + auth-content
  -> auth-vuln + auth-injection
  -> llm-surface-analysis
  -> llm-autonomous-controller
```

This flow does not run public DNS, HTTP fingerprinting, screenshots, archive collection, service scan, public nuclei, or public injection modules. It is intended for cases where public recon has already been completed or the user only wants private authenticated coverage.

Example:

```bash
osmedeus run -f auth-only -t example.com \
  -p 'enableAuthScan=true' \
  -p 'authMode=manual' \
  -p 'authScope=https://app.example.com,https://api.example.com' \
  -p 'authHeaderFile=/path/to/headers.txt'
```

If previous public artifacts exist in the same workspace, `auth-only` may read them as passive context for LLM analysis and reporting, but it must not rerun public modules.

### `domain-llm` and `web-analysis-llm`

Authenticated scanning runs after the public scan path:

```text
public recon
  -> llm surface expansion
  -> public vuln/content/injection scans
  -> auth-session
  -> auth-spider + auth-content
  -> auth-vuln + auth-injection
  -> llm-autonomous-controller
```

### `general` and `domain-extensive`

Auth scanning is optional and disabled by default:

```text
normal recon
  -> auth-session
  -> auth-spider + auth-content
  -> auth-vuln + auth-injection
```

Flow params:

```yaml
- name: enableAuthScan
  type: bool
  default: false
- name: skipPublicRecon
  type: bool
  default: false
- name: authMode
  default: "manual"
- name: authScopeFile
  default: "{{Output}}/auth/scope-{{TargetSpace}}.txt"
- name: authHeaderFile
  default: "{{Output}}/auth/headers-{{TargetSpace}}.txt"
- name: authCookieFile
  default: "{{Output}}/auth/cookies-{{TargetSpace}}.txt"
```

`skipPublicRecon=true` is only valid in flows that are explicitly designed to honor it. For the first implementation, `auth-only` is the preferred way to avoid repeated public scans. If `skipPublicRecon` is added to `domain-llm` or `web-analysis-llm`, every public module in that flow must have a guard that skips cleanly while preserving the auth module chain.

Example manual mode:

```bash
osmedeus run -f domain-llm -t example.com \
  -p 'enableAuthScan=true' \
  -p 'authMode=manual' \
  -p 'authScope=https://app.example.com,https://api.example.com' \
  -p 'authHeaderFile=/path/to/headers.txt'
```

Example form login:

```bash
osmedeus run -f web-analysis-llm -t https://app.example.com \
  -p 'enableAuthScan=true' \
  -p 'authMode=form' \
  -p 'authLoginUrl=https://app.example.com/login' \
  -p 'authUsername=demo' \
  -p 'authPassword=demo'
```

Example auth-only rerun after public recon already exists:

```bash
osmedeus run -f auth-only -t example.com \
  -p 'enableAuthScan=true' \
  -p 'authMode=api' \
  -p 'authScope=https://api.example.com' \
  -p 'authLoginUrl=https://api.example.com/login' \
  -p 'authApiLoginBody={"username":"demo","password":"demo"}' \
  -p 'authTokenJsonPath=.token'
```

## Safety and Failure Handling

- Auth modules never run unless `enableAuthScan=true`.
- Auth modules never run unless `auth/scope-*.txt` has at least one URL.
- If login fails, `auth-session` writes a failure report and downstream auth modules skip.
- If `authCheckUrl` is provided, it must pass before scanning.
- Default auth check status is `200`.
- If `authCheckRegex` is non-empty, the auth check response body must match it. Example: `logout|dashboard|account`.
- Auth scanners write only to `auth/`, `vulnscan/auth/`, or `vulnscan/auth-injection/`.
- Baseline public artifacts are not overwritten by auth modules.
- Plaintext secrets exist in workspace by design, but normal reports should list only header/cookie names unless debug mode is explicitly added later.

## LLM Integration

LLM context should include auth metadata and private discoveries, not raw secrets.

Files added to LLM context:

```text
auth/session-report-*.md
auth/scope-*.txt
auth/links-*.txt
auth/content-records-*.jsonl
vulnscan/auth/nuclei-jsonl-*.txt
vulnscan/auth-injection/injection-findings-*.jsonl
```

`session-report-*.md` includes:

```text
Auth mode: manual/form/api/browser
Scope count: 2
Headers present: Authorization, X-Api-Key, Cookie
Cookies present: sid, csrf
Auth check: passed/failed
```

The autonomous controller gets auth metrics:

```json
{
  "auth_scope": 2,
  "auth_links": 143,
  "auth_parameterized_urls": 27,
  "auth_nuclei_findings": 3,
  "auth_injection_findings": 1
}
```

The controller allowlist must include only these auth modules:

```text
auth-spider
auth-content
auth-vuln
auth-injection
```

## Testing Strategy

Lint:

```bash
osmedeus workflow lint common/auth-session.yaml
osmedeus workflow lint common/auth-browser-login.yaml
osmedeus workflow lint common/auth-spider.yaml
osmedeus workflow lint common/auth-content.yaml
osmedeus workflow lint common/auth-vuln.yaml
osmedeus workflow lint common/auth-injection.yaml
osmedeus workflow lint domain-llm.yaml
osmedeus workflow lint web-analysis-llm.yaml
```

Dry-run:

```bash
osmedeus run -m ./common/auth-session.yaml -t example.com --dry-run
osmedeus run -f ./web-analysis-llm.yaml -t https://app.example.com \
  -p 'enableAuthScan=true' \
  -p 'authMode=manual' \
  -p 'authScope=https://app.example.com' \
  -p 'authHeader=Authorization: Bearer test' \
  --dry-run
```

Functional test targets:

- Manual header mode: a local HTTP app that requires `Authorization`.
- API login mode: `/api/login` returns a token and `/api/private` requires it.
- Form login mode: `/login` sets a cookie and `/dashboard` requires it.
- Browser mode: JS login writes a token to localStorage and Playwright captures/maps it.

Success criteria:

- No auth module runs when `enableAuthScan=false`.
- `auth-only` does not render or execute public recon modules.
- `auth-only` can use existing public artifacts as read-only context when they exist.
- Auth modules skip when scope is empty.
- Headers/cookies are passed to spider/content/nuclei/sqlmap/Dalfox.
- Auth artifacts remain separate from baseline artifacts.
- LLM context includes auth metadata and private links but not raw secrets.
- Dry-runs render without undefined params or bad preconditions.

## Non-Goals

- No credential brute force.
- No MFA bypass.
- No automatic scanning outside explicit auth scope.
- No secret encryption in the first implementation.
- No replacement of baseline public recon modules.
