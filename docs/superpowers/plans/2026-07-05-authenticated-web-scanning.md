# Authenticated Web Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add isolated authenticated web scanning workflows and modules that preserve cookies/headers, support manual/form/API/browser login, run auth-only scans, and expose safe auth context to LLM/autonomous analysis.

**Architecture:** Implement a dedicated auth second pass under `auth/`, `vulnscan/auth/`, and `vulnscan/auth-injection/` without modifying baseline public scanner modules. Auth state is normalized once by `auth-session`, then consumed by dedicated `auth-*` scanner modules and the `auth-only` flow. LLM participates in discovery/config proposal only; deterministic workflow steps perform login, registration, and scanning under explicit flags.

**Tech Stack:** Osmedeus YAML workflows, bash steps, Python 3 inline helpers, curl, jq, pd-httpx, katana, ffuf, nuclei, sqlmap, Dalfox, optional Playwright for browser login.

---

## Scope Check

The spec covers one coherent feature: authenticated web scanning as a dedicated workflow layer. It includes multiple modules, but each module is independently lintable and dry-runnable. Do not split this into separate specs unless browser login becomes too large during implementation; browser login is isolated behind `enableBrowserLogin=false`.

## File Structure

- Create `common/auth-session.yaml`: session normalization, manual/form/API login, helper header files, auth check, session report.
- Create `common/auth-discovery.yaml`: deterministic plus LLM-assisted login/register/check candidate discovery.
- Create `common/auth-browser-login.yaml`: optional Playwright-based login capture producing the same session artifacts.
- Create `common/auth-spider.yaml`: authenticated Katana crawl against explicit scope.
- Create `common/auth-content.yaml`: authenticated ffuf content discovery against explicit scope.
- Create `common/auth-vuln.yaml`: authenticated nuclei scan with auth headers.
- Create `common/auth-injection.yaml`: authenticated sqlmap/Dalfox scan with auth headers.
- Create `auth-only.yaml`: standalone auth-only flow that does not run public recon.
- Modify `domain-llm.yaml`: add auth params and auth modules after public scan, before autonomous controller.
- Modify `web-analysis-llm.yaml`: add auth params and auth modules after public scan, before autonomous controller.
- Modify `common/llm-surface-analysis.yaml`: include auth report/private artifacts in bounded context.
- Modify `common/llm-autonomous-controller.yaml`: include auth metrics and allowlisted auth modules.
- Modify `README.md`: document auth modules, `auth-only`, and example commands.

## Task 1: Create `auth-session` Core Module

**Files:**
- Create: `common/auth-session.yaml`
- Test: `osmedeus workflow lint common/auth-session.yaml`
- Test: `osmedeus run -m ./common/auth-session.yaml -t example.com --dry-run`

- [ ] **Step 1: Create the module file**

Create `common/auth-session.yaml` with this content:

```yaml
# =============================================================================
# Module Workflow: Authenticated Session Normalization
# =============================================================================

kind: module
name: auth-session
description: Normalize manual, form, API, or browser authentication into reusable session artifacts
tags: auth, session, web, authenticated

params:
  - name: authDir
    default: "{{Output}}/auth"
  - name: authSessionFile
    default: "{{Output}}/auth/session-{{TargetSpace}}.json"
  - name: authHeaderFile
    default: "{{Output}}/auth/headers-{{TargetSpace}}.txt"
  - name: authCookieFile
    default: "{{Output}}/auth/cookies-{{TargetSpace}}.txt"
  - name: authScopeFile
    default: "{{Output}}/auth/scope-{{TargetSpace}}.txt"
  - name: authHeaderArgsFile
    default: "{{Output}}/auth/header-args-{{TargetSpace}}.txt"
  - name: authSqlmapHeadersFile
    default: "{{Output}}/auth/sqlmap-headers-{{TargetSpace}}.txt"
  - name: authSessionReport
    default: "{{Output}}/auth/session-report-{{TargetSpace}}.md"
  - name: authConfigProposalFile
    default: "{{Output}}/auth/auth-config-proposal-{{TargetSpace}}.yaml"

  - name: enableAuthScan
    type: bool
    default: false
  - name: authMode
    default: "manual"
  - name: authScope
    default: ""
  - name: authHeader
    default: ""
  - name: authCookie
    default: ""
  - name: authLoginUrl
    default: ""
  - name: authUsername
    default: ""
  - name: authPassword
    default: ""
  - name: authApiLoginMethod
    default: "POST"
  - name: authApiLoginBody
    default: ""
  - name: authTokenJsonPath
    default: ".token"
  - name: authCheckUrl
    default: ""
  - name: authCheckStatus
    default: "200"
  - name: authCheckRegex
    default: ""
  - name: useAuthConfigProposal
    type: bool
    default: false
  - name: enableAutoRegister
    type: bool
    default: false
  - name: registerScope
    default: ""
  - name: registerEmailTemplate
    default: ""
  - name: registerUsernameTemplate
    default: ""
  - name: registerPassword
    default: ""
  - name: defaultUA
    default: "User-Agent: Mozilla/5.0 (compatible; Osmedeus/v5; +https://github.com/j3ssie/osmedeus)"

dependencies:
  commands:
    - python3
    - curl
    - jq
  variables:
    - name: Target
      type: string
      required: true

reports:
  - name: auth-session-report
    path: "{{authSessionReport}}"
    type: md
    description: Authenticated session summary without raw secret values
  - name: auth-session-json
    path: "{{authSessionFile}}"
    type: json
    description: Plaintext authenticated session artifact

steps:
  - name: create-auth-folder
    type: function
    log: "Creating auth output folder"
    functions:
      - 'create_folder("{{authDir}}")'

  - name: normalize-manual-input
    type: bash
    log: "Normalizing manual auth scope, headers, and cookies"
    pre_condition: '"{{enableAuthScan}}" == "true"'
    commands:
      - |
        python3 - "{{Target}}" "{{authMode}}" "{{authScope}}" "{{authHeader}}" "{{authCookie}}" \
          "{{authScopeFile}}" "{{authHeaderFile}}" "{{authCookieFile}}" "{{authSessionFile}}" "{{authSessionReport}}" <<'PY'
        import json
        import sys
        from datetime import datetime, timezone
        from pathlib import Path

        target, mode, scope_raw, header_raw, cookie_raw = sys.argv[1:6]
        scope_file, header_file, cookie_file, session_file, report_file = map(Path, sys.argv[6:11])

        def split_values(value):
            out = []
            for chunk in (value or "").replace(",", "\n").splitlines():
                chunk = chunk.strip()
                if chunk:
                    out.append(chunk)
            return out

        scope = split_values(scope_raw)
        headers = split_values(header_raw)
        cookies = split_values(cookie_raw)

        if scope_file.exists():
            scope.extend(split_values(scope_file.read_text(encoding="utf-8", errors="replace")))
        if header_file.exists():
            headers.extend(split_values(header_file.read_text(encoding="utf-8", errors="replace")))
        if cookie_file.exists():
            cookies.extend(split_values(cookie_file.read_text(encoding="utf-8", errors="replace")))

        scope = sorted(dict.fromkeys(scope))
        headers = sorted(dict.fromkeys(headers))
        cookies = sorted(dict.fromkeys(cookies))

        scope_file.write_text("\n".join(scope) + ("\n" if scope else ""), encoding="utf-8")
        header_file.write_text("\n".join(headers) + ("\n" if headers else ""), encoding="utf-8")
        cookie_file.write_text("\n".join(cookies) + ("\n" if cookies else ""), encoding="utf-8")

        header_map = {}
        for line in headers:
            if ":" in line:
                name, value = line.split(":", 1)
                header_map[name.strip()] = value.strip()
        if cookies and "Cookie" not in header_map:
            header_map["Cookie"] = "; ".join(cookies)

        session = {
            "target": target,
            "source": mode,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "headers": header_map,
            "cookies": [{"raw": item} for item in cookies],
            "scope": scope,
            "evidence": {},
        }
        session_file.write_text(json.dumps(session, indent=2), encoding="utf-8")

        report_lines = [
            f"# Auth Session - {target}",
            "",
            f"- Mode: {mode}",
            f"- Scope count: {len(scope)}",
            f"- Headers present: {', '.join(sorted(header_map)) if header_map else 'None'}",
            f"- Cookies present: {len(cookies)}",
            "- Auth check: not configured",
            "",
        ]
        report_file.write_text("\n".join(report_lines), encoding="utf-8")
        PY
    on_error:
      - action: continue

  - name: api-login
    type: bash
    log: "Performing API login when configured"
    pre_condition: '"{{enableAuthScan}}" == "true" && "{{authMode}}" == "api" && "{{authLoginUrl}}" != "" && "{{authApiLoginBody}}" != ""'
    commands:
      - |
        response="{{authDir}}/api-login-response-{{TargetSpace}}.json"
        curl -ksS -X "{{authApiLoginMethod}}" -H "{{defaultUA}}" -H "Content-Type: application/json" \
          --data '{{authApiLoginBody}}' "{{authLoginUrl}}" -o "$response" || true
        token="$(jq -r '{{authTokenJsonPath}} // empty' "$response" 2>/dev/null || true)"
        if [ -n "$token" ] && [ "$token" != "null" ]; then
          grep -v '^Authorization:' "{{authHeaderFile}}" 2>/dev/null > "{{authHeaderFile}}.tmp" || true
          printf 'Authorization: Bearer %s\n' "$token" >> "{{authHeaderFile}}.tmp"
          mv "{{authHeaderFile}}.tmp" "{{authHeaderFile}}"
        fi
    on_error:
      - action: continue

  - name: form-login
    type: bash
    log: "Performing simple form login when configured"
    pre_condition: '"{{enableAuthScan}}" == "true" && "{{authMode}}" == "form" && "{{authLoginUrl}}" != "" && "{{authUsername}}" != "" && "{{authPassword}}" != ""'
    commands:
      - |
        cookiejar="{{authDir}}/form-login-cookies-{{TargetSpace}}.jar"
        curl -ksS -c "$cookiejar" -b "$cookiejar" -H "{{defaultUA}}" \
          --data-urlencode "username={{authUsername}}" \
          --data-urlencode "password={{authPassword}}" \
          "{{authLoginUrl}}" -o "{{authDir}}/form-login-response-{{TargetSpace}}.html" || true
        awk 'NF >= 7 && $1 !~ /^#/ {print $6"="$7}' "$cookiejar" | paste -sd '; ' - > "{{authCookieFile}}.tmp" || true
        if [ -s "{{authCookieFile}}.tmp" ]; then
          cookie="$(cat "{{authCookieFile}}.tmp")"
          printf '%s\n' "$cookie" > "{{authCookieFile}}"
          grep -v '^Cookie:' "{{authHeaderFile}}" 2>/dev/null > "{{authHeaderFile}}.headers" || true
          printf 'Cookie: %s\n' "$cookie" >> "{{authHeaderFile}}.headers"
          mv "{{authHeaderFile}}.headers" "{{authHeaderFile}}"
        fi
        rm -f "{{authCookieFile}}.tmp"
    on_error:
      - action: continue

  - name: generate-auth-helper-files
    type: bash
    log: "Generating reusable auth header arguments"
    pre_condition: '"{{enableAuthScan}}" == "true" && file_length("{{authHeaderFile}}") > 0'
    commands:
      - |
        python3 - "{{authHeaderFile}}" "{{authHeaderArgsFile}}" "{{authSqlmapHeadersFile}}" "{{authSessionFile}}" "{{authSessionReport}}" <<'PY'
        import json
        import shlex
        import sys
        from pathlib import Path

        header_file, args_file, sqlmap_file, session_file, report_file = map(Path, sys.argv[1:6])
        headers = [line.strip() for line in header_file.read_text(encoding="utf-8", errors="replace").splitlines() if ":" in line]
        args_file.write_text(" ".join("-H " + shlex.quote(h) for h in headers), encoding="utf-8")
        sqlmap_file.write_text("\\r\\n".join(headers), encoding="utf-8")

        if session_file.exists():
            session = json.loads(session_file.read_text(encoding="utf-8", errors="replace"))
        else:
            session = {"headers": {}, "cookies": [], "scope": []}
        session["headers"] = {h.split(":", 1)[0].strip(): h.split(":", 1)[1].strip() for h in headers}
        session_file.write_text(json.dumps(session, indent=2), encoding="utf-8")

        text = report_file.read_text(encoding="utf-8", errors="replace") if report_file.exists() else "# Auth Session\n"
        text += f"\n- Header arg file: `{args_file}`\n- sqlmap header file: `{sqlmap_file}`\n"
        report_file.write_text(text, encoding="utf-8")
        PY
    on_error:
      - action: continue

  - name: auth-check
    type: bash
    log: "Checking authenticated session"
    pre_condition: '"{{enableAuthScan}}" == "true" && "{{authCheckUrl}}" != "" && file_length("{{authHeaderArgsFile}}") > 0'
    commands:
      - |
        set +e
        status="$(curl -ksS -o "{{authDir}}/auth-check-body-{{TargetSpace}}.txt" -w "%{http_code}" $(cat "{{authHeaderArgsFile}}") "{{authCheckUrl}}")"
        echo "$status" > "{{authDir}}/auth-check-status-{{TargetSpace}}.txt"
        if [ "$status" != "{{authCheckStatus}}" ]; then
          echo "auth check failed: expected {{authCheckStatus}}, got $status" >> "{{authSessionReport}}"
        elif [ -n "{{authCheckRegex}}" ] && ! grep -E "{{authCheckRegex}}" "{{authDir}}/auth-check-body-{{TargetSpace}}.txt" >/dev/null 2>&1; then
          echo "auth check failed: regex {{authCheckRegex}} not found" >> "{{authSessionReport}}"
        else
          echo "auth check passed: $status" >> "{{authSessionReport}}"
        fi
    on_error:
      - action: continue
```

- [ ] **Step 2: Lint the module**

Run:

```bash
osmedeus workflow lint common/auth-session.yaml
```

Expected:

```text
✔ Workflow 'auth-session' (module) passed all lint checks
```

- [ ] **Step 3: Dry-run manual mode**

Run:

```bash
osmedeus run -m ./common/auth-session.yaml -t example.com \
  -p 'enableAuthScan=true' \
  -p 'authMode=manual' \
  -p 'authScope=https://app.example.com' \
  -p 'authHeader=Authorization: Bearer test' \
  --dry-run
```

Expected: dry-run shows `normalize-manual-input` and `generate-auth-helper-files`; `auth-check` precondition renders false unless `authCheckUrl` is provided.

- [ ] **Step 4: Commit**

```bash
git add common/auth-session.yaml
git commit -m "feat: add auth session normalization"
```

## Task 2: Create Auth Discovery Module

**Files:**
- Create: `common/auth-discovery.yaml`
- Test: `osmedeus workflow lint common/auth-discovery.yaml`
- Test: `osmedeus run -m ./common/auth-discovery.yaml -t example.com --dry-run`

- [ ] **Step 1: Create deterministic and LLM-assisted discovery module**

Create `common/auth-discovery.yaml` with this content:

```yaml
# =============================================================================
# Module Workflow: Authentication Surface Discovery
# =============================================================================

kind: module
name: auth-discovery
description: Discover likely login, registration, and authenticated check surfaces without submitting credentials
tags: auth, discovery, llm, login, register

params:
  - name: authDir
    default: "{{Output}}/auth"
  - name: httpFile
    default: "{{Output}}/probing/http-{{TargetSpace}}.txt"
  - name: httpFingerprintJsonFile
    default: "{{Output}}/fingerprint/http-fingerprint-{{TargetSpace}}.jsonl"
  - name: linkFile
    default: "{{Output}}/links/links-{{TargetSpace}}.txt"
  - name: contentDiscoveryJsonlFile
    default: "{{Output}}/content-discovery/deparos-records-{{TargetSpace}}.jsonl"
  - name: contentDiscoverUrlsFile
    default: "{{Output}}/content-discovery/content-discovery-url-{{TargetSpace}}.txt"
  - name: authScopeFile
    default: "{{Output}}/auth/scope-{{TargetSpace}}.txt"
  - name: authLoginCandidatesFile
    default: "{{Output}}/auth/login-candidates-{{TargetSpace}}.jsonl"
  - name: authRegisterCandidatesFile
    default: "{{Output}}/auth/register-candidates-{{TargetSpace}}.jsonl"
  - name: authCheckCandidatesFile
    default: "{{Output}}/auth/auth-check-candidates-{{TargetSpace}}.jsonl"
  - name: authPlanFile
    default: "{{Output}}/auth/auth-plan-{{TargetSpace}}.md"
  - name: authConfigProposalFile
    default: "{{Output}}/auth/auth-config-proposal-{{TargetSpace}}.yaml"
  - name: enableAuthDiscovery
    type: bool
    default: true
  - name: enableLLMAuthDiscovery
    type: bool
    default: true
  - name: authDiscoveryLineLimit
    default: "2000"

dependencies:
  commands:
    - python3
  variables:
    - name: Target
      type: string
      required: true

reports:
  - name: auth-plan
    path: "{{authPlanFile}}"
    type: md
    description: Authentication discovery plan and candidate summary
  - name: auth-config-proposal
    path: "{{authConfigProposalFile}}"
    type: yaml
    description: Proposed auth-session parameters generated from discovered login surfaces

steps:
  - name: create-auth-folder
    type: function
    log: "Creating auth discovery output folder"
    functions:
      - 'create_folder("{{authDir}}")'

  - name: deterministic-auth-discovery
    type: bash
    log: "Finding likely auth URLs from existing artifacts"
    pre_condition: '{{enableAuthDiscovery}}'
    commands:
      - |
        python3 - "{{Target}}" "{{authDiscoveryLineLimit}}" "{{authScopeFile}}" \
          "{{authLoginCandidatesFile}}" "{{authRegisterCandidatesFile}}" "{{authCheckCandidatesFile}}" "{{authPlanFile}}" \
          "{{httpFile}}" "{{linkFile}}" "{{contentDiscoverUrlsFile}}" "{{httpFingerprintJsonFile}}" "{{contentDiscoveryJsonlFile}}" <<'PY'
        import json
        import re
        import sys
        from pathlib import Path
        from urllib.parse import urlsplit

        target = sys.argv[1].lower().strip()
        limit = int(sys.argv[2])
        scope_file = Path(sys.argv[3])
        login_out, register_out, check_out, plan_out = map(Path, sys.argv[4:8])
        input_paths = [Path(p) for p in sys.argv[8:]]

        auth_words = {
            "login": ["login", "signin", "sign-in", "auth", "session"],
            "register": ["register", "signup", "sign-up", "join", "create-account"],
            "check": ["me", "profile", "account", "dashboard", "settings", "logout"],
        }

        explicit_scope = set()
        if scope_file.exists():
            explicit_scope = {line.strip() for line in scope_file.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()}

        def in_scope(url):
            try:
                parsed = urlsplit(url)
            except ValueError:
                return False
            host = (parsed.hostname or "").lower()
            if not parsed.scheme.startswith("http") or not host:
                return False
            if explicit_scope:
                return any(url.startswith(root.rstrip("/") + "/") or url == root.rstrip("/") for root in explicit_scope)
            return host == target or host.endswith("." + target) or target in host

        def extract_urls(path):
            urls = []
            if not path.exists():
                return urls
            count = 0
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if count >= limit:
                    break
                count += 1
                try:
                    row = json.loads(line)
                    values = [row.get("url"), row.get("matched-at"), row.get("host")]
                    if isinstance(row.get("data"), dict):
                        values.append(row["data"].get("url"))
                except Exception:
                    values = [line]
                for value in values:
                    if not value:
                        continue
                    for match in re.findall(r"https?://[^\\s\\\"'<>]+", str(value)):
                        urls.append(match.rstrip(".,;)"))
            return urls

        buckets = {"login": {}, "register": {}, "check": {}}
        for path in input_paths:
            for url in extract_urls(path):
                if not in_scope(url):
                    continue
                lowered = url.lower()
                for bucket, words in auth_words.items():
                    if any(word in lowered for word in words):
                        buckets[bucket][url] = {"url": url, "source": path.name, "reason": bucket}

        for out_path, bucket in ((login_out, "login"), (register_out, "register"), (check_out, "check")):
            rows = buckets[bucket].values()
            out_path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\\n" for row in rows), encoding="utf-8")

        plan = [
            f"# Auth Discovery - {target}",
            "",
            f"- Login candidates: {len(buckets['login'])}",
            f"- Register candidates: {len(buckets['register'])}",
            f"- Auth check candidates: {len(buckets['check'])}",
            "",
            "## Top Login Candidates",
        ]
        plan.extend(f"- {row['url']}" for row in list(buckets["login"].values())[:20])
        plan.extend(["", "## Top Register Candidates"])
        plan.extend(f"- {row['url']}" for row in list(buckets["register"].values())[:20])
        plan.extend(["", "## Top Auth Check Candidates"])
        plan.extend(f"- {row['url']}" for row in list(buckets["check"].values())[:20])
        plan_out.write_text("\\n".join(plan) + "\\n", encoding="utf-8")
        PY
    on_error:
      - action: continue

  - name: llm-auth-config-proposal
    type: agent
    log: "Using LLM to classify auth surfaces and propose auth-session config"
    pre_condition: '{{enableAuthDiscovery}} && {{enableLLMAuthDiscovery}} && (file_length("{{authLoginCandidatesFile}}") > 0 || file_length("{{authRegisterCandidatesFile}}") > 0)'
    system_prompt: |
      You are an authorized web authentication workflow analyst.
      You may inspect candidate URLs and propose configuration only.
      Do not submit credentials, register accounts, bypass MFA, solve CAPTCHA, or expand scope.
      Do not include raw secrets in any output.
    query: |
      Read:
      - {{authLoginCandidatesFile}}
      - {{authRegisterCandidatesFile}}
      - {{authCheckCandidatesFile}}
      - {{authPlanFile}}

      Update {{authPlanFile}} with:
      - likely auth type: form, api, browser, or manual
      - strongest login/register/check candidates
      - field names likely needed
      - suggested auth check URL and body regex
      - reasons and confidence

      Write {{authConfigProposalFile}} as YAML with these keys only:
      authMode: ""
      authLoginUrl: ""
      authUsernameField: "username"
      authPasswordField: "password"
      authApiLoginMethod: "POST"
      authApiLoginBody: ""
      authTokenJsonPath: ".token"
      authCheckUrl: ""
      authCheckRegex: ""

      Keep all URLs inside {{Target}} or existing auth scope artifacts. Leave fields empty when unsure.
    max_iterations: 8
    parallel_tool_calls: false
    agent_tools:
      - preset: read_file
      - preset: file_exists
      - preset: file_length
      - preset: save_content
    llm_config:
      max_tokens: 3000
      temperature: 0.1
      timeout: "5m"
      max_retries: 2
    on_error:
      - action: continue
```

- [ ] **Step 2: Lint the module**

Run:

```bash
osmedeus workflow lint common/auth-discovery.yaml
```

Expected:

```text
✔ Workflow 'auth-discovery' (module) passed all lint checks
```

- [ ] **Step 3: Dry-run the module**

Run:

```bash
osmedeus run -m ./common/auth-discovery.yaml -t example.com --dry-run
```

Expected: dry-run shows deterministic discovery and the LLM agent step with precondition referencing candidate files.

- [ ] **Step 4: Commit**

```bash
git add common/auth-discovery.yaml
git commit -m "feat: add auth surface discovery"
```

## Task 3: Create Optional Browser Login Module

**Files:**
- Create: `common/auth-browser-login.yaml`
- Test: `osmedeus workflow lint common/auth-browser-login.yaml`

- [ ] **Step 1: Create browser login module**

Create `common/auth-browser-login.yaml` with this content:

```yaml
# =============================================================================
# Module Workflow: Browser Authentication Capture
# =============================================================================

kind: module
name: auth-browser-login
description: Capture authenticated cookies and browser storage with Playwright for JS-heavy login flows
tags: auth, browser, playwright, login

params:
  - name: authDir
    default: "{{Output}}/auth"
  - name: authSessionFile
    default: "{{Output}}/auth/session-{{TargetSpace}}.json"
  - name: authHeaderFile
    default: "{{Output}}/auth/headers-{{TargetSpace}}.txt"
  - name: authCookieFile
    default: "{{Output}}/auth/cookies-{{TargetSpace}}.txt"
  - name: authScopeFile
    default: "{{Output}}/auth/scope-{{TargetSpace}}.txt"
  - name: authSessionReport
    default: "{{Output}}/auth/session-report-{{TargetSpace}}.md"
  - name: enableAuthScan
    type: bool
    default: false
  - name: enableBrowserLogin
    type: bool
    default: false
  - name: authLoginUrl
    default: ""
  - name: authUsername
    default: ""
  - name: authPassword
    default: ""
  - name: browserUsernameSelector
    default: "input[name='username'],input[type='email']"
  - name: browserPasswordSelector
    default: "input[name='password'],input[type='password']"
  - name: browserSubmitSelector
    default: "button[type='submit'],input[type='submit']"
  - name: browserStorageTokenRegex
    default: "(token|jwt|access)"
  - name: browserAuthHeaderName
    default: "Authorization"
  - name: browserAuthHeaderPrefix
    default: "Bearer "
  - name: browserLoginTimeout
    default: "30000"

dependencies:
  commands:
    - node
  variables:
    - name: Target
      type: string
      required: true

reports:
  - name: browser-auth-session-report
    path: "{{authSessionReport}}"
    type: md
    description: Browser login capture summary

steps:
  - name: create-auth-folder
    type: function
    functions:
      - 'create_folder("{{authDir}}")'

  - name: browser-login-capture
    type: bash
    log: "Capturing browser login session with Playwright"
    pre_condition: '"{{enableAuthScan}}" == "true" && "{{enableBrowserLogin}}" == "true" && "{{authLoginUrl}}" != ""'
    commands:
      - |
        node - "{{Target}}" "{{authLoginUrl}}" "{{authUsername}}" "{{authPassword}}" \
          "{{browserUsernameSelector}}" "{{browserPasswordSelector}}" "{{browserSubmitSelector}}" \
          "{{browserStorageTokenRegex}}" "{{browserAuthHeaderName}}" "{{browserAuthHeaderPrefix}}" \
          "{{browserLoginTimeout}}" "{{authSessionFile}}" "{{authHeaderFile}}" "{{authCookieFile}}" "{{authSessionReport}}" <<'NODE'
        const fs = require("fs");
        const [
          target, loginUrl, username, password, userSelector, passSelector, submitSelector,
          tokenRegexRaw, headerName, headerPrefix, timeoutRaw,
          sessionFile, headerFile, cookieFile, reportFile
        ] = process.argv.slice(2);

        (async () => {
          const { chromium } = require("playwright");
          const timeout = Number(timeoutRaw || "30000");
          const browser = await chromium.launch({ headless: true });
          const context = await browser.newContext();
          const page = await context.newPage();
          await page.goto(loginUrl, { waitUntil: "domcontentloaded", timeout });
          if (username) await page.locator(userSelector).first().fill(username, { timeout }).catch(() => {});
          if (password) await page.locator(passSelector).first().fill(password, { timeout }).catch(() => {});
          await page.locator(submitSelector).first().click({ timeout }).catch(() => {});
          await page.waitForLoadState("networkidle", { timeout }).catch(() => {});

          const cookies = await context.cookies();
          const storage = await page.evaluate(() => {
            const out = {};
            for (const storeName of ["localStorage", "sessionStorage"]) {
              const store = window[storeName];
              out[storeName] = {};
              for (let i = 0; i < store.length; i++) {
                const key = store.key(i);
                out[storeName][key] = store.getItem(key);
              }
            }
            return out;
          });
          await browser.close();

          const tokenRegex = new RegExp(tokenRegexRaw, "i");
          let token = "";
          for (const area of Object.values(storage)) {
            for (const [key, value] of Object.entries(area)) {
              if (tokenRegex.test(key) && value) token = value;
            }
          }

          const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join("; ");
          const headers = {};
          if (cookieHeader) headers["Cookie"] = cookieHeader;
          if (token) headers[headerName] = `${headerPrefix}${token}`;

          fs.writeFileSync(headerFile, Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n") + "\n");
          fs.writeFileSync(cookieFile, cookieHeader ? cookieHeader + "\n" : "");
          fs.writeFileSync(sessionFile, JSON.stringify({
            target,
            source: "browser-login",
            created_at: new Date().toISOString(),
            headers,
            cookies,
            scope: [],
            evidence: { login_url: loginUrl, final_url: page.url ? page.url() : "" }
          }, null, 2));
          fs.writeFileSync(reportFile, [
            `# Browser Auth Session - ${target}`,
            "",
            "- Mode: browser",
            `- Cookies present: ${cookies.length}`,
            `- Headers present: ${Object.keys(headers).join(", ") || "None"}`,
            "- Auth check: not configured",
            ""
          ].join("\n"));
        })().catch(err => {
          fs.writeFileSync(reportFile, `# Browser Auth Session - ${target}\n\n- Error: ${err.message}\n`);
          process.exit(0);
        });
        NODE
    on_error:
      - action: continue
```

- [ ] **Step 2: Lint the module**

Run:

```bash
osmedeus workflow lint common/auth-browser-login.yaml
```

Expected:

```text
✔ Workflow 'auth-browser-login' (module) passed all lint checks
```

- [ ] **Step 3: Dry-run disabled default**

Run:

```bash
osmedeus run -m ./common/auth-browser-login.yaml -t example.com --dry-run
```

Expected: `browser-login-capture` precondition renders false because `enableBrowserLogin=false`.

- [ ] **Step 4: Commit**

```bash
git add common/auth-browser-login.yaml
git commit -m "feat: add optional browser auth capture"
```

## Task 4: Create Authenticated Spider and Content Modules

**Files:**
- Create: `common/auth-spider.yaml`
- Create: `common/auth-content.yaml`
- Test: `osmedeus workflow lint common/auth-spider.yaml`
- Test: `osmedeus workflow lint common/auth-content.yaml`

- [ ] **Step 1: Create authenticated spider module**

Create `common/auth-spider.yaml` with this content:

```yaml
kind: module
name: auth-spider
description: Crawl authenticated scope with preserved session headers
tags: auth, spider, crawl

params:
  - name: authDir
    default: "{{Output}}/auth"
  - name: authScopeFile
    default: "{{Output}}/auth/scope-{{TargetSpace}}.txt"
  - name: authHeaderArgsFile
    default: "{{Output}}/auth/header-args-{{TargetSpace}}.txt"
  - name: authLinksFile
    default: "{{Output}}/auth/links-{{TargetSpace}}.txt"
  - name: authParameterizedUrlsFile
    default: "{{Output}}/auth/parameterized-urls-{{TargetSpace}}.txt"
  - name: authSpiderRecordsFile
    default: "{{Output}}/auth/spider-records-{{TargetSpace}}.jsonl"
  - name: enableAuthScan
    type: bool
    default: false
  - name: authSpiderTimeout
    default: "45m"
  - name: authSpiderThreads
    default: "{{ threads }}"
  - name: authSpiderParallel
    default: "{{ threads / 2 }}"
  - name: authCrawlingTime
    default: "20"

dependencies:
  commands:
    - katana
    - python3
  variables:
    - name: Target
      type: string
      required: true

reports:
  - name: auth-links
    path: "{{authLinksFile}}"
    type: text
    description: Authenticated crawled links

steps:
  - name: create-auth-folder
    type: function
    functions:
      - 'create_folder("{{authDir}}")'

  - name: crawl-auth-scope
    type: foreach
    log: "Crawling authenticated scope with Katana"
    pre_condition: '"{{enableAuthScan}}" == "true" && file_length("{{authScopeFile}}") > 0 && file_length("{{authHeaderArgsFile}}") > 0'
    input: "{{authScopeFile}}"
    variable: line
    threads: "{{authSpiderParallel}}"
    step:
      name: katana-auth-target
      type: bash
      command: 'timeout -k 1m {{authSpiderTimeout}} katana -silent -c {{authSpiderThreads}} -jc -ct {{authCrawlingTime}} $(cat "{{authHeaderArgsFile}}") -u [[line]] | sort -u >> "{{authLinksFile}}"'
      on_error:
        - action: continue

  - name: normalize-auth-links
    type: bash
    log: "Normalizing authenticated links"
    pre_condition: 'file_exists("{{authLinksFile}}")'
    commands:
      - |
        sort -u "{{authLinksFile}}" -o "{{authLinksFile}}" 2>/dev/null || true
        grep '?' "{{authLinksFile}}" | sort -u > "{{authParameterizedUrlsFile}}" || true
        python3 - "{{authLinksFile}}" "{{authSpiderRecordsFile}}" <<'PY'
        import json
        import sys
        from pathlib import Path
        links = Path(sys.argv[1])
        out = Path(sys.argv[2])
        rows = []
        if links.exists():
            for url in links.read_text(encoding="utf-8", errors="replace").splitlines():
                if url.strip():
                    rows.append({"url": url.strip(), "source": "auth-spider"})
        out.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        PY
    on_error:
      - action: continue
```

- [ ] **Step 2: Create authenticated content module**

Create `common/auth-content.yaml` with this content:

```yaml
kind: module
name: auth-content
description: Run authenticated content discovery against explicit auth scope
tags: auth, content-discovery, ffuf

params:
  - name: authDir
    default: "{{Output}}/auth"
  - name: authScopeFile
    default: "{{Output}}/auth/scope-{{TargetSpace}}.txt"
  - name: authHeaderArgsFile
    default: "{{Output}}/auth/header-args-{{TargetSpace}}.txt"
  - name: authContentUrlsFile
    default: "{{Output}}/auth/content-discovery-url-{{TargetSpace}}.txt"
  - name: authContentRecordsFile
    default: "{{Output}}/auth/content-records-{{TargetSpace}}.jsonl"
  - name: authContentReport
    default: "{{Output}}/auth/content-discovery-report-{{TargetSpace}}.md"
  - name: authContentWordlist
    default: "{{Data}}/wordlists/content/small.txt"
  - name: enableAuthScan
    type: bool
    default: false
  - name: authFfufTimeout
    default: "30m"
  - name: authFfufParallel
    default: "10"
  - name: authFfufThreads
    default: "25"

dependencies:
  commands:
    - ffuf
    - jq
    - python3
  variables:
    - name: Target
      type: string
      required: true

reports:
  - name: auth-content-report
    path: "{{authContentReport}}"
    type: md
    description: Authenticated content discovery report

steps:
  - name: create-auth-folder
    type: function
    functions:
      - 'create_folder("{{authDir}}")'

  - name: ffuf-auth-scope
    type: foreach
    log: "Running ffuf with authenticated headers"
    pre_condition: '"{{enableAuthScan}}" == "true" && file_length("{{authScopeFile}}") > 0 && file_length("{{authHeaderArgsFile}}") > 0'
    input: "{{authScopeFile}}"
    variable: line
    threads: "{{authFfufParallel}}"
    step:
      name: ffuf-auth-target
      type: bash
      command: 'timeout -k 1m {{authFfufTimeout}} ffuf -s -t {{authFfufThreads}} -noninteractive -ac -acs advanced -timeout 15 -se -D -fc "429,404,400" -json $(cat "{{authHeaderArgsFile}}") -u "[[line]]/FUZZ" -w "{{authContentWordlist}}":FUZZ > "{{authDir}}/ffuf-auth-raw-[[_id_]].json" 2>/dev/null'
      on_error:
        - action: continue

  - name: process-auth-ffuf
    type: bash
    log: "Processing authenticated ffuf results"
    pre_condition: 'dir_length("{{authDir}}") > 0'
    commands:
      - |
        cat "{{authDir}}"/ffuf-auth-raw-*.json 2>/dev/null | jq -r '.results[]?.url // empty' | sort -u > "{{authContentUrlsFile}}" || true
        python3 - "{{authContentUrlsFile}}" "{{authContentRecordsFile}}" "{{authContentReport}}" <<'PY'
        import json
        import sys
        from pathlib import Path
        urls = Path(sys.argv[1])
        records = Path(sys.argv[2])
        report = Path(sys.argv[3])
        values = [line.strip() for line in urls.read_text(encoding="utf-8", errors="replace").splitlines()] if urls.exists() else []
        records.write_text("".join(json.dumps({"url": u, "source": "auth-content"}) + "\n" for u in values), encoding="utf-8")
        report.write_text("# Auth Content Discovery\n\n" + "\n".join(f"- {u}" for u in values[:200]) + "\n", encoding="utf-8")
        PY
        rm -f "{{authDir}}"/ffuf-auth-raw-*.json
    on_error:
      - action: continue
```

- [ ] **Step 3: Lint both modules**

Run:

```bash
osmedeus workflow lint common/auth-spider.yaml
osmedeus workflow lint common/auth-content.yaml
```

Expected:

```text
✔ Workflow 'auth-spider' (module) passed all lint checks
✔ Workflow 'auth-content' (module) passed all lint checks
```

- [ ] **Step 4: Dry-run both modules**

Run:

```bash
osmedeus run -m ./common/auth-spider.yaml -t example.com --dry-run
osmedeus run -m ./common/auth-content.yaml -t example.com --dry-run
```

Expected: scan steps render with `enableAuthScan=false` in preconditions by default.

- [ ] **Step 5: Commit**

```bash
git add common/auth-spider.yaml common/auth-content.yaml
git commit -m "feat: add authenticated spider and content scans"
```

## Task 5: Create Authenticated Vulnerability and Injection Modules

**Files:**
- Create: `common/auth-vuln.yaml`
- Create: `common/auth-injection.yaml`
- Test: `osmedeus workflow lint common/auth-vuln.yaml`
- Test: `osmedeus workflow lint common/auth-injection.yaml`

- [ ] **Step 1: Create authenticated nuclei module**

Create `common/auth-vuln.yaml` with this content:

```yaml
kind: module
name: auth-vuln
description: Run Nuclei with authenticated headers against explicit authenticated scope
tags: auth, vulnerability, nuclei

params:
  - name: authScopeFile
    default: "{{Output}}/auth/scope-{{TargetSpace}}.txt"
  - name: authContentUrlsFile
    default: "{{Output}}/auth/content-discovery-url-{{TargetSpace}}.txt"
  - name: authHeaderArgsFile
    default: "{{Output}}/auth/header-args-{{TargetSpace}}.txt"
  - name: authVulnDir
    default: "{{Output}}/vulnscan/auth"
  - name: authVulnInputFile
    default: "{{Output}}/vulnscan/auth/input-{{TargetSpace}}.txt"
  - name: authNucleiOutputJsonl
    default: "{{Output}}/vulnscan/auth/nuclei-jsonl-{{TargetSpace}}.txt"
  - name: authNucleiCleanOutputJsonl
    default: "{{Output}}/vulnscan/auth/clean-jsonl-{{TargetSpace}}.txt"
  - name: authNucleiMarkdownReport
    default: "{{Output}}/vulnscan/auth/nuclei-overview-report-{{TargetSpace}}.md"
  - name: enableAuthScan
    type: bool
    default: false
  - name: nucleiTemplateConfig
    default: "~/nuclei-templates/"
  - name: nucleiThreads
    default: "{{ threads * 10 }}"
  - name: nucleiTimeout
    default: "4h"
  - name: nucleiSeverity
    default: "critical,high,medium,low,info"
  - name: extraNuclei
    default: " "

dependencies:
  commands:
    - nuclei
  variables:
    - name: Target
      type: string
      required: true

reports:
  - name: auth-nuclei-raw-json
    path: "{{authNucleiOutputJsonl}}"
    type: jsonl
    description: Authenticated nuclei findings

steps:
  - name: create-auth-vuln-folder
    type: function
    functions:
      - 'create_folder("{{authVulnDir}}")'

  - name: build-auth-vuln-input
    type: bash
    log: "Building authenticated nuclei input"
    pre_condition: '"{{enableAuthScan}}" == "true" && file_length("{{authScopeFile}}") > 0'
    commands:
      - |
        {
          cat "{{authScopeFile}}"
          [ -f "{{authContentUrlsFile}}" ] && cat "{{authContentUrlsFile}}"
        } | sort -u > "{{authVulnInputFile}}"
    on_error:
      - action: continue

  - name: nuclei-auth-scan
    type: bash
    log: "Running nuclei with authenticated headers"
    pre_condition: 'file_length("{{authVulnInputFile}}") > 0 && file_length("{{authHeaderArgsFile}}") > 0'
    commands:
      - 'timeout -k 1m {{nucleiTimeout}} nuclei $(cat "{{authHeaderArgsFile}}") -silent -c {{nucleiThreads}} -jsonl -severity "{{nucleiSeverity}}" -t {{nucleiTemplateConfig}} -l "{{authVulnInputFile}}" -irr -o "{{authNucleiOutputJsonl}}" {{extraNuclei}} > /dev/null 2>&1'
    on_error:
      - action: continue

  - name: process-auth-nuclei
    type: function
    log: "Processing authenticated nuclei findings"
    pre_condition: 'file_length("{{authNucleiOutputJsonl}}") > 0'
    functions:
      - jsonl_filter("{{authNucleiOutputJsonl}}", "{{authNucleiCleanOutputJsonl}}", "template-id,info.name,info.severity,matched-at,matched-name")
      - sort_unix("{{authNucleiCleanOutputJsonl}}")
      - 'convert_jsonl_to_markdown("{{authNucleiCleanOutputJsonl}}", "{{authNucleiMarkdownReport}}")'
      - 'db_import_vuln_from_file("{{TargetSpace}}", "{{authNucleiOutputJsonl}}")'
    on_error:
      - action: continue
```

- [ ] **Step 2: Create authenticated injection module**

Create `common/auth-injection.yaml` with this content:

```yaml
kind: module
name: auth-injection
description: Run sqlmap and Dalfox with authenticated headers against private parameterized URLs
tags: auth, injection, sqli, xss, sqlmap, dalfox

params:
  - name: authParameterizedUrlsFile
    default: "{{Output}}/auth/parameterized-urls-{{TargetSpace}}.txt"
  - name: authContentUrlsFile
    default: "{{Output}}/auth/content-discovery-url-{{TargetSpace}}.txt"
  - name: authHeaderArgsFile
    default: "{{Output}}/auth/header-args-{{TargetSpace}}.txt"
  - name: authSqlmapHeadersFile
    default: "{{Output}}/auth/sqlmap-headers-{{TargetSpace}}.txt"
  - name: authInjectionDir
    default: "{{Output}}/vulnscan/auth-injection"
  - name: authInjectableFile
    default: "{{Output}}/vulnscan/auth-injection/injectable-urls-{{TargetSpace}}.txt"
  - name: authDalfoxInputFile
    default: "{{Output}}/vulnscan/auth-injection/injectable-urls-dalfox-{{TargetSpace}}.txt"
  - name: authSqlmapFindingsJsonl
    default: "{{Output}}/vulnscan/auth-injection/sqlmap-findings-{{TargetSpace}}.jsonl"
  - name: authDalfoxRawJsonl
    default: "{{Output}}/vulnscan/auth-injection/dalfox-raw-{{TargetSpace}}.jsonl"
  - name: authDalfoxFindingsJsonl
    default: "{{Output}}/vulnscan/auth-injection/dalfox-findings-{{TargetSpace}}.jsonl"
  - name: authInjectionFindingsJsonl
    default: "{{Output}}/vulnscan/auth-injection/injection-findings-{{TargetSpace}}.jsonl"
  - name: authInjectionCleanJsonl
    default: "{{Output}}/vulnscan/auth-injection/injection-findings-clean-{{TargetSpace}}.jsonl"
  - name: authInjectionMarkdownReport
    default: "{{Output}}/vulnscan/auth-injection/injection-findings-{{TargetSpace}}.md"
  - name: enableAuthScan
    type: bool
    default: false
  - name: enableDalfox
    type: bool
    default: true
  - name: authInjectionLimit
    default: "500"
  - name: sqlmapRisk
    default: "1"
  - name: sqlmapLevel
    default: "2"
  - name: injectionThreads
    default: "{{ threads }}"
  - name: sqlmapTimeout
    default: "2h"

dependencies:
  commands:
    - sqlmap
    - dalfox
    - python3
  variables:
    - name: Target
      type: string
      required: true

reports:
  - name: auth-injection-findings
    path: "{{authInjectionFindingsJsonl}}"
    type: jsonl
    description: Authenticated SQLi/XSS findings

steps:
  - name: create-auth-injection-folder
    type: function
    functions:
      - 'create_folder("{{authInjectionDir}}")'

  - name: build-auth-injectable-list
    type: bash
    log: "Building authenticated injectable URL list"
    pre_condition: '"{{enableAuthScan}}" == "true"'
    commands:
      - |
        {
          [ -f "{{authParameterizedUrlsFile}}" ] && cat "{{authParameterizedUrlsFile}}"
          [ -f "{{authContentUrlsFile}}" ] && grep '?' "{{authContentUrlsFile}}"
        } | grep '?' | sort -u | head -n {{authInjectionLimit}} > "{{authInjectableFile}}"
    on_error:
      - action: continue

  - name: sqlmap-auth-scan
    type: bash
    log: "Running sqlmap with authenticated headers"
    pre_condition: 'file_length("{{authInjectableFile}}") > 0 && file_length("{{authSqlmapHeadersFile}}") > 0'
    commands:
      - |
        timeout -k 1m {{sqlmapTimeout}} sqlmap -m "{{authInjectableFile}}" \
          --batch --random-agent \
          --headers="$(cat "{{authSqlmapHeadersFile}}")" \
          --level={{sqlmapLevel}} --risk={{sqlmapRisk}} \
          --threads={{injectionThreads}} \
          --output-dir="{{authInjectionDir}}/sqlmap" \
          --flush-session \
          2>&1 | tee "{{authInjectionDir}}/sqlmap-run.log" || true
        find "{{authInjectionDir}}/sqlmap" -name 'log' -exec cat {} \; > "{{authInjectionDir}}/sqlmap-summary.txt" 2>/dev/null || true
    on_error:
      - action: continue

  - name: normalize-auth-sqlmap-findings
    type: bash
    log: "Normalizing authenticated sqlmap findings"
    pre_condition: 'file_exists("{{authInjectionDir}}/sqlmap")'
    commands:
      - |
        python3 - "{{authInjectionDir}}/sqlmap" "{{authSqlmapFindingsJsonl}}" <<'PY'
        import csv, json, sys
        from pathlib import Path
        from urllib.parse import urlparse
        sqlmap_dir = Path(sys.argv[1])
        out = Path(sys.argv[2])
        rows = []
        for csv_path in sorted(sqlmap_dir.glob("results-*.csv")):
            with csv_path.open(newline="", encoding="utf-8", errors="replace") as handle:
                for row in csv.DictReader(handle):
                    url = row.get("Target URL") or row.get("TargetURL") or ""
                    if not url:
                        continue
                    rows.append({
                        "template-id": "auth-sqlmap-sqli",
                        "info": {"name": "SQL Injection (authenticated)", "severity": "critical", "tags": ["auth", "sqli", "sqlmap"]},
                        "type": "http",
                        "host": urlparse(url).hostname or "",
                        "url": url,
                        "matched-at": url,
                        "extracted-results": [json.dumps(row, ensure_ascii=False)[:1000]],
                    })
        out.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
        PY
    on_error:
      - action: continue

  - name: prepare-auth-dalfox-input
    type: function
    pre_condition: '{{enableDalfox}} && file_length("{{authInjectableFile}}") > 0'
    functions:
      - 'exec_cmd("cp {{authInjectableFile}} {{authDalfoxInputFile}}")'

  - name: dalfox-auth-scan
    type: bash
    log: "Running Dalfox with authenticated headers"
    pre_condition: '{{enableDalfox}} && file_length("{{authDalfoxInputFile}}") > 0 && file_length("{{authHeaderArgsFile}}") > 0'
    commands:
      - |
        dalfox file "{{authDalfoxInputFile}}" $(cat "{{authHeaderArgsFile}}") \
          --skip-bav --format jsonl \
          -o "{{authDalfoxRawJsonl}}" 2>&1 | tee "{{authInjectionDir}}/dalfox-console.log" || true
    on_error:
      - action: continue

  - name: normalize-auth-dalfox-findings
    type: bash
    pre_condition: 'file_length("{{authDalfoxRawJsonl}}") > 0'
    commands:
      - |
        python3 - "{{authDalfoxRawJsonl}}" "{{authDalfoxFindingsJsonl}}" <<'PY'
        import json, sys
        from pathlib import Path
        from urllib.parse import urlparse
        raw = Path(sys.argv[1])
        out = Path(sys.argv[2])
        rows = []
        for line in raw.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = row.get("data") or row.get("url") or row.get("poc") or ""
            if not url:
                continue
            rows.append({
                "template-id": "auth-dalfox-xss",
                "info": {"name": "Cross-Site Scripting (authenticated)", "severity": "high", "tags": ["auth", "xss", "dalfox"]},
                "type": "http",
                "host": urlparse(url).hostname or "",
                "url": url,
                "matched-at": url,
                "extracted-results": [json.dumps(row, ensure_ascii=False)[:1000]],
            })
        out.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
        PY
    on_error:
      - action: continue

  - name: merge-auth-injection-findings
    type: bash
    commands:
      - |
        {
          [ -f "{{authSqlmapFindingsJsonl}}" ] && cat "{{authSqlmapFindingsJsonl}}"
          [ -f "{{authDalfoxFindingsJsonl}}" ] && cat "{{authDalfoxFindingsJsonl}}"
        } | sort -u > "{{authInjectionFindingsJsonl}}"
    on_error:
      - action: continue

  - name: report-auth-injection-findings
    type: function
    pre_condition: 'file_length("{{authInjectionFindingsJsonl}}") > 0'
    functions:
      - jsonl_filter("{{authInjectionFindingsJsonl}}", "{{authInjectionCleanJsonl}}", "template-id,info.name,info.severity,matched-at,host,url,extracted-results")
      - 'convert_jsonl_to_markdown("{{authInjectionCleanJsonl}}", "{{authInjectionMarkdownReport}}")'
      - 'db_import_vuln_from_file("{{TargetSpace}}", "{{authInjectionFindingsJsonl}}")'
    on_error:
      - action: continue
```

- [ ] **Step 3: Lint both modules**

Run:

```bash
osmedeus workflow lint common/auth-vuln.yaml
osmedeus workflow lint common/auth-injection.yaml
```

Expected:

```text
✔ Workflow 'auth-vuln' (module) passed all lint checks
✔ Workflow 'auth-injection' (module) passed all lint checks
```

- [ ] **Step 4: Commit**

```bash
git add common/auth-vuln.yaml common/auth-injection.yaml
git commit -m "feat: add authenticated vuln and injection scans"
```

## Task 6: Add Auth-Only Flow and Wire LLM Flows

**Files:**
- Create: `auth-only.yaml`
- Modify: `domain-llm.yaml`
- Modify: `web-analysis-llm.yaml`
- Test: `osmedeus workflow lint auth-only.yaml`
- Test: `osmedeus workflow lint domain-llm.yaml`
- Test: `osmedeus workflow lint web-analysis-llm.yaml`

- [ ] **Step 1: Create `auth-only.yaml`**

Create `auth-only.yaml` with this content:

```yaml
kind: flow
name: auth-only
description: Authenticated-only web testing using existing workspace context or explicit auth scope
tags: auth, web, authenticated, llm
help:
  example_targets: ['example.com', 'https://app.example.com']
  usage: osmedeus run -f auth-only -t example.com -p 'enableAuthScan=true' -p 'authScope=https://app.example.com'

params:
  - name: enableAuthScan
    type: bool
    default: true
  - name: enableAuthDiscovery
    type: bool
    default: true
  - name: enableLLMAuthDiscovery
    type: bool
    default: true
  - name: enableLLMRecon
    type: bool
    default: true
  - name: enableAutonomousLLM
    type: bool
    default: true
  - name: authMode
    default: "manual"
  - name: useAuthConfigProposal
    type: bool
    default: false
  - name: enableAutoRegister
    type: bool
    default: false

dependencies:
  variables:
    - name: Target
      type: string
      required: true

modules:
  - name: auth-discovery
    path: common/auth-discovery.yaml

  - name: auth-browser-login
    path: common/auth-browser-login.yaml
    depends_on:
      - auth-discovery

  - name: auth-session
    path: common/auth-session.yaml
    depends_on:
      - auth-discovery
      - auth-browser-login

  - name: auth-spider
    path: common/auth-spider.yaml
    depends_on:
      - auth-session

  - name: auth-content
    path: common/auth-content.yaml
    depends_on:
      - auth-session

  - name: auth-vuln
    path: common/auth-vuln.yaml
    depends_on:
      - auth-spider
      - auth-content

  - name: auth-injection
    path: common/auth-injection.yaml
    depends_on:
      - auth-spider
      - auth-content

  - name: llm-surface-analysis
    path: common/llm-surface-analysis.yaml
    depends_on:
      - auth-vuln
      - auth-injection

  - name: llm-autonomous-controller
    path: common/llm-autonomous-controller.yaml
    depends_on:
      - llm-surface-analysis
      - auth-vuln
      - auth-injection
```

- [ ] **Step 2: Modify `domain-llm.yaml` params**

Add these params after `enableAutonomousLLM`:

```yaml
  - name: enableAuthScan
    type: bool
    default: false
  - name: enableAuthDiscovery
    type: bool
    default: true
  - name: enableLLMAuthDiscovery
    type: bool
    default: true
  - name: authMode
    default: "manual"
  - name: useAuthConfigProposal
    type: bool
    default: false
  - name: enableAutoRegister
    type: bool
    default: false
```

- [ ] **Step 3: Modify `domain-llm.yaml` modules**

Insert these modules after `scan-injection` and before `llm-autonomous-controller`:

```yaml
  # ===========================================================================
  # Phase 17: Authentication Surface Discovery
  # ===========================================================================
  - name: auth-discovery
    path: common/auth-discovery.yaml
    depends_on:
      - scan-injection

  # ===========================================================================
  # Phase 18: Optional Browser Authentication Capture
  # ===========================================================================
  - name: auth-browser-login
    path: common/auth-browser-login.yaml
    depends_on:
      - auth-discovery

  # ===========================================================================
  # Phase 19: Authenticated Session Normalization
  # ===========================================================================
  - name: auth-session
    path: common/auth-session.yaml
    depends_on:
      - auth-discovery
      - auth-browser-login

  # ===========================================================================
  # Phase 20: Authenticated Spidering
  # ===========================================================================
  - name: auth-spider
    path: common/auth-spider.yaml
    depends_on:
      - auth-session

  # ===========================================================================
  # Phase 21: Authenticated Content Discovery
  # ===========================================================================
  - name: auth-content
    path: common/auth-content.yaml
    depends_on:
      - auth-session

  # ===========================================================================
  # Phase 22: Authenticated Vulnerability Scanning
  # ===========================================================================
  - name: auth-vuln
    path: common/auth-vuln.yaml
    depends_on:
      - auth-spider
      - auth-content

  # ===========================================================================
  # Phase 23: Authenticated Injection Scanning
  # ===========================================================================
  - name: auth-injection
    path: common/auth-injection.yaml
    depends_on:
      - auth-spider
      - auth-content
```

Change `llm-autonomous-controller.depends_on` to include auth modules:

```yaml
    depends_on:
      - scan-vuln
      - scan-vuln-thorough
      - scan-injection
      - auth-vuln
      - auth-injection
```

- [ ] **Step 4: Modify `web-analysis-llm.yaml` params and modules**

Add the same auth params after `enableAutonomousLLM`, then insert auth modules after `do-scan-injection` and before `llm-autonomous-controller`:

```yaml
  - name: auth-discovery
    path: common/auth-discovery.yaml
    depends_on:
      - do-scan-injection

  - name: auth-browser-login
    path: common/auth-browser-login.yaml
    depends_on:
      - auth-discovery

  - name: auth-session
    path: common/auth-session.yaml
    depends_on:
      - auth-discovery
      - auth-browser-login

  - name: auth-spider
    path: common/auth-spider.yaml
    depends_on:
      - auth-session

  - name: auth-content
    path: common/auth-content.yaml
    depends_on:
      - auth-session

  - name: auth-vuln
    path: common/auth-vuln.yaml
    depends_on:
      - auth-spider
      - auth-content

  - name: auth-injection
    path: common/auth-injection.yaml
    depends_on:
      - auth-spider
      - auth-content
```

Change `llm-autonomous-controller.depends_on` to:

```yaml
    depends_on:
      - do-scan-vuln
      - do-scan-vuln-thorough
      - do-scan-injection
      - auth-vuln
      - auth-injection
```

- [ ] **Step 5: Lint flows**

Run:

```bash
osmedeus workflow lint auth-only.yaml
osmedeus workflow lint domain-llm.yaml
osmedeus workflow lint web-analysis-llm.yaml
```

Expected:

```text
✔ Workflow 'auth-only' (flow) passed all lint checks
✔ Workflow 'domain-llm' (flow) passed all lint checks
✔ Workflow 'web-analysis-llm' (flow) passed all lint checks
```

- [ ] **Step 6: Dry-run auth-only**

Run:

```bash
osmedeus run -f ./auth-only.yaml -t example.com \
  -p 'enableAuthScan=true' \
  -p 'authMode=manual' \
  -p 'authScope=https://app.example.com' \
  -p 'authHeader=Authorization: Bearer test' \
  --dry-run
```

Expected: module list contains only `auth-*`, `llm-surface-analysis`, and `llm-autonomous-controller`. It must not contain `enum-subdomain`, `probe-dns`, `recon-http-fp`, `scan-vuln`, or `scan-injection`.

- [ ] **Step 7: Commit**

```bash
git add auth-only.yaml domain-llm.yaml web-analysis-llm.yaml
git commit -m "feat: wire authenticated scan flows"
```

## Task 7: Feed Auth Artifacts into LLM Context and Autonomous Metrics

**Files:**
- Modify: `common/llm-surface-analysis.yaml`
- Modify: `common/llm-autonomous-controller.yaml`
- Test: `osmedeus workflow lint common/llm-surface-analysis.yaml`
- Test: `osmedeus workflow lint common/llm-autonomous-controller.yaml`

- [ ] **Step 1: Add auth params to `common/llm-surface-analysis.yaml`**

Add these params after existing related-domain auth-adjacent params:

```yaml
  - name: authSessionReport
    default: "{{Output}}/auth/session-report-{{TargetSpace}}.md"
  - name: authScopeFile
    default: "{{Output}}/auth/scope-{{TargetSpace}}.txt"
  - name: authPlanFile
    default: "{{Output}}/auth/auth-plan-{{TargetSpace}}.md"
  - name: authConfigProposalFile
    default: "{{Output}}/auth/auth-config-proposal-{{TargetSpace}}.yaml"
  - name: authLinksFile
    default: "{{Output}}/auth/links-{{TargetSpace}}.txt"
  - name: authContentRecordsFile
    default: "{{Output}}/auth/content-records-{{TargetSpace}}.jsonl"
  - name: authNucleiOutputJsonl
    default: "{{Output}}/vulnscan/auth/nuclei-jsonl-{{TargetSpace}}.txt"
  - name: authInjectionFindingsJsonl
    default: "{{Output}}/vulnscan/auth-injection/injection-findings-{{TargetSpace}}.jsonl"
```

- [ ] **Step 2: Add auth files to `prepare-agent-context` command**

Append these arguments to the Python command file list:

```yaml
          "{{authSessionReport}}" "{{authScopeFile}}" "{{authPlanFile}}" "{{authConfigProposalFile}}" \
          "{{authLinksFile}}" "{{authContentRecordsFile}}" "{{authNucleiOutputJsonl}}" "{{authInjectionFindingsJsonl}}" <<'PY'
```

Expected behavior: context includes auth reports and findings when present. It must not include `authSessionFile`, `authHeaderFile`, `authCookieFile`, `authHeaderArgsFile`, or `authSqlmapHeadersFile`.

- [ ] **Step 3: Add auth metrics params to `common/llm-autonomous-controller.yaml`**

Add these params after existing entity/service params:

```yaml
  - name: authScopeFile
    default: "{{Output}}/auth/scope-{{TargetSpace}}.txt"
  - name: authLinksFile
    default: "{{Output}}/auth/links-{{TargetSpace}}.txt"
  - name: authParameterizedUrlsFile
    default: "{{Output}}/auth/parameterized-urls-{{TargetSpace}}.txt"
  - name: authNucleiOutputJsonl
    default: "{{Output}}/vulnscan/auth/nuclei-jsonl-{{TargetSpace}}.txt"
  - name: authInjectionFindingsJsonl
    default: "{{Output}}/vulnscan/auth-injection/injection-findings-{{TargetSpace}}.jsonl"
```

- [ ] **Step 4: Add auth metrics labels and paths**

Append these paths to the `build-autonomous-metrics` command:

```yaml
          "{{authScopeFile}}" "{{authLinksFile}}" "{{authParameterizedUrlsFile}}" \
          "{{authNucleiOutputJsonl}}" "{{authInjectionFindingsJsonl}}" <<'PY'
```

Append these labels to the Python `labels` list:

```python
            "auth_scope",
            "auth_links",
            "auth_parameterized_urls",
            "auth_nuclei_findings",
            "auth_injection_findings",
```

- [ ] **Step 5: Update controller allowlist in prompt**

In `common/llm-autonomous-controller.yaml`, add auth modules to the allowed module list:

```text
      - auth-discovery
      - auth-spider
      - auth-content
      - auth-vuln
      - auth-injection
```

Add this sentence to the controller system prompt:

```text
      Never run auth modules unless auth_scope has at least one line and enableAuthScan is true in the current flow params.
```

- [ ] **Step 6: Lint both modules**

Run:

```bash
osmedeus workflow lint common/llm-surface-analysis.yaml
osmedeus workflow lint common/llm-autonomous-controller.yaml
```

Expected:

```text
✔ Workflow 'llm-surface-analysis' (module) passed all lint checks
✔ Workflow 'llm-autonomous-controller' (module) passed all lint checks
```

- [ ] **Step 7: Commit**

```bash
git add common/llm-surface-analysis.yaml common/llm-autonomous-controller.yaml
git commit -m "feat: expose auth artifacts to llm controller"
```

## Task 8: Documentation and Final Verification

**Files:**
- Modify: `README.md`
- Test: all auth lint commands
- Test: auth-only and LLM flow dry-runs

- [ ] **Step 1: Update README module table**

Add these rows to the common modules table:

```markdown
| `auth-discovery.yaml` | Detects login/register/session-check surfaces and writes LLM-assisted auth config proposals |
| `auth-session.yaml` | Normalizes manual/form/API/browser authentication into reusable plaintext session artifacts |
| `auth-browser-login.yaml` | Optional Playwright-based login capture for JS-heavy applications |
| `auth-spider.yaml` | Authenticated crawling against explicit auth scope |
| `auth-content.yaml` | Authenticated content discovery against explicit auth scope |
| `auth-vuln.yaml` | Authenticated nuclei scan with preserved headers/cookies |
| `auth-injection.yaml` | Authenticated sqlmap/Dalfox scan for private parameterized URLs |
```

- [ ] **Step 2: Update README flow table**

Add this row:

```markdown
| `auth-only.yaml` | Authenticated-only testing for an existing workspace or explicit private scope |
```

- [ ] **Step 3: Add README usage examples**

Add this section near LLM workflow examples:

````markdown
### Authenticated scanning

Run only authenticated tests when public recon already exists:

```bash
osmedeus run -f auth-only -t example.com \
  -p 'enableAuthScan=true' \
  -p 'authMode=manual' \
  -p 'authScope=https://app.example.com' \
  -p 'authHeaderFile=/path/to/headers.txt'
```

Run LLM-guided recon plus an authenticated second pass:

```bash
osmedeus run -f domain-llm -t example.com \
  -p 'enableAuthScan=true' \
  -p 'authMode=api' \
  -p 'authScope=https://api.example.com' \
  -p 'authLoginUrl=https://api.example.com/login' \
  -p 'authApiLoginBody={"username":"demo","password":"demo"}' \
  -p 'authTokenJsonPath=.token'
```

Use LLM auth discovery only as a reviewed config proposal:

```bash
osmedeus run -f auth-only -t example.com \
  -p 'enableAuthScan=true' \
  -p 'enableAuthDiscovery=true' \
  -p 'enableLLMAuthDiscovery=true' \
  -p 'useAuthConfigProposal=true' \
  -p 'authMode=form' \
  -p 'authScope=https://app.example.com' \
  -p 'authUsername=demo' \
  -p 'authPassword=demo'
```
````

- [ ] **Step 4: Run all lint checks**

Run:

```bash
osmedeus workflow lint common/auth-session.yaml
osmedeus workflow lint common/auth-discovery.yaml
osmedeus workflow lint common/auth-browser-login.yaml
osmedeus workflow lint common/auth-spider.yaml
osmedeus workflow lint common/auth-content.yaml
osmedeus workflow lint common/auth-vuln.yaml
osmedeus workflow lint common/auth-injection.yaml
osmedeus workflow lint auth-only.yaml
osmedeus workflow lint domain-llm.yaml
osmedeus workflow lint web-analysis-llm.yaml
osmedeus workflow lint common/llm-surface-analysis.yaml
osmedeus workflow lint common/llm-autonomous-controller.yaml
```

Expected: every command exits `0` and prints a pass message.

- [ ] **Step 5: Run auth-only dry-run**

Run:

```bash
osmedeus run -f ./auth-only.yaml -t example.com \
  -p 'enableAuthScan=true' \
  -p 'authMode=manual' \
  -p 'authScope=https://app.example.com' \
  -p 'authHeader=Authorization: Bearer test' \
  --dry-run
```

Expected module summary includes:

```text
auth-discovery
auth-browser-login
auth-session
auth-spider
auth-content
auth-vuln
auth-injection
llm-surface-analysis
llm-autonomous-controller
```

Expected module summary does not include:

```text
enum-subdomain
probe-dns
recon-http-fp
scan-vuln
scan-injection
```

- [ ] **Step 6: Run domain LLM dry-run with auth enabled**

Run:

```bash
osmedeus run -f ./domain-llm.yaml -t example.com \
  -p 'enableAuthScan=true' \
  -p 'authMode=manual' \
  -p 'authScope=https://app.example.com' \
  -p 'authHeader=Authorization: Bearer test' \
  --dry-run
```

Expected: public modules render first, then `auth-discovery`, `auth-session`, `auth-spider`, `auth-content`, `auth-vuln`, `auth-injection`, then controller.

- [ ] **Step 7: Run web-analysis LLM dry-run with auth enabled**

Run:

```bash
osmedeus run -f ./web-analysis-llm.yaml -t https://app.example.com \
  -p 'enableAuthScan=true' \
  -p 'authMode=manual' \
  -p 'authScope=https://app.example.com' \
  -p 'authHeader=Authorization: Bearer test' \
  --dry-run
```

Expected: URL-focused modules render first, then the auth modules and controller.

- [ ] **Step 8: Commit docs**

```bash
git add README.md
git commit -m "docs: document authenticated scanning workflows"
```

## Task 9: Post-Implementation Review Checklist

**Files:**
- Review: all files changed in Tasks 1-8

- [ ] **Step 1: Search for raw secret exposure in LLM context**

Run:

```bash
rg -n "authSessionFile|authHeaderFile|authCookieFile|authHeaderArgsFile|authSqlmapHeadersFile" common/llm-surface-analysis.yaml common/llm-autonomous-controller.yaml
```

Expected: no matches in `prepare-agent-context` file arguments. Matches in param declarations are acceptable only if those params are not passed into LLM context.

- [ ] **Step 2: Search for auth modules writing baseline artifact paths**

Run:

```bash
rg -n "probing/http-|links/links-|content-discovery/content-discovery-url-|vulnscan/nuclei-jsonl-|vulnscan/injection/injection-findings-" common/auth-*.yaml
```

Expected: no matches. Auth modules must write under `auth/`, `vulnscan/auth/`, or `vulnscan/auth-injection/`.

- [ ] **Step 3: Search for accidental auto-register defaults**

Run:

```bash
rg -n "enableAutoRegister|registerScope|captcha|mfa" common/auth-*.yaml docs/superpowers/specs/2026-07-05-authenticated-web-scan-design.md
```

Expected:

```text
enableAutoRegister default: false
registerScope default: ""
No CAPTCHA/MFA bypass behavior implemented
```

- [ ] **Step 4: Final status**

Run:

```bash
git status --short
```

Expected: only intentional untracked local files remain, such as `.codex/` or `.gortex/`; no partially staged implementation files.
