# LLM Workflow Guide for Osmedeus

## Purpose

This guide describes how to add LLM-assisted workflows to Osmedeus without turning the pipeline into a duplicate scanner stack.

The goal is to use the LLM for what it does well:

- infer missed routes, parameters, and hidden surfaces from recon artifacts
- classify and prioritize follow-up targets
- combine signals across HTTP, service, and entity discovery
- tune scan parameters within bounded limits

The LLM should not replace the baseline scanners. It should widen and sharpen their input.

## Core Pattern

The recommended pattern is:

1. Collect deterministic recon artifacts.
2. Build a bounded artifact context for the LLM.
3. Ask the LLM to produce concrete follow-up artifacts.
4. Normalize those outputs into scanner-friendly files.
5. Feed the new inputs back into the normal scanners.
6. Stop when the marginal gain flattens.

In practice, that means:

- `llm-surface-analysis` reads recon artifacts and writes candidate files.
- `llm-guided-surface-scan` probes LLM-suggested surfaces and merges live URLs back into the normal link and HTTP files.
- `llm-autonomous-controller` can rerun allowlisted modules when there is enough evidence to justify another pass.

## What The LLM Should Do

Use the LLM for these tasks:

- identify route families from titles, tech fingerprints, status codes, and link patterns
- infer likely admin, auth, API, upload, search, and debug paths
- suggest parameterized URLs worth testing with injection tools
- notice entity clues from certificates, RDAP, and CNAME-linked properties
- recommend tighter scan parameters, but only inside a bounded loop
- propose nuclei follow-up categories from observed evidence

## What The LLM Should Not Do

Do not use the LLM as a second copy of nuclei, sqlmap, or dalfox.

Avoid these anti-patterns:

- running the same scanner twice on almost the same input
- generating output files that nothing consumes
- serializing the whole flow so heavily that wall-clock time doubles without a real gain
- expanding scope silently into related domains without an explicit opt-in
- allowing unbounded input sizes into the agent context

## Recommended Module Set

### `common/llm-surface-analysis.yaml`

This module is the discovery brain.

Inputs:

- `probing/http-*.txt`
- `fingerprint/http-fingerprint-*.jsonl`
- `links/links-*.txt`
- `content-discovery/*`
- `vulnscan/*`
- `services/services-*.jsonl`
- `entity/entity-profile-*.json`
- `entity/related-root-domains-*.txt`

Outputs:

- `llm/surface-candidates-*.txt`
- `llm/route-candidates-*.txt`
- `llm/parameter-candidates-*.txt`
- `llm/nuclei-followup-*.md`
- `llm/surface-analysis-*.md`

Use it to produce concrete, in-scope follow-up artifacts.

## Examples

### 1. Domain flow that uses the LLM to widen coverage

```yaml
modules:
  - name: enum-subdomain
    path: common/enum-subdomain.yaml

  - name: probe-dns
    path: common/probe-dns.yaml
    depends_on: [enum-subdomain]

  - name: enum-entity
    path: common/enum-entity.yaml
    depends_on: [probe-dns]

  - name: recon-http-fp
    path: common/recon-http-fp.yaml
    depends_on: [probe-dns]

  - name: scan-content
    path: common/scan-content.yaml
    depends_on: [recon-http-fp]

  - name: llm-surface-analysis
    path: common/llm-surface-analysis.yaml
    depends_on: [recon-spider, scan-content, scan-service, enum-entity]

  - name: llm-guided-surface-scan
    path: common/llm-guided-surface-scan.yaml
    depends_on: [llm-surface-analysis]
```

This pattern keeps the baseline scanners in place and lets the LLM improve what gets scanned next.

### 2. LLM surface analysis that writes useful outputs

```yaml
steps:
  - name: analyze-surfaces-with-agent
    type: agent
    query: |
      Analyze {{llmDir}}/context-{{TargetSpace}}.md and write:
      - {{llmSurfaceCandidatesFile}}
      - {{llmRouteCandidatesFile}}
      - {{llmParameterCandidatesFile}}
      - {{llmNucleiFollowupFile}}
```

The important part is that every file has a downstream consumer. If a file is only written and never read, it is overhead.

### 3. Bounded autonomous loop

```yaml
params:
  - name: enableAutonomousLLM
    type: bool
    default: true
  - name: autonomousMaxRounds
    default: "2"
  - name: autonomousMaxExtraMinutes
    default: "180"

steps:
  - name: autonomous-agent-control-loop
    type: agent
    pre_condition: '"{{enableAutonomousLLM}}" == "true"'
    max_iterations: 10
```

Keep the loop capped. The point is to tighten the next pass, not to run forever.

### `common/llm-guided-surface-scan.yaml`

This module should take the LLM outputs and turn them into real coverage.

Recommended behavior:

- probe candidate URLs with `pd-httpx`
- crawl live LLM-suggested surfaces with `katana`
- merge new live URLs back into `httpFile`
- merge discovered links back into `linkFile`
- feed parameterized URLs into `llmParameterCandidatesFile`
- optionally convert route candidates into URLs against known HTTP roots

This is the module that makes LLM output operational.

### `common/enum-entity.yaml`

This module adds related-entity discovery that is not HTTP-only.

It should gather:

- certificate siblings
- RDAP entity hints
- CNAME-linked properties
- optional related-domain subdomains and HTTP surfaces

Use it to expand the analyst’s view of the target organization, not to secretly widen scope.

### `common/scan-service.yaml`

This module audits non-HTTP services.

It exists because recon that only looks at ports 80 and 443 misses:

- SSH
- FTP
- SMTP
- IMAP
- POP3
- SMB
- RDP
- LDAP
- databases and caches

Keep it in the standard domain flow so the LLM can reason over services as well as web assets.

### `common/llm-autonomous-controller.yaml`

This module is for bounded iterative tuning.

Use it only when:

- there is enough artifact signal to justify another pass
- the module allowlist is narrow
- max rounds and max extra minutes are capped
- the controller can write a report even if it stops early

The controller should tune and rerun, not loop forever.

## Flow Wiring

### Domain Flow

For domain targets, the recommended order is:

1. `enum-subdomain`
2. `probe-dns`
3. `enum-entity`
4. `recon-http-fp`
5. `recon-spider`
6. `scan-content`
7. `scan-service`
8. `llm-surface-analysis`
9. `llm-guided-surface-scan`
10. `scan-vuln`
11. `scan-vuln-thorough`
12. `scan-injection`
13. `llm-autonomous-controller`

This keeps the LLM in the middle where it can improve later scans without replacing baseline coverage.

### Web Flow

For single URL analysis, keep the same idea:

1. recon and spider the URL
2. run content discovery
3. audit services if relevant
4. run `llm-surface-analysis`
5. run `llm-guided-surface-scan`
6. feed the normal vuln and injection scanners
7. let the autonomous controller decide whether another pass is worthwhile

## Guardrails

### Scope

Only scan what is in scope.

Related-domain artifacts are discovery intelligence by default. They should not widen the main target unless the user explicitly enables that behavior.

### Input Budget

Limit the LLM context.

Use both:

- a per-file line cap
- a global character budget

This prevents a large workspace from dumping everything into a single agent call.

### Output Budget

The agent should write a small number of concrete files, not a pile of speculative notes.

Prefer files that downstream modules can actually consume.

### Iteration Cap

The autonomous loop must have:

- a maximum round count
- a maximum extra runtime
- a clear stop reason
- a fallback report if the agent does not write one itself

## Good Outputs

Good LLM outputs are:

- absolute URLs that can be probed immediately
- route candidates that can be turned into a wordlist
- parameterized URLs that can be passed into sqlmap or dalfox
- nuclei follow-up categories with evidence
- agent reports that explain why another round is or is not justified

Bad outputs are vague notes like:

- “investigate more”
- “possible hidden endpoints”
- “check for auth issues”

Those are too abstract to feed back into the pipeline.

## Verification Checklist

When adding a new LLM workflow or module, check the following:

1. Every new param used in a template has a module default.
2. Every output file has a consumer.
3. LLM output is converted into scanner input before the scan runs.
4. The flow still passes `osmedeus workflow lint`.
5. A dry-run shows the new module in the expected place.
6. The autonomous loop has a cap and a fallback report.
7. Related-domain discovery is explicitly opt-in when it widens scope.

## Practical Rule

If a module does not change what the baseline scanners see, it is probably not worth keeping.

The best LLM modules in this repository do one of three things:

- add coverage
- reduce wasted scans
- improve target selection for the next pass

Anything else is noise.
