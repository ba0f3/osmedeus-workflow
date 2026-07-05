# Vigolium Workflow Guide

## Why This Exists

Vigolium can replace a lot of legacy web testing glue, but only when the workflow gives it the right inputs and enough scan context.

The weak pattern is:

```text
root URL -> vigolium scan balanced
```

That often misses real SQLi/XSS because the vulnerable surface lives behind crawled routes, forms, or parameterized URLs.

The stronger pattern is:

```text
root URLs -> spider/discover/deep scan
parameterized URLs -> injection-focused Vigolium pass
```

## Current Workflow Usage

The repository uses Vigolium in four places:

1. `recon-spider`
   Browser crawling through Vigolium spidering.

2. `scan-content`
   Content discovery through Vigolium discover mode.

3. `scan-vuln-thorough`
   Deep native Vigolium scan with spidering, discovery, follow-subdomain support, and a focused host/framework sweep enabled by default.

4. `scan-injection`
   Injection-focused Vigolium pass over `vulnscan/injectable-urls-*.txt`.

## v0.2.0 Capabilities To Leverage

Vigolium `v0.2.0` adds or expands these families:

- GraphQL security scanning
- Adobe Experience Manager checks
- Salesforce, ServiceNow, and Power Pages exposure checks
- IIS short-name and IIS bypass checks
- MCP checks
- dependency-confusion passive detection
- JavaScript beautification for better passive analysis
- response-aware form filling
- common credential login spray on confirmed login forms
- SQLite import/merge and replay improvements

Most of these families are tech-gated inside Vigolium, so the workflow should give Vigolium enough discovery and traffic context rather than trying to guess every technology in YAML.

## Recommended Defaults

For thorough web vulnerability scanning:

```yaml
vigoliumStrategy: deep
vigoliumIntensity: deep
enableVigoliumDiscover: true
enableVigoliumSpider: true
enableVigoliumFollowSubdomains: true
enableVigoliumKnownIssueScan: false
enableVigoliumFocusedHostSweep: true
vigoliumFocusedHostTags: mcp,api-security,auth-bypass,cloud,cache-poisoning,request-smuggling,aspnet,nextjs,spring,java,php,python,javascript,cms,info-disclosure,misconfiguration,ssrf,rce
```

`enableVigoliumKnownIssueScan` is false by default because Osmedeus already runs nuclei separately. Turn it on when testing whether Vigolium can replace that legacy path.

For injection-focused scanning:

```yaml
enableVigoliumInjection: true
vigoliumInjectionStrategy: deep
vigoliumInjectionIntensity: deep
enableVigoliumInjectionNoTechFilter: true
vigoliumInjectionModuleTags: injection,sqli,xss,graphql,lfi,ssrf,ssti,rce,command-injection,xxe,prototype-pollution,api,api-security,auth-bypass,idor,csrf,open-redirect,jwt,websocket
```

This makes Vigolium scan the same parameterized URL set used by sqlmap and Dalfox, but with broader dynamic module coverage.

## Module Groups Worth Calling Out

The local module registry exposes these high-value families:

- Injection: SQLi, NoSQLi, XSS, SSTI, LFI, SSRF, XXE, command injection, prototype pollution, LDAP injection, file upload, mass assignment.
- API and auth: GraphQL, Swagger/OpenAPI discovery, API key exposure, BFLA, IDOR/BOLA, JWT, OAuth/OIDC, CSRF, default credentials.
- Host and platform: MCP, cloud storage, subdomain takeover, request smuggling, cache poisoning, IIS shortname, TLS cert recon.
- Frameworks: ASP.NET/IIS, Next.js, Spring/Java, PHP/Laravel/Symfony/Magento, Django/FastAPI/Flask, Rails, WordPress/Drupal/Joomla, Express/Node.js.

Those groups are intentionally split:

- Host/root modules run in `scan-vuln-thorough`.
- Parameter/request modules run in `scan-injection`.

## Useful Overrides

Run all tech-gated modules more aggressively:

```bash
-p 'enableVigoliumNoTechFilter=true'
```

Include Vigolium's known issue phase:

```bash
-p 'enableVigoliumKnownIssueScan=true'
```

Focus on specific module families in the injection pass:

```bash
-p 'vigoliumInjectionModuleTags=sqli,xss,graphql,lfi,ssrf,ssti,rce'
```

Focus the host/framework sweep:

```bash
-p 'vigoliumFocusedHostTags=mcp,cloud,request-smuggling,cache-poisoning,aspnet,nextjs,spring'
```

Disable the focused host sweep when time is tight:

```bash
-p 'enableVigoliumFocusedHostSweep=false'
```

Pass raw Vigolium flags for new releases:

```bash
-p 'extraVigoliumScan=--module-tag aem --module-tag salesforce --module-tag iis'
-p 'extraVigoliumInjection=--module-tag injection --module-tag graphql'
```

## Testasp Example

For `testasp.vulnweb.com`, the important thing is not only scanning the root.

Run a flow that produces parameterized URLs first:

```bash
osmedeus run -f domain-extensive -t testasp.vulnweb.com
```

Then inspect:

```text
vulnscan/injectable-urls-vulnweb.com.txt
vulnscan/injection/vigolium-injection-vulnweb.com.jsonl
vulnscan/injection/vigolium-findings-vulnweb.com.jsonl
vulnscan/injection/injection-findings-vulnweb.com.jsonl
```

If SQLi is still missed, raise the injection pass first:

```bash
osmedeus run -m ./common/scan-injection.yaml -t testasp.vulnweb.com \
  -p 'enableVigoliumInjection=true' \
  -p 'vigoliumInjectionStrategy=deep' \
  -p 'vigoliumInjectionIntensity=deep' \
  -p 'vigoliumInjectionModuleTags=injection,sqli,xss,graphql,lfi,ssrf,ssti,rce,command-injection,xxe,prototype-pollution' \
  -p 'extraVigoliumInjection=--no-tech-filter'
```

## Verification Checklist

1. Confirm the installed binary is `v0.2.0` or newer with `vigolium version`.
2. Confirm `scan-injection` has non-empty `injectable-urls-*.txt`.
3. Confirm Vigolium writes `vigolium-injection-*.jsonl`.
4. Confirm normalized findings merge into `injection-findings-*.jsonl`.
5. Compare Vigolium findings against sqlmap and Dalfox before removing legacy tools.
