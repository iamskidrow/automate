# automate

Unattended, modular web-assessment runner for authorized targets (clients / bug-bounty scope).

## Usage

```bash
./automate.sh target.com          # single host: full tool chain against that one host
./automate.sh target.com --full   # host + every discovered subdomain / resolved asset
./automate.sh --check             # verify tools
./automate.sh --config my.sh target.com --full   # load local overrides
```

All tools run in both modes; `--full` only widens the scope. There is no authorization flag —
point it only at assets you are authorized to test.

## Configuration

One file, `config.sh`, holds every knob. Override per run from the environment:

```bash
THREADS=100 CONCURRENCY=50 RATE=200 TIMEOUT=2400 MAX_URLS=0 ./automate.sh target.com --full
```

| Knob | Applied to every tool |
|------|------|
| `THREADS` | worker threads |
| `CONCURRENCY` | parallel hosts / fetchers |
| `RATE` | requests per second |
| `HTTP_TIMEOUT` | per-request timeout |
| `TIMEOUT` | wall-clock cap per tool |
| `MAX_URLS` / `MAX_PARAMS` / `MAX_DNS` / `FUZZ_WORDS` | scope budgets (0 = unlimited) |
| `NUCLEI_TAGS` / `NUCLEI_SEVERITY` | Nuclei coverage |
| `UA` | browser User-Agent for content fetches (default curl UA is often WAF-blocked) |

Set `WPSCAN_API_TOKEN` (free tier at wpscan.com) for vulnerable-plugin/theme lookups; without it,
wpscan still enumerates plugins, themes and users.

## Pipeline

discover (subfinder/assetfinder → alterx → dnsx → httpx) → collect (waymore, katana, jsluice,
trufflehog) → enrich (httpx/whatweb, tlsx/testssl, headers, cdncheck, naabu→nmap, gowitness) →
active (wafw00f, cors, nuclei takeover, crlfuzz, gf triage, nuclei templates, nuclei `-dast`,
dalfox, sqlmap, ffuf, wpscan, cloud_enum/s3scanner, vulnx) → anew diff → report.

Scanners are targeted: gf triage feeds likely-vulnerable params to dalfox/sqlmap, wpscan runs only
on detected WordPress, cloud runs only in `--full`, and each stage skips cleanly when it has no input.

## Output

```
~/Automate/<domain>/<timestamp>/
  REPORT.html             open this
  summary.txt
  findings.json / .csv    normalized Nuclei + DAST candidates
  assets/                 subdomains, hosts-live, urls, params, ports, tech, new-*
  vulns/                  only non-empty: nuclei, xss, crlf, takeover, wpscan, secrets, cloud, sqli, cors
  hygiene/                headers.tsv, waf.txt, tls-issues.txt
  screenshots/
  .evidence/              raw tool output + logs (hidden); nothing duplicated or empty surfaces above
```

`assets/new-*.txt` list what is new since the last run (anew diff against `~/Automate/<domain>/.known/`).
Empty files and empty category folders are pruned. Scanner results are candidates until manually
validated; partial/skipped stages are not a clean bill of health.

## Layout

```
automate.sh   orchestrator        config.sh   central config
lib/core.sh   helpers, scope/IP, tool supervisor, selection, stages
lib/discover.sh  subdomains, permutations, DNS, live hosts
lib/collect.sh   waymore, katana, jsluice, trufflehog, inventory, parameters
lib/enrich.sh    tech, TLS, headers, infra, ports, services, screenshots
lib/scan.sh      waf, cors, takeover, crlf, gf triage, nuclei, dast, xss, sqli, fuzz, wordpress, cloud, vulnx
lib/report.sh    anew diff + curate .evidence into the clean tree
install.sh    one-time dependency setup (APT + Go + pipx + gf patterns + Nuclei/WPScan DB)
```

Optional, not auto-installed: **x8** (needs Rust: `cargo install x8`) is preferred over arjun for hidden
parameters; **dnsReaper** (`pipx install git+https://github.com/punk-security/dnsReaper`) adds takeover
signatures. Both are used automatically if present; otherwise arjun and Nuclei's takeover templates cover them.
