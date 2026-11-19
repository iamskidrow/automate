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

| Knob | Meaning (applied to every tool) |
|------|------|
| `THREADS` | worker threads |
| `CONCURRENCY` | parallel hosts / fetchers |
| `RATE` | requests per second |
| `HTTP_TIMEOUT` | per-request timeout |
| `TIMEOUT` | wall-clock cap per tool |
| `MAX_URLS` / `MAX_PARAMS` / `MAX_DNS` / `FUZZ_WORDS` | scope budgets (0 = unlimited) |
| `NUCLEI_TAGS` / `NUCLEI_SEVERITY` | Nuclei coverage |

## Layout

```
automate.sh       orchestrator (arg parse, scope, stage pipeline)
config.sh         central configuration
lib/core.sh       logging, scope/IP validation, tool supervisor, selection, stages
lib/discover.sh   subdomains, permutations, DNS, live hosts
lib/collect.sh    historical URLs, crawl, JS, inventory, parameters
lib/enrich.sh     tech, TLS, headers, infra, ports, services, screenshots
lib/scan.sh       WAF, CORS, takeover, CRLF, hidden params, gf triage, Nuclei, XSS, SQLi, fuzz, CVE
lib/report.sh     summary.txt / findings.json / findings.csv / report.html
install.sh        one-time dependency setup (APT + Go + gf patterns + Nuclei templates)
```

## Output

`~/Automate/<domain>/<UTC>/` — `reports/` (summary, findings, html), `results/`* inventories,
`raw/` per-tool output, `logs/` per-tool stderr, `stages.tsv`, `commands.tsv`.

Scanner results are candidates until manually validated; skipped/partial stages are not a clean bill of health.
