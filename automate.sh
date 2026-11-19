#!/usr/bin/env bash
# Automate — modular, unattended web-assessment runner.
#   ./automate.sh target.com          single host only
#   ./automate.sh target.com --full   host + all discovered subdomains/assets
#   ./automate.sh --check              verify tools
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

source "$HERE/config.sh"
for m in core discover collect enrich scan report; do source "$HERE/lib/$m.sh"; done

SCOPE_MODE=single; TARGET=''; CHECK=0; CONFIG=''
while (($#)); do case "$1" in
  --full) SCOPE_MODE=full; shift;;
  --check) CHECK=1; shift;;
  --config) CONFIG=${2:?}; shift 2;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  -*) die "unknown option: $1";;
  *) [[ -z $TARGET ]] || die 'one target only'; TARGET=$1; shift;;
esac; done
[[ -n $CONFIG ]] && { [[ -f $CONFIG ]] || die "no config: $CONFIG"; source "$CONFIG"; }

# ProjectDiscovery HTTPX, not the Python one.
HTTPX_BIN=httpx-toolkit
have "$HTTPX_BIN" || { have httpx && httpx -h 2>&1 | grep -q projectdiscovery && HTTPX_BIN=httpx; }

REQUIRED=(jq curl awk sed grep sort timeout "$HTTPX_BIN")
OPTIONAL=(subfinder assetfinder amass chaos alterx dnsx gau urlfinder waybackurls katana jsluice
  cdncheck tlsx asnmap naabu nmap nuclei dalfox ffuf sqlmap arjun crlfuzz subjack wafw00f
  whatweb testssl gowitness gf vulnx)
if ((CHECK)); then
  printf '%-16s %-8s %s\n' TOOL STATUS PATH
  miss=0
  for t in "${REQUIRED[@]}"; do have "$t" && printf '%-16s %-8s %s\n' "$t" OK "$(command -v "$t")" \
    || { printf '%-16s %-8s -\n' "$t" MISSING; miss=1; }; done
  echo
  for t in "${OPTIONAL[@]}"; do have "$t" && printf '%-16s %-8s %s\n' "$t" OK "$(command -v "$t")" \
    || printf '%-16s %-8s -\n' "$t" optional; done
  exit "$miss"
fi

[[ -n $TARGET ]] || die 'usage: ./automate.sh target.com [--full]'
DOMAIN=$(normalize_target "$TARGET") || die 'invalid target domain'
for t in jq curl awk timeout sort "$HTTPX_BIN"; do have "$t" || die "missing required tool: $t (run ./install.sh)"; done

RUN="$OUTPUT_ROOT/$DOMAIN/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN"/{raw,logs,reports}
: >"$RUN/stages.tsv"; : >"$RUN/commands.tsv"
: >"$RUN/parameters.hidden.txt"
info "Automate | $DOMAIN | scope=$SCOPE_MODE | $RUN"
info "perf: threads=$THREADS concurrency=$CONCURRENCY rate=$RATE timeout=${TIMEOUT}s"

# Discovery
stage subdomains    discover_subdomains
stage permutations  discover_permutations
stage dns           discover_dns
stage live          discover_live
# Collection
stage historical    collect_historical
stage crawl         collect_crawl
stage javascript    collect_javascript
stage inventory     collect_inventory
stage hidden_params scan_hidden_params
stage parameters    collect_parameters
stage gf_triage     scan_gf_triage
# Enrichment
stage technologies  enrich_technologies
stage tls           enrich_tls
stage headers       enrich_headers
stage infrastructure enrich_infrastructure
stage ports         enrich_ports
stage services      enrich_services
stage screenshots   enrich_screenshots
# Active testing
stage waf           scan_waf
stage cors          scan_cors
stage takeover      scan_takeover
stage crlf          scan_crlf
stage nuclei        scan_nuclei
stage xss           scan_xss
stage sqli          scan_sqli
stage fuzz          scan_fuzz
stage vulnx         scan_vulnx

report
