#!/usr/bin/env bash
# Asset discovery: subdomains, permutations, DNS resolution, live web hosts.

# Passive subdomain enumeration (full mode only; single mode scopes to one host).
discover_subdomains(){
  if [[ $SCOPE_MODE == single ]]; then printf '%s\n' "$DOMAIN" >"$RUN/hosts.passive.txt"; return; fi
  local raw="$RUN/raw"
  have subfinder   && run "$raw/subfinder.txt"   subfinder   subfinder -d "$DOMAIN" -silent -t "$THREADS"
  have assetfinder && run "$raw/assetfinder.txt" assetfinder assetfinder --subs-only "$DOMAIN"
  ((ENABLE_AMASS)) && have amass && run "$raw/amass.txt" amass amass enum -passive -d "$DOMAIN"
  [[ -n ${PDCP_API_KEY:-} ]] && have chaos && run "$raw/chaos.txt" chaos chaos -d "$DOMAIN" -silent
  cat "$raw"/subfinder.txt "$raw"/assetfinder.txt "$raw"/amass.txt "$raw"/chaos.txt 2>/dev/null \
    | { cat; printf '%s\n' "$DOMAIN"; } >"$raw/subs.raw"
  filter_hosts "$raw/subs.raw" "$RUN/hosts.passive.txt"
  info "passive subdomains: $(count "$RUN/hosts.passive.txt")"
}

# Permutations from discovered names (full mode only).
discover_permutations(){
  [[ $SCOPE_MODE == full ]] || { cp "$RUN/hosts.passive.txt" "$RUN/hosts.all.txt"; skip 'single-host scope'; return; }
  need hosts.passive.txt || return
  if have alterx; then run "$RUN/raw/alterx.txt" alterx alterx -silent <"$RUN/hosts.passive.txt"; fi
  filter_hosts "$RUN/raw/alterx.txt" "$RUN/raw/alterx.scoped.txt"
  cat "$RUN/hosts.passive.txt" "$RUN/raw/alterx.scoped.txt" 2>/dev/null \
    | LC_ALL=C sort -u | head -n "$(( MAX_DNS>0 ? MAX_DNS : 2000000 ))" >"$RUN/hosts.all.txt"
  info "candidates to resolve: $(count "$RUN/hosts.all.txt")"
}

# Resolve to public addresses only; drop private/reserved.
discover_dns(){
  need hosts.all.txt || return
  local json="$RUN/raw/dnsx.jsonl"
  if have dnsx; then
    run "$json" dnsx dnsx -l "$RUN/hosts.all.txt" -a -aaaa -cname -json -silent -rl "$RATE" -t "$THREADS" -retry "$RETRIES"
    : >"$RUN/raw/resolved.raw"
    local host addrs ip ok bad
    while IFS=$'\t' read -r host addrs; do
      [[ -n $host ]] || continue; ok=0; bad=0
      while IFS= read -r ip; do [[ -n $ip ]] || continue; ok=1
        if [[ $ip == *:* ]]; then public_ipv6 "$ip" || bad=1; else public_ipv4 "$ip" || bad=1; fi
      done < <(tr ',' '\n' <<<"$addrs")
      ((ok&&!bad)) && printf '%s\n' "$host" >>"$RUN/raw/resolved.raw"
    done < <(jq -r 'select(type=="object")|[(.host//.input//""),(([(.a//[])[],(.aaaa//[])[]])|join(","))]|@tsv' "$json" 2>/dev/null)
  else
    local host ip ok
    while IFS= read -r host; do ok=0
      while IFS= read -r ip; do public_ipv4 "$ip" && ok=1 || { ok=0; break; }; done \
        < <(dig +time=2 +tries=1 +short "$host" A 2>/dev/null | grep -E '^[0-9.]+$')
      ((ok)) && printf '%s\n' "$host" >>"$RUN/raw/resolved.raw"
    done <"$RUN/hosts.all.txt"
  fi
  filter_hosts "$RUN/raw/resolved.raw" "$RUN/hosts.resolved.txt"
  info "resolved hosts: $(count "$RUN/hosts.resolved.txt")"
}

# Probe for live HTTP(S) services and record technology/metadata.
discover_live(){
  need hosts.resolved.txt || return; have "$HTTPX_BIN" || { skip "missing $HTTPX_BIN"; return; }
  local src="$RUN/hosts.resolved.txt"
  ((MAX_HOSTS>0)) && { head -n "$MAX_HOSTS" "$src" >"$RUN/hosts.selected.txt"; src="$RUN/hosts.selected.txt"; }
  run "$RUN/raw/httpx.hosts.jsonl" httpx_hosts "$HTTPX_BIN" -l "$src" -silent -json \
    -sc -title -td -ip -cname -cdn -location -threads "$THREADS" -rl "$RATE" -timeout "$HTTP_TIMEOUT" -retries "$RETRIES"
  jq -r 'select(type=="object")|.url//empty' "$RUN/raw/httpx.hosts.jsonl" 2>/dev/null >"$RUN/raw/live.raw"
  filter_urls "$RUN/raw/live.raw" "$RUN/hosts.live.txt"
  info "live web hosts: $(count "$RUN/hosts.live.txt")"
}
