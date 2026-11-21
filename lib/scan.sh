#!/usr/bin/env bash
# Active testing: WAF, CORS, takeover, CRLF, hidden params, gf triage,
# Nuclei (templates + DAST), XSS, SQLi, fuzzing, WordPress, cloud, CVE context.

scan_waf(){
  need hosts.live.txt || return; have wafw00f || { skip 'wafw00f missing'; return; }
  run "$RUN/raw/wafw00f.out" wafw00f wafw00f -i "$RUN/hosts.live.txt" -o "$RUN/raw/waf.txt"
}

scan_cors(){
  need hosts.live.txt || return; have curl || { skip 'curl missing'; return; }
  printf 'url\tstatus\treflects_origin\tallow_credentials\n' >"$RUN/cors.tsv"
  local url f code origin creds
  while IFS= read -r url; do scope_url "$url" || continue; f=$(mktemp)
    code=$(curl -sS -A "$UA" -D "$f" -o /dev/null --max-redirs 0 -m "$HTTP_TIMEOUT" -H 'Origin: https://evil.example' -w '%{http_code}' "$url" 2>/dev/null || true)
    origin=$(awk 'BEGIN{IGNORECASE=1}tolower($1)=="access-control-allow-origin:"{print $2;exit}' "$f" | tr -d '\r')
    creds=$(awk 'tolower($1)=="access-control-allow-credentials:"{print $2;exit}' "$f" | tr -d '\r')
    printf '%s\t%s\t%s\t%s\n' "$url" "$code" "$([[ $origin == https://evil.example ]] && echo yes || echo no)" "${creds:-none}" >>"$RUN/cors.tsv"
    rm -f "$f"
  done <"$RUN/hosts.live.txt"
}

# Takeover across ALL passive names (incl. dangling): dnsReaper if present, else Nuclei templates.
scan_takeover(){
  need hosts.passive.txt || return
  if have dnsreaper; then
    run "$RUN/raw/dnsreaper.txt" takeover dnsreaper file --filename "$RUN/hosts.passive.txt"
  elif have nuclei; then
    local -a a=(-l "$RUN/hosts.passive.txt" -tags takeover -jsonl -silent -duc -rl "$RATE" -c "$CONCURRENCY" -timeout "$HTTP_TIMEOUT" -retries "$RETRIES")
    ((ENABLE_OOB)) || a+=(-ni)
    run "$RUN/raw/takeover.jsonl" takeover nuclei "${a[@]}"
  else skip 'no takeover tool'; fi
}

scan_crlf(){
  need hosts.live.txt || return; have crlfuzz || { skip 'crlfuzz missing'; return; }
  run "$RUN/raw/crlfuzz.out" crlfuzz crlfuzz -l "$RUN/hosts.live.txt" -c "$CONCURRENCY" -s -o "$RUN/raw/crlf.txt"
}

# Hidden GET parameters on representative endpoints (x8 if installed, else arjun).
scan_hidden_params(){
  : >"$RUN/parameters.hidden.txt"
  need urls.live.txt || return
  awk '{l=tolower($0); if(l~/\.(png|jpg|jpeg|gif|svg|webp|ico|woff2?|ttf|css|js|pdf|zip|mp4)(\?|$)/)next;
    h=l;sub(/^https?:\/\//,"",h);sub(/\/.*/,"",h); if(!seen[h]++)print}' "$RUN/urls.live.txt" | head -n 5 >"$RUN/pd.selected.txt"
  [[ -s $RUN/pd.selected.txt ]] || { skip 'no eligible endpoints'; return; }
  if have x8; then
    run "$RUN/raw/x8.txt" x8 x8 -u "$RUN/pd.selected.txt" -O url -o "$RUN/raw/x8.out"
    [[ -f $RUN/raw/x8.out ]] && filter_urls "$RUN/raw/x8.out" "$RUN/parameters.hidden.txt"
  elif have arjun; then
    run "$RUN/raw/arjun.out" arjun arjun -i "$RUN/pd.selected.txt" -m GET -t "$THREADS" --rate-limit "$RATE" --disable-redirects -oJ "$RUN/raw/arjun.json"
    [[ -s $RUN/raw/arjun.json ]] || return 0
    jq -r 'to_entries[]|.key as $u|.value.params[]?|(if type=="string" then . else (.name//empty) end)|select(test("^[A-Za-z0-9_-]{1,80}$"))|$u+(if ($u|contains("?")) then "&" else "?" end)+.+"=1"' \
      "$RUN/raw/arjun.json" 2>/dev/null >"$RUN/raw/arjun.urls.raw" || true
    filter_urls "$RUN/raw/arjun.urls.raw" "$RUN/parameters.hidden.txt"
  else skip 'no parameter tool'; fi
}

# gf pattern triage: bucket URLs by likely vuln class to target downstream scanners.
scan_gf_triage(){
  need urls.all.txt || return; have gf || { skip 'gf missing'; return; }
  mkdir -p "$RUN/triage"; local pat
  for pat in sqli xss ssrf lfi redirect rce ssti idor; do
    gf "$pat" <"$RUN/urls.all.txt" 2>/dev/null | LC_ALL=C sort -u >"$RUN/triage/$pat.txt" || true
    [[ -s $RUN/triage/$pat.txt ]] && info "gf $pat: $(count "$RUN/triage/$pat.txt")"
  done
  :
}

# Single Nuclei pass over all live hosts: tag/severity filtered, templates compiled once.
scan_nuclei(){
  need hosts.live.txt || return; have nuclei || { skip 'nuclei missing'; return; }
  local -a a=(-l "$RUN/hosts.live.txt" -jsonl -silent -duc -tags "$NUCLEI_TAGS" -severity "$NUCLEI_SEVERITY"
     -etags "$NUCLEI_EXCLUDE" -c "$CONCURRENCY" -rl "$RATE" -timeout "$HTTP_TIMEOUT" -retries "$RETRIES")
  ((ENABLE_OOB)) || a+=(-ni)
  run "$RUN/raw/nuclei.jsonl" nuclei nuclei "${a[@]}"
  info "nuclei candidates: $(count "$RUN/raw/nuclei.jsonl")"
}

# DAST parameter fuzzing (open-redirect/SSRF/XSS/SQLi) over parameterized endpoints.
scan_dast(){
  need parameters.scan.txt || return; have nuclei || { skip 'nuclei missing'; return; }
  local -a a=(-l "$RUN/parameters.scan.txt" -dast -jsonl -silent -duc -rl "$RATE" -c "$CONCURRENCY"
     -timeout "$HTTP_TIMEOUT" -retries "$RETRIES" -etags "$NUCLEI_EXCLUDE")
  ((ENABLE_OOB)) || a+=(-ni)
  run "$RUN/raw/nuclei.dast.jsonl" dast nuclei "${a[@]}"
  info "dast candidates: $(count "$RUN/raw/nuclei.dast.jsonl")"
}

# XSS on gf-triaged parameters when available, else all scan parameters.
scan_xss(){
  have dalfox || { skip 'dalfox missing'; return; }
  local in="$RUN/parameters.scan.txt"
  [[ -s $RUN/triage/xss.txt ]] && in="$RUN/triage/xss.txt"
  [[ -s $in ]] || { skip 'no parameters'; return; }
  local rc=0
  run "$RUN/raw/dalfox.out" dalfox dalfox scan -i file "$in" --silence --rate-limit "$RATE" \
    --timeout "$HTTP_TIMEOUT" --scan-timeout "$TIMEOUT" --output "$RUN/raw/dalfox.txt" || rc=$?
  ((rc==1)) && [[ -s $RUN/raw/dalfox.txt ]] && info 'dalfox reported candidates'
  ((rc<=2)) && STAGE_ERR=0   # 0 clean, 1 findings, 2 no scannable targets
  return 0
}

# SQLi on gf-triaged sqli parameters when available, else scan parameters.
scan_sqli(){
  have sqlmap || { skip 'sqlmap missing'; return; }
  local in="$RUN/parameters.scan.txt"
  [[ -s $RUN/triage/sqli.txt ]] && { param_signatures "$RUN/triage/sqli.txt" "$RUN/parameters.sqli.txt"; in="$RUN/parameters.sqli.txt"; }
  [[ -s $in ]] || { skip 'no parameters'; return; }
  head -n "$MAX_PARAMS" "$in" >"$RUN/sqlmap.selected.txt"
  local th=$(( THREADS>10 ? 10 : THREADS ))   # sqlmap hard-caps threads at 10
  run "$RUN/raw/sqlmap.out" sqlmap sqlmap -m "$RUN/sqlmap.selected.txt" --batch --level=2 --risk=1 \
    --threads="$th" --timeout="$HTTP_TIMEOUT" --retries="$RETRIES" --output-dir="$RUN/raw/sqlmap"
}

scan_fuzz(){
  need hosts.live.txt || return; have ffuf || { skip 'ffuf missing'; return; }
  [[ -f $WORDLIST ]] || { skip "wordlist missing: $WORDLIST"; return; }
  head -n "$FUZZ_WORDS" "$WORDLIST" >"$RUN/fuzz.words.txt"
  local url i=0
  while IFS= read -r url; do scope_url "$url" || continue; i=$((i+1))
    run "$RUN/raw/ffuf_$i.out" "ffuf_$i" ffuf -w "$RUN/fuzz.words.txt" -u "${url%/}/FUZZ" \
      -t "$THREADS" -rate "$RATE" -timeout "$HTTP_TIMEOUT" -maxtime "$TIMEOUT" -ac -s -of json -o "$RUN/raw/ffuf_$i.json"
  done <"$RUN/hosts.live.txt"
}

# WordPress deep scan — only when WordPress is detected.
scan_wordpress(){
  have wpscan || { skip 'wpscan missing'; return; }
  : >"$RUN/wp.hosts"
  # Primary: hosts fingerprinted as WordPress by httpx tech detection.
  [[ -s $RUN/technologies.jsonl ]] && jq -r 'select((.tech//[])|map(ascii_downcase)|index("wordpress"))|.url' \
    "$RUN/technologies.jsonl" 2>/dev/null | sort -u >"$RUN/wp.hosts"
  # Fallback: hosts serving wp-* paths in the collected URLs.
  [[ -s $RUN/wp.hosts ]] || grep -iE 'wp-content|wp-json|wp-includes' "$RUN/urls.all.txt" 2>/dev/null \
    | grep -hoE 'https?://[^/"]+' | sort -u >"$RUN/wp.hosts"
  [[ -s $RUN/wp.hosts ]] || { skip 'no WordPress detected'; return; }
  head -n 3 "$RUN/wp.hosts" >"$RUN/wp.hosts.sel"; mv "$RUN/wp.hosts.sel" "$RUN/wp.hosts"
  # vp/vt (vulnerable plugin/theme) enumeration needs a paid API token; fall back to free p,t,u.
  local enum='p,t,u'; local -a tok=()
  [[ -n ${WPSCAN_API_TOKEN:-} ]] && { enum='vp,vt,u'; tok=(--api-token "$WPSCAN_API_TOKEN"); }
  : >"$RUN/raw/wpscan.txt"; local u i=0
  while IFS= read -r u; do scope_url "$u" || continue; i=$((i+1))
    run "$RUN/raw/wpscan_$i.out" "wpscan_$i" wpscan --url "$u" --no-banner --random-user-agent --enumerate "$enum" "${tok[@]}" --format cli
    { printf '\n### %s ###\n' "$u"; cat "$RUN/raw/wpscan_$i.out"; } >>"$RUN/raw/wpscan.txt"
  done <"$RUN/wp.hosts"
  # wpscan exits nonzero for findings or "not WordPress"; only a missing-DB error is a real failure.
  grep -qiE 'Update required|database file is missing' "$RUN/raw/wpscan.txt" || STAGE_ERR=0
  return 0
}

# Cloud bucket exposure (full scope only).
scan_cloud(){
  have cloud_enum || have s3scanner || { skip 'no cloud tools'; return; }
  local kw=${DOMAIN%%.*}; : >"$RUN/raw/cloud_enum.txt"
  if have cloud_enum; then
    run "$RUN/raw/cloud_enum.out" cloud_enum cloud_enum -k "$kw" -k "$DOMAIN" -l "$RUN/raw/cloud_enum.log" --disable-azure --quickscan
    cat "$RUN/raw/cloud_enum.log" "$RUN/raw/cloud_enum.out" 2>/dev/null >>"$RUN/raw/cloud_enum.txt" || true
  fi
  if have s3scanner; then
    run "$RUN/raw/s3scanner.out" s3scanner s3scanner scan -bucket "$kw" || true
    cat "$RUN/raw/s3scanner.out" 2>/dev/null >>"$RUN/raw/cloud_enum.txt" || true
  fi
  # bucket scanners exit nonzero when nothing is found; that is a result, not a failure.
  [[ -s $RUN/raw/cloud_enum.txt ]] && STAGE_ERR=0
  return 0
}

# CVE context for Nuclei-reported CVE IDs only.
scan_vulnx(){
  [[ -s $RUN/raw/nuclei.jsonl || -s $RUN/raw/nuclei.dast.jsonl ]] || { skip 'no nuclei findings'; return; }
  have vulnx || { skip 'vulnx missing'; return; }
  grep -hEoi 'CVE-[0-9]{4}-[0-9]{4,}' "$RUN"/raw/nuclei*.jsonl 2>/dev/null | LC_ALL=C sort -u >"$RUN/cve.ids.txt" || true
  [[ -s $RUN/cve.ids.txt ]] || { skip 'no CVE identifiers'; return; }
  run "$RUN/raw/vulnx.json" vulnx vulnx id --json --file "$RUN/cve.ids.txt"
}
