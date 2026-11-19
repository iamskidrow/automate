#!/usr/bin/env bash
# Active testing: WAF, CORS, takeover, CRLF, hidden params, gf triage, Nuclei, XSS, SQLi, fuzzing, CVE context.

scan_waf(){
  need hosts.live.txt || return; have wafw00f || { skip 'wafw00f missing'; return; }
  run "$RUN/raw/wafw00f.out" wafw00f wafw00f -i "$RUN/hosts.live.txt" -o "$RUN/raw/waf.txt"
}

scan_cors(){
  need hosts.live.txt || return; have curl || { skip 'curl missing'; return; }
  printf 'url\tstatus\treflects_origin\tallow_credentials\n' >"$RUN/cors.tsv"
  local url f code origin creds
  while IFS= read -r url; do scope_url "$url" || continue; f=$(mktemp)
    code=$(curl -sS -D "$f" -o /dev/null --max-redirs 0 -m "$HTTP_TIMEOUT" -H 'Origin: https://evil.example' -w '%{http_code}' "$url" 2>/dev/null || true)
    origin=$(awk 'BEGIN{IGNORECASE=1}tolower($1)=="access-control-allow-origin:"{print $2;exit}' "$f" | tr -d '\r')
    creds=$(awk 'tolower($1)=="access-control-allow-credentials:"{print $2;exit}' "$f" | tr -d '\r')
    printf '%s\t%s\t%s\t%s\n' "$url" "$code" "$([[ $origin == https://evil.example ]] && echo yes || echo no)" "${creds:-none}" >>"$RUN/cors.tsv"
    rm -f "$f"
  done <"$RUN/hosts.live.txt"
}

scan_takeover(){
  need hosts.passive.txt || return; have subjack || { skip 'subjack missing'; return; }
  local fp=/usr/share/subjack/fingerprints.json; [[ -f $fp ]] || fp=''
  run "$RUN/raw/subjack.out" subjack subjack -w "$RUN/hosts.passive.txt" -t "$THREADS" -ssl ${fp:+-c "$fp"} -o "$RUN/raw/subjack.txt"
}

scan_crlf(){
  need hosts.live.txt || return; have crlfuzz || { skip 'crlfuzz missing'; return; }
  run "$RUN/raw/crlfuzz.out" crlfuzz crlfuzz -l "$RUN/hosts.live.txt" -c "$CONCURRENCY" -s -o "$RUN/raw/crlf.txt"
}

# Hidden GET parameters on a few representative endpoints; feeds the parameter inventory.
scan_hidden_params(){
  : >"$RUN/parameters.hidden.txt"
  need urls.live.txt || return; have arjun || { skip 'arjun missing'; return; }
  awk '{l=tolower($0); if(l~/\.(png|jpg|jpeg|gif|svg|webp|ico|woff2?|ttf|css|js|pdf|zip|mp4)(\?|$)/)next;
    h=l;sub(/^https?:\/\//,"",h);sub(/\/.*/,"",h); if(!seen[h]++)print}' "$RUN/urls.live.txt" | head -n 5 >"$RUN/arjun.selected.txt"
  [[ -s $RUN/arjun.selected.txt ]] || { skip 'no eligible endpoints'; return; }
  run "$RUN/raw/arjun.out" arjun arjun -i "$RUN/arjun.selected.txt" -m GET -t "$THREADS" --rate-limit "$RATE" --disable-redirects -oJ "$RUN/raw/arjun.json"
  [[ -s $RUN/raw/arjun.json ]] || return 0
  jq -r 'to_entries[]|.key as $u|.value.params[]?|(if type=="string" then . else (.name//empty) end)|select(test("^[A-Za-z0-9_-]{1,80}$"))|$u+(if ($u|contains("?")) then "&" else "?" end)+.+"=1"' \
    "$RUN/raw/arjun.json" 2>/dev/null >"$RUN/raw/arjun.urls.raw" || true
  filter_urls "$RUN/raw/arjun.urls.raw" "$RUN/parameters.hidden.txt"
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
  local out="$RUN/raw/nuclei.jsonl"; local -a a
  a=(-l "$RUN/hosts.live.txt" -jsonl -silent -duc -tags "$NUCLEI_TAGS" -severity "$NUCLEI_SEVERITY"
     -etags "$NUCLEI_EXCLUDE" -c "$CONCURRENCY" -rl "$RATE" -timeout "$HTTP_TIMEOUT" -retries "$RETRIES")
  ((ENABLE_OOB)) || a+=(-ni)
  run "$out" nuclei nuclei "${a[@]}"
  info "nuclei candidates: $(count "$out")"
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
  # dalfox exit codes: 0 clean, 1 findings, 2 no scannable targets — none is a framework failure.
  ((rc==1)) && [[ -s $RUN/raw/dalfox.txt ]] && info 'dalfox reported candidates'
  ((rc<=2)) && STAGE_ERR=0
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

# CVE context for Nuclei-reported CVE IDs only (no inference from product names).
scan_vulnx(){
  [[ -s $RUN/raw/nuclei.jsonl ]] || { skip 'no nuclei findings'; return; }
  have vulnx || { skip 'vulnx missing'; return; }
  grep -Eoi 'CVE-[0-9]{4}-[0-9]{4,}' "$RUN/raw/nuclei.jsonl" | LC_ALL=C sort -u >"$RUN/cve.ids.txt" || true
  [[ -s $RUN/cve.ids.txt ]] || { skip 'no CVE identifiers'; return; }
  run "$RUN/raw/vulnx.json" vulnx vulnx id --json --file "$RUN/cve.ids.txt"
}
