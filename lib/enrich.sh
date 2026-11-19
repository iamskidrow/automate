#!/usr/bin/env bash
# Enrichment: technologies, TLS, HTTP headers, infrastructure, ports, services, screenshots.

enrich_technologies(){
  need raw/httpx.hosts.jsonl || return
  jq -c 'select(type=="object")|{url,host,status_code,title,tech,webserver,cdn,ip,cname}' \
    "$RUN/raw/httpx.hosts.jsonl" 2>/dev/null >"$RUN/technologies.jsonl"
  jq -r 'select(type=="object")|select((.tech//[])|length==0)|.url//empty' \
    "$RUN/raw/httpx.hosts.jsonl" 2>/dev/null >"$RUN/raw/tech.unknown.txt"
  if [[ -s $RUN/raw/tech.unknown.txt ]] && have whatweb; then
    run "$RUN/raw/whatweb.txt" whatweb whatweb --color=never --input-file="$RUN/raw/tech.unknown.txt" -t "$THREADS"
  fi
}

enrich_tls(){
  need hosts.resolved.txt || return
  have tlsx && run "$RUN/raw/tlsx.jsonl" tlsx tlsx -l "$RUN/hosts.resolved.txt" -json -silent -c "$CONCURRENCY" -rl "$RATE"
  have testssl || { skip 'testssl missing (tlsx metadata kept)'; return; }
  grep '^https://' "$RUN/hosts.live.txt" 2>/dev/null | head -n 10 >"$RUN/tls.selected.txt" || true
  [[ -s $RUN/tls.selected.txt ]] || { skip 'no HTTPS hosts'; return; }
  local i=0 url
  while IFS= read -r url; do i=$((i+1))
    run "$RUN/raw/testssl_$i.txt" "testssl_$i" testssl --quiet --warnings off "$url"
  done <"$RUN/tls.selected.txt"
}

# Security-header and cookie-attribute inventory; cookies redacted after capture.
enrich_headers(){
  need hosts.live.txt || return; have curl || { skip 'curl missing'; return; }
  printf 'url\thsts\tcsp\txframe\tnosniff\tcookie\tsecure\thttponly\tsamesite\tstatus\n' >"$RUN/headers.tsv"
  local url f
  while IFS= read -r url; do scope_url "$url" || continue
    f=$(mktemp)
    curl -I -sS -D "$f" -o /dev/null --max-redirs 0 --connect-timeout 5 --max-time "$HTTP_TIMEOUT" "$url" 2>/dev/null || true
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$url" \
      "$(grep -qi '^strict-transport-security:' "$f" && echo y || echo n)" \
      "$(grep -qi '^content-security-policy:' "$f" && echo y || echo n)" \
      "$(grep -qi '^x-frame-options:' "$f" && echo y || echo n)" \
      "$(grep -qi '^x-content-type-options:.*nosniff' "$f" && echo y || echo n)" \
      "$(grep -qi '^set-cookie:' "$f" && echo y || echo n)" \
      "$(grep -i '^set-cookie:' "$f" | grep -Eqi '(;| )secure([;[:space:]]|$)' && echo y || echo n)" \
      "$(grep -i '^set-cookie:' "$f" | grep -Eqi 'httponly' && echo y || echo n)" \
      "$(grep -i '^set-cookie:' "$f" | grep -Eqi 'samesite=' && echo y || echo n)" \
      "$(awk '/^HTTP\//{c=$2}END{print c+0}' "$f")" >>"$RUN/headers.tsv"
    rm -f "$f"
  done <"$RUN/hosts.live.txt"
}

# CDN / cloud classification (reference only; never added to scan scope).
enrich_infrastructure(){
  need hosts.resolved.txt || return
  have cdncheck && run "$RUN/raw/cdncheck.jsonl" cdncheck cdncheck -i "$RUN/hosts.resolved.txt" -jsonl
  [[ -s ${OWNED_ASNS_FILE:-/nonexistent} ]] && have asnmap && run "$RUN/raw/asnmap.jsonl" asnmap asnmap -l "$OWNED_ASNS_FILE" -json
  :
}

enrich_screenshots(){
  ((ENABLE_SCREENSHOTS)) || { skip 'screenshots disabled'; return; }
  need hosts.live.txt || return; have gowitness || { skip 'gowitness missing'; return; }
  run "$RUN/raw/gowitness.txt" gowitness gowitness scan file -f "$RUN/hosts.live.txt" --screenshot-path "$RUN/raw/screenshots" -T "$THREADS"
}

enrich_ports(){
  need hosts.resolved.txt || return; have naabu || { skip 'naabu missing'; return; }
  run "$RUN/raw/naabu.out" naabu naabu -list "$RUN/hosts.resolved.txt" -top-ports 1000 -exclude-cdn -rate "$RATE" -c "$CONCURRENCY" -silent -o "$RUN/raw/naabu.txt"
  [[ -f $RUN/raw/naabu.txt ]] || : >"$RUN/raw/naabu.txt"
  info "open ports: $(count "$RUN/raw/naabu.txt")"
}

enrich_services(){
  need raw/naabu.txt || return; have nmap || { skip 'nmap missing'; return; }
  printf 'host\tport\txml\n' >"$RUN/services.tsv"
  local line host port i=0
  while IFS= read -r line; do host=${line%:*}; port=${line##*:}
    in_scope "$host" || continue; [[ $port =~ ^[0-9]{1,5}$ ]] || continue; i=$((i+1))
    run "$RUN/raw/nmap_$i.out" "nmap_$i" nmap -Pn -sV --version-light -p "$port" --host-timeout 120s "$host" -oX "$RUN/raw/nmap_$i.xml"
    printf '%s\t%s\t%s\n' "$host" "$port" "raw/nmap_$i.xml" >>"$RUN/services.tsv"
  done <"$RUN/raw/naabu.txt"
}
