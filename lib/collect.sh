#!/usr/bin/env bash
# Endpoint collection: historical URLs, live crawl, JS endpoints, inventory, parameters.

# Historical URLs from passive archives.
collect_historical(){
  local raw="$RUN/raw" subs=''
  [[ $SCOPE_MODE == full ]] && subs='--subs'
  have gau         && run "$raw/gau.txt"         gau         gau $subs --threads "$THREADS" --timeout "$HTTP_TIMEOUT" "$DOMAIN"
  have urlfinder   && run "$raw/urlfinder.txt"   urlfinder   urlfinder -d "$DOMAIN" -rl "$RATE" -silent
  have waybackurls && printf '%s\n' "$DOMAIN" | run "$raw/wayback.txt" waybackurls waybackurls
  cat "$raw"/gau.txt "$raw"/urlfinder.txt "$raw"/wayback.txt 2>/dev/null >"$raw/historical.raw"
  filter_urls "$raw/historical.raw" "$RUN/urls.historical.txt"
  info "historical URLs: $(count "$RUN/urls.historical.txt")"
}

# Live crawl with JS parsing; response bodies omitted from derived URLs.
collect_crawl(){
  need hosts.live.txt || return; have katana || { skip 'katana missing'; return; }
  local out="$RUN/raw/katana.jsonl"
  run "$out" katana katana -list "$RUN/hosts.live.txt" \
    -d "$CRAWL_DEPTH" -jc -kf all -fs fqdn -c "$CONCURRENCY" -rl "$RATE" -timeout "$HTTP_TIMEOUT" \
    -or -ob -jsonl -silent
  jq -Rr '(fromjson?//empty)|select(type=="object")|(.request.endpoint//.endpoint//empty)' "$out" 2>/dev/null >"$RUN/raw/crawl.raw"
  filter_urls "$RUN/raw/crawl.raw" "$RUN/urls.crawl.txt"
  info "crawled URLs: $(count "$RUN/urls.crawl.txt")"
}

# Parse JavaScript for endpoints and potential secrets (secrets kept in raw only).
collect_javascript(){
  have jsluice || { skip 'jsluice missing'; return; }
  need urls.crawl.txt || return
  grep -Ei '\.m?js([?]|$)' "$RUN/urls.crawl.txt" | head -n 50 >"$RUN/js.selected.txt" || true
  [[ -s $RUN/js.selected.txt ]] || { skip 'no JS files'; return; }
  mkdir -p "$RUN/raw/js"; local i=0 url
  : >"$RUN/raw/jsluice.paths"; : >"$RUN/raw/jsluice.secrets.jsonl"
  while IFS= read -r url; do scope_url "$url" || continue; i=$((i+1))
    curl -sS --fail --max-time 12 --max-filesize 1048576 --max-redirs 0 "$url" -o "$RUN/raw/js/$i.js" 2>/dev/null || continue
    jsluice urls -R "$url" "$RUN/raw/js/$i.js" 2>/dev/null | jq -r 'select(type=="object")|.url//empty' >>"$RUN/raw/jsluice.paths" || true
    jsluice secrets "$RUN/raw/js/$i.js" 2>/dev/null | jq -cr 'select(type=="object")' >>"$RUN/raw/jsluice.secrets.jsonl" || true
  done <"$RUN/js.selected.txt"
  filter_urls "$RUN/raw/jsluice.paths" "$RUN/urls.js.txt"
  info "JS endpoints: $(count "$RUN/urls.js.txt")  secrets(raw): $(count "$RUN/raw/jsluice.secrets.jsonl")"
}

# Merge every source, select a balanced probe set, probe it live.
collect_inventory(){
  cat "$RUN"/urls.historical.txt "$RUN"/urls.crawl.txt "$RUN"/urls.js.txt "$RUN"/hosts.live.txt 2>/dev/null >"$RUN/raw/urls.merged.raw"
  filter_urls "$RUN/raw/urls.merged.raw" "$RUN/urls.all.txt"
  select_balanced "$RUN/urls.all.txt" "$RUN/urls.selected.txt" "$MAX_URLS"
  info "URL inventory: all=$(count "$RUN/urls.all.txt") selected=$(count "$RUN/urls.selected.txt")"
  need urls.selected.txt || return; have "$HTTPX_BIN" || { skip "missing $HTTPX_BIN"; return; }
  run "$RUN/raw/httpx.urls.jsonl" httpx_urls "$HTTPX_BIN" -l "$RUN/urls.selected.txt" -silent -json \
    -sc -title -td -location -threads "$THREADS" -rl "$RATE" -timeout "$HTTP_TIMEOUT" -retries "$RETRIES"
  jq -r 'select(type=="object")|.url//empty' "$RUN/raw/httpx.urls.jsonl" 2>/dev/null >"$RUN/raw/urls.live.raw"
  filter_urls "$RUN/raw/urls.live.raw" "$RUN/urls.live.txt"
  info "live URLs: $(count "$RUN/urls.live.txt")"
}

# Distinct parameterized endpoints for injection testing.
collect_parameters(){
  need urls.all.txt || return
  # Drop static assets — they carry no injectable parameters.
  cat "$RUN/urls.all.txt" "$RUN/parameters.hidden.txt" 2>/dev/null \
    | grep -ivE '\.(css|js|png|jpg|jpeg|gif|svg|webp|ico|woff2?|ttf|eot|pdf|zip|mp4|map)(\?|$)' >"$RUN/raw/params.raw" || true
  param_signatures "$RUN/raw/params.raw" "$RUN/parameters.all.txt"
  head -n "$MAX_PARAMS" "$RUN/parameters.all.txt" >"$RUN/parameters.scan.txt"
  info "parameter signatures: all=$(count "$RUN/parameters.all.txt") scan=$(count "$RUN/parameters.scan.txt")"
}
