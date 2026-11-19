#!/usr/bin/env bash
# Curate the hidden .evidence working tree into a clean, readable run folder.

# anew diffing against the per-domain known store (runs as its own stage).
diff_new(){
  have anew || { skip 'anew missing'; return; }
  : >"$RUN/new.subdomains.txt"; : >"$RUN/new.urls.txt"
  [[ -s $RUN/hosts.resolved.txt ]] && anew "$KNOWN/subdomains.txt" <"$RUN/hosts.resolved.txt" >"$RUN/new.subdomains.txt"
  [[ -s $RUN/urls.all.txt ]]       && anew "$KNOWN/urls.txt"       <"$RUN/urls.all.txt"       >"$RUN/new.urls.txt"
  info "new since last run: $(count "$RUN/new.subdomains.txt") subdomains, $(count "$RUN/new.urls.txt") urls"
}

report(){
  local R="$RUN_ROOT" E="$RUN"
  cp2(){ [[ -s $1 ]] && cp "$1" "$2"; }   # copy only when the source has content

  # Normalized findings from Nuclei (templates + DAST).
  cat "$E/raw/nuclei.jsonl" "$E/raw/nuclei.dast.jsonl" 2>/dev/null >"$E/raw/nuclei.combined.jsonl"
  if [[ -s $E/raw/nuclei.combined.jsonl ]]; then
    jq -Rsc '[split("\n")[]|try fromjson catch empty|select(type=="object" and has("template-id"))
      |{id:."template-id",name:(.info.name//."template-id"),severity:(.info.severity//"unknown"),
        url:(."matched-at"//.host//"")}]|unique_by(.id,.url)' "$E/raw/nuclei.combined.jsonl" 2>/dev/null >"$R/findings.json" || echo '[]' >"$R/findings.json"
  else echo '[]' >"$R/findings.json"; fi
  jq -r '(["severity","id","name","url"]|@csv),(.[]|[.severity,.id,.name,.url]|@csv)' "$R/findings.json" >"$R/findings.csv"

  # assets/ — the inventory that matters.
  cp2 "$E/hosts.resolved.txt" "$R/assets/subdomains.txt"
  cp2 "$E/hosts.live.txt"     "$R/assets/hosts-live.txt"
  cp2 "$E/urls.all.txt"       "$R/assets/urls.txt"
  cp2 "$E/urls.live.txt"      "$R/assets/urls-live.txt"
  cp2 "$E/parameters.all.txt" "$R/assets/params.txt"
  cp2 "$E/raw/naabu.txt"      "$R/assets/ports.txt"
  cp2 "$E/new.subdomains.txt" "$R/assets/new-subdomains.txt"
  cp2 "$E/new.urls.txt"       "$R/assets/new-urls.txt"
  [[ -s $E/technologies.jsonl ]] && jq -r 'select(.tech!=null)|[.url,((.tech//[])|join(","))]|@tsv' \
    "$E/technologies.jsonl" 2>/dev/null >"$R/assets/tech.tsv"

  # vulns/ — only what has content.
  [[ $(jq 'length' "$R/findings.json") -gt 0 ]] && jq -r '.[]|[.severity,.id,.url]|@tsv' "$R/findings.json" >"$R/vulns/nuclei.tsv"
  cp2 "$E/raw/dalfox.txt"       "$R/vulns/xss-dalfox.txt"
  cp2 "$E/raw/crlf.txt"         "$R/vulns/crlf.txt"
  cp2 "$E/raw/takeover.jsonl"   "$R/vulns/takeover.jsonl"
  cp2 "$E/raw/wpscan.txt"       "$R/vulns/wpscan.txt"
  cp2 "$E/raw/trufflehog.jsonl" "$R/vulns/secrets.jsonl"
  cp2 "$E/raw/cloud_enum.txt"   "$R/vulns/cloud.txt"
  if [[ -s $E/cors.tsv ]]; then awk -F'\t' 'NR==1||$3=="yes"' "$E/cors.tsv" >"$R/vulns/cors.tsv"
    [[ $(count "$R/vulns/cors.tsv") -le 1 ]] && rm -f "$R/vulns/cors.tsv"; fi
  [[ -d $E/raw/sqlmap ]] && find "$E/raw/sqlmap" -name '*.csv' -exec cat {} + >"$R/vulns/sqli.txt" 2>/dev/null

  # hygiene/ — config findings.
  cp2 "$E/headers.tsv" "$R/hygiene/headers.tsv"
  cp2 "$E/raw/waf.txt" "$R/hygiene/waf.txt"
  cat "$E"/raw/testssl_*.txt 2>/dev/null | grep -iE 'VULNERABLE|NOT ok|weak|offered' >"$R/hygiene/tls-issues.txt" 2>/dev/null || true

  [[ -d $E/raw/screenshots ]] && cp -r "$E/raw/screenshots" "$R/screenshots" 2>/dev/null

  # summary.
  local findings; findings=$(jq 'length' "$R/findings.json")
  local ok part skip
  ok=$(awk -F'\t' '$2=="OK"{n++}END{print n+0}' "$E/stages.tsv")
  part=$(awk -F'\t' '$2=="PARTIAL"{n++}END{print n+0}' "$E/stages.tsv")
  skip=$(awk -F'\t' '$2=="SKIP"{n++}END{print n+0}' "$E/stages.tsv")
  cat >"$R/summary.txt" <<EOF
AUTOMATE ASSESSMENT — $DOMAIN  (scope: $SCOPE_MODE)
$(date -u +%FT%TZ)

Subdomains:      $(count "$E/hosts.resolved.txt")
Live web hosts:  $(count "$E/hosts.live.txt")
URLs:            $(count "$E/urls.all.txt")  (live: $(count "$E/urls.live.txt"))
Parameters:      $(count "$E/parameters.all.txt")
Open ports:      $(count "$E/raw/naabu.txt")
New this run:    $(count "$E/new.subdomains.txt") subdomains, $(count "$E/new.urls.txt") urls
Nuclei findings: $findings
Stages:          $ok OK / $part partial / $skip skipped

Deliverables:  assets/  vulns/  hygiene/  screenshots/  findings.csv
Raw evidence:  .evidence/ (hidden)
Candidates need manual validation; partial/skipped stages are not a clean result.
EOF

  {
    printf '<!doctype html><meta charset=utf-8><title>Automate — %s</title>' "$DOMAIN"
    printf '<style>body{font-family:system-ui;max-width:900px;margin:3rem auto;padding:0 1rem;color:#222}pre{background:#f4f6fb;padding:1.5rem;border-radius:.6rem;white-space:pre-wrap}table{border-collapse:collapse;width:100%%;margin-top:1rem}td,th{padding:6px 8px;border-bottom:1px solid #e3e3e3;text-align:left;font-size:14px}</style>'
    printf '<h1>Automate — %s</h1><pre>' "$DOMAIN"
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' "$R/summary.txt"
    printf '</pre><h2>Stages</h2><table><tr><th>Stage</th><th>Status</th><th>s</th><th>note</th></tr>'
    awk -F'\t' '{printf "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",$1,$2,$3,$4}' "$E/stages.tsv"
    printf '</table>'
  } >"$R/REPORT.html"

  # Prune empties and empty category dirs from the visible tree (never touch .evidence).
  find "$R" -type f -empty -not -path '*/.evidence/*' -delete 2>/dev/null
  find "$R/assets" "$R/vulns" "$R/hygiene" -type d -empty -delete 2>/dev/null
  cat "$R/summary.txt"
  info "report: $R/REPORT.html"
}
