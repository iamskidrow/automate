#!/usr/bin/env bash
# Reporting: normalized findings (json/csv), a text summary, and an HTML view.

report(){
  local f="$RUN/reports"; mkdir -p "$f"
  # Deduplicated Nuclei findings; scanner candidates, not confirmed vulnerabilities.
  if [[ -s $RUN/raw/nuclei.jsonl ]]; then
    jq -Rsc '[split("\n")[]|try fromjson catch empty|select(type=="object" and has("template-id"))
      |{id:."template-id",name:(.info.name//."template-id"),severity:(.info.severity//"unknown"),
        url:(."matched-at"//.host//""),cve:([.info.classification."cve-id"?]|flatten|map(select(type=="string")))}]
      |unique_by(.id,.url)' "$RUN/raw/nuclei.jsonl" 2>/dev/null >"$f/findings.json" || echo '[]' >"$f/findings.json"
  else echo '[]' >"$f/findings.json"; fi
  jq -r '(["id","name","severity","url"]|@csv),(.[]|[.id,.name,.severity,.url]|@csv)' "$f/findings.json" >"$f/findings.csv"

  # Latest status per stage.
  awk -F'\t' '{s[$1]=$2;t[$1]=$3}END{for(k in s)print k"\t"s[k]"\t"t[k]}' "$RUN/stages.tsv" | LC_ALL=C sort >"$f/stages.tsv"
  local ok part skip
  ok=$(awk -F'\t' '$2=="OK"{n++}END{print n+0}' "$f/stages.tsv")
  part=$(awk -F'\t' '$2=="PARTIAL"{n++}END{print n+0}' "$f/stages.tsv")
  skip=$(awk -F'\t' '$2=="SKIP"{n++}END{print n+0}' "$f/stages.tsv")

  cat >"$f/summary.txt" <<EOF
AUTOMATE ASSESSMENT SUMMARY
Target:            $DOMAIN
Scope:             $SCOPE_MODE
UTC:               $(date -u +%FT%TZ)
Run directory:     $RUN

Subdomains:        $(count "$RUN/hosts.passive.txt")
Resolved hosts:    $(count "$RUN/hosts.resolved.txt")
Live web hosts:    $(count "$RUN/hosts.live.txt")
URLs (all):        $(count "$RUN/urls.all.txt")
URLs (probed):     $(count "$RUN/urls.selected.txt")
Live URLs:         $(count "$RUN/urls.live.txt")
Parameters:        $(count "$RUN/parameters.all.txt")
Open ports:        $(count "$RUN/raw/naabu.txt")
Nuclei findings:   $(jq 'length' "$f/findings.json")

Stages OK/partial/skipped: $ok / $part / $skip

NOTE: candidates require manual validation. Skipped or partial stages are not a clean result.
EOF

  {
    printf '<!doctype html><meta charset=utf-8><title>Automate — %s</title>' "$DOMAIN"
    printf '<style>body{font-family:system-ui;max-width:960px;margin:3rem auto;padding:0 1rem;color:#222}pre{background:#f4f6fb;padding:1.5rem;border-radius:.75rem;white-space:pre-wrap}table{border-collapse:collapse;width:100%%}td,th{padding:6px 8px;border-bottom:1px solid #e3e3e3;text-align:left}</style>'
    printf '<h1>Automate — %s</h1><pre>' "$DOMAIN"
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' "$f/summary.txt"
    printf '</pre><h2>Stages</h2><table><tr><th>Stage</th><th>Status</th><th>Seconds</th></tr>'
    awk -F'\t' '{printf "<tr><td>%s</td><td>%s</td><td>%s</td></tr>",$1,$2,$3}' "$f/stages.tsv"
    printf '</table>'
  } >"$f/report.html"

  cat "$f/summary.txt"
  info "report: $f/summary.txt"
}
