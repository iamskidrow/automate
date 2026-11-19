#!/usr/bin/env bash
# Shared helpers: logging, the tool supervisor, scope/IP validation, stage plumbing.
umask 077
export PATH="$PATH:$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin:$HOME/.local/bin"

# --- logging ---
log(){ printf '[%s] %s\n' "$1" "$2" >&2; }
info(){ log INFO "$*"; }
warn(){ log WARN "$*"; }
die(){ log ERR "$*"; exit 1; }

have(){ command -v "$1" >/dev/null 2>&1; }
count(){ [[ -f $1 ]] && awk 'END{print NR+0}' "$1" || echo 0; }

# --- target & scope ---
# single mode -> only the exact host; full mode -> host and its subdomains.
normalize_target(){
  local t=${1#*://}; t=${t%%/*}; t=${t%%:*}; t=${t,,}; t=${t%.}
  [[ $t =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && $t == *.* && $t != *..* ]] || return 1
  printf '%s' "$t"
}
url_host(){ local u=${1#*://}; u=${u%%/*}; u=${u%%:*}; printf '%s' "${u,,}"; }
in_scope(){
  local h=${1,,}; h=${h%.}
  [[ $SCOPE_MODE == full ]] && { [[ $h == "$DOMAIN" || $h == *.$DOMAIN ]]; return; }
  [[ $h == "$DOMAIN" ]]
}
scope_url(){
  local u=$1
  [[ $u == http://* || $u == https://* ]] || return 1
  [[ $u != *[[:space:]@]* && ${#u} -le 8000 ]] || return 1
  in_scope "$(url_host "$u")"
}

# Reject private / reserved addresses so scans never reach internal ranges.
public_ipv4(){ awk -F. 'NF!=4{exit 1}{for(i=1;i<=4;i++)if($i!~/^[0-9]+$/||$i>255)exit 1;
  if($1==0||$1==10||$1==127||$1>=224||($1==169&&$2==254)||($1==172&&$2>=16&&$2<=31)||($1==192&&$2==168)||($1==100&&$2>=64&&$2<=127))exit 1; exit 0}' <<<"$1"; }
public_ipv6(){ local ip=${1,,}; [[ $ip =~ ^[23][0-9a-f]{3}: && $ip != 2001:db8:* && $ip != *%* ]]; }

filter_hosts(){ local s=$1 d=$2 h; : >"$d"; [[ -f $s ]] || return 0
  while IFS= read -r h || [[ -n $h ]]; do h=${h,,}; h=${h%.}
    [[ $h =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] && in_scope "$h" && printf '%s\n' "$h"
  done <"$s" | LC_ALL=C sort -u >"$d"; }
filter_urls(){ local s=$1 d=$2 u; : >"$d"; [[ -f $s ]] || return 0
  while IFS= read -r u || [[ -n $u ]]; do u=${u%%#*}; scope_url "$u" && printf '%s\n' "$u"; done \
    <"$s" | LC_ALL=C sort -u >"$d"; }

# --- selection ---
# Balance selected URLs across hosts and schemes, distinct param signatures first.
select_balanced(){
  local src=$1 dest=$2 limit=$3 root; root=$(mktemp -d)
  : >"$dest"; [[ -s $src ]] || { rm -rf "$root"; return 0; }
  ((limit==0)) && { cp "$src" "$dest"; rm -rf "$root"; return 0; }
  local url host proto grp
  while IFS= read -r url || [[ -n $url ]]; do
    scope_url "$url" || continue; host=$(url_host "$url"); proto=${url%%:*}
    printf '%s\n' "$url" >>"$root/$proto--$host"
  done <"$src"
  local order="$root/order"; : >"$order"
  for grp in "$root"/http*--*; do [[ -f $grp ]] || continue
    host=${grp##*--}; proto=${grp##*/}; proto=${proto%%--*}
    if   [[ $host == "$DOMAIN" && $proto == https ]]; then printf '0\t%s\n' "$grp"
    elif [[ $host == "$DOMAIN" ]]; then printf '1\t%s\n' "$grp"
    elif [[ $proto == https ]]; then printf '2\t%s\n' "$grp"
    else printf '3\t%s\n' "$grp"; fi >>"$order"
  done
  LC_ALL=C sort -t$'\t' -k1,1 -k2,2 "$order" | cut -f2 >"$root/keys"
  for grp in "$root"/http*--*; do [[ -f $grp ]] || continue
    awk '{u=$0;b=u;sub(/\?.*/,"",b);p=u;if(index(p,"?")==0)p="";else sub(/^.*\?/,"",p);gsub(/=[^&]*/,"=",p);
      s=b"?"p;if(!(s in d)){d[s]=1;print "0\t"u}else print "1\t"u}' "$grp" \
      | LC_ALL=C sort -s -t$'\t' -k1,1 | cut -f2- >"$grp.p"; mv "$grp.p" "$grp"
  done
  awk -v max="$limit" 'FNR==NR{keys[++k]=$0;next}{split($0,a,"\t");q[a[1],++n[a[1]]]=a[2]}
    END{c=0;go=1;while(c<max&&go){go=0;for(j=1;j<=k&&c<max;j++){key=keys[j];
      if(pos[key]<n[key]){pos[key]++;print q[key,pos[key]];c++;go=1}}}}' \
    "$root/keys" <(for grp in "$root"/http*--*; do [[ -f $grp ]] || continue
      while IFS= read -r url; do printf '%s\t%s\n' "$grp" "$url"; done <"$grp"; done) >"$dest"
  rm -rf "$root"
}
# One representative URL per (scheme, host, path, sorted param names).
param_signatures(){ local src=$1 dest=$2; : >"$dest"; [[ -s $src ]] || return 0
  awk '/\?/&&/=/{u=$0;h=u;sub(/^https?:\/\//,"",h);sub(/\/.*/,"",h);s=u;sub(/:.*/,"",s);
    p=u;sub(/^https?:\/\/[^\/]+/,"",p);sub(/\?.*/,"",p);q=u;sub(/^[^?]*\?/,"",q);n=split(q,v,"&");
    for(i=1;i<=n;i++){x=v[i];sub(/=.*/,"",x);nm[i]=x}
    for(i=2;i<=n;i++){x=nm[i];j=i-1;while(j>0&&nm[j]>x){nm[j+1]=nm[j];j--}nm[j+1]=x}
    key=s"|"h"|"p;for(i=1;i<=n;i++)key=key"|"nm[i];if(!(key in seen)){seen[key]=1;print u}}' \
    "$src" | LC_ALL=C sort -u >"$dest"; }

# --- tool supervisor ---
# run OUTFILE LABEL -- cmd ...   stdout->OUTFILE, stderr->log, bounded by $TIMEOUT.
run(){ local out=$1 label=$2; shift 2; local lg="$RUN/logs/$label.log" rc=0
  : >"$out"; : >"$lg"
  timeout --signal=TERM --kill-after=10s "${TIMEOUT}s" "$@" >"$out" 2>"$lg" || rc=$?
  printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$label" "$rc" >>"$RUN/commands.tsv"
  if ((rc!=0)); then STAGE_ERR=$((STAGE_ERR+1))
    ((rc==124||rc==137)) && warn "$label timed out (${TIMEOUT}s)" || warn "$label exited $rc — logs/$label.log"
  fi
  return "$rc"
}

# --- stage plumbing ---
skip(){ SKIP=$1; return 20; }
need(){ [[ -s $RUN/$1 ]] || skip "no input: ${1##*/}"; }
stage(){ local name=$1; shift; SKIP=''; STAGE_ERR=0; local start rc=0 st
  info "▶ $name"; start=$(date +%s); "$@" || rc=$?
  if   ((rc==20)); then st=SKIP
  elif ((rc!=0||STAGE_ERR>0)); then st=PARTIAL
  else st=OK; fi
  printf '%s\t%s\t%s\t%s\n' "$name" "$st" "$(( $(date +%s)-start ))" "$SKIP" >>"$RUN/stages.tsv"
  info "  $name: $st${SKIP:+ — $SKIP}"
}
