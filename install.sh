#!/usr/bin/env bash
# One-time dependency setup for Kali/Debian. Never runs during a scan.
set -uo pipefail
have(){ command -v "$1" >/dev/null 2>&1; }

APT=(jq curl dnsutils coreutils gawk git golang-go ca-certificates pipx
  subfinder assetfinder dnsx httpx-toolkit naabu nmap nuclei ffuf dalfox sqlmap
  wafw00f crlfuzz whatweb testssl.sh arjun gowitness trufflehog wpscan)
GO=(
  'github.com/lc/gau/v2/cmd/gau@latest'
  'github.com/projectdiscovery/alterx/cmd/alterx@latest'
  'github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest'
  'github.com/projectdiscovery/tlsx/cmd/tlsx@latest'
  'github.com/projectdiscovery/asnmap/cmd/asnmap@latest'
  'github.com/projectdiscovery/katana/cmd/katana@latest'
  'github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest'
  'github.com/BishopFox/jsluice/cmd/jsluice@latest'
  'github.com/tomnomnom/gf@latest'
  'github.com/tomnomnom/anew@latest'
)
PIPX=(waymore s3scanner 'git+https://github.com/initstring/cloud_enum')

have apt-get || { echo 'Debian/Kali APT required'; exit 1; }
sudo apt-get update
for p in "${APT[@]}"; do
  apt-cache show "$p" >/dev/null 2>&1 || { echo "[skip] $p not in repo"; continue; }
  dpkg -s "$p" >/dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$p" || echo "[warn] apt $p"
done

export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin:$HOME/.local/bin"
rc="$HOME/.bashrc"; [[ ${SHELL:-} == *zsh* ]] && rc="$HOME/.zshrc"; touch "$rc"
grep -Fq 'go env GOPATH' "$rc" || echo 'export PATH="$PATH:$(go env GOPATH)/bin:$HOME/.local/bin"' >>"$rc"

if have go; then
  for pkg in "${GO[@]}"; do bin=${pkg%@*}; bin=${bin##*/}
    have "$bin" && { echo "[ok] $bin"; continue; }
    echo "[go] $bin"; go install "$pkg" || echo "[warn] $bin failed"
  done
else echo '[warn] go missing; Go tools skipped'; fi

if have pipx; then
  pipx ensurepath >/dev/null 2>&1 || true
  for p in "${PIPX[@]}"; do echo "[pipx] $p"; pipx install "$p" 2>/dev/null || echo "[warn] pipx $p"; done
else echo '[warn] pipx missing; waymore/s3scanner/cloud_enum skipped'; fi

# gf patterns.
if have gf && [[ ! -d $HOME/.gf ]]; then
  git clone -q https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp 2>/dev/null && mkdir -p "$HOME/.gf" && cp /tmp/gfp/*.json "$HOME/.gf/" 2>/dev/null || true
fi
have nuclei && nuclei -ut -silent 2>/dev/null || true
have wpscan && wpscan --update --no-banner 2>/dev/null || true

# Optional (not auto-installed): x8 (needs Rust: cargo install x8), dnsReaper (pipx git+https://github.com/punk-security/dnsReaper).
echo '[done] run ./automate.sh --check'
