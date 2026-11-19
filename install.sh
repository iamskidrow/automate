#!/usr/bin/env bash
# One-time dependency setup for Kali/Debian. Never runs during a scan.
set -uo pipefail
have(){ command -v "$1" >/dev/null 2>&1; }

APT=(jq curl dnsutils coreutils gawk git golang-go ca-certificates
  subfinder assetfinder dnsx httpx-toolkit naabu nmap nuclei ffuf dalfox sqlmap
  wafw00f crlfuzz subjack whatweb testssl.sh arjun gowitness trivy gitleaks)
GO=(
  'github.com/lc/gau/v2/cmd/gau@latest'
  'github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest'
  'github.com/tomnomnom/waybackurls@latest'
  'github.com/projectdiscovery/alterx/cmd/alterx@latest'
  'github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest'
  'github.com/projectdiscovery/tlsx/cmd/tlsx@latest'
  'github.com/projectdiscovery/asnmap/cmd/asnmap@latest'
  'github.com/projectdiscovery/katana/cmd/katana@latest'
  'github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest'
  'github.com/BishopFox/jsluice/cmd/jsluice@latest'
  'github.com/tomnomnom/gf@latest'
)

have apt-get || { echo 'Debian/Kali APT required'; exit 1; }
sudo apt-get update
for p in "${APT[@]}"; do
  apt-cache show "$p" >/dev/null 2>&1 || { echo "[skip] $p not in repo"; continue; }
  dpkg -s "$p" >/dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$p" || echo "[warn] apt $p"
done

have go || { echo '[warn] go missing; optional tools skipped'; exit 0; }
export PATH="$PATH:$(go env GOPATH)/bin"
rc="$HOME/.bashrc"; [[ ${SHELL:-} == *zsh* ]] && rc="$HOME/.zshrc"; touch "$rc"
grep -Fq 'go env GOPATH' "$rc" || echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >>"$rc"
for pkg in "${GO[@]}"; do
  bin=${pkg%@*}; bin=${bin##*/}
  have "$bin" && { echo "[ok] $bin"; continue; }
  echo "[go] $bin"; go install "$pkg" || echo "[warn] $bin failed"
done

# gf patterns.
if have gf && [[ ! -d $HOME/.gf ]]; then
  git clone -q https://github.com/tomnomnom/gf "$HOME/.gf" 2>/dev/null || true
  git clone -q https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp 2>/dev/null && cp /tmp/gfp/*.json "$HOME/.gf/" 2>/dev/null || true
fi
have nuclei && nuclei -ut -silent 2>/dev/null || true
echo '[done] run ./automate.sh --check'
