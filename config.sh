#!/usr/bin/env bash
# Central configuration. One value per concern, applied to every tool.
# Override any value from the environment: THREADS=100 ./automate.sh target

# Performance — sized for ~11 cores / 11 GB. These are the only knobs most runs need.
THREADS="${THREADS:-60}"          # worker threads   (-t / --threads)
CONCURRENCY="${CONCURRENCY:-40}"  # parallel hosts   (-c / fetchers)
RATE="${RATE:-150}"               # requests/second  (-rl / -rate / --rate-limit)
HTTP_TIMEOUT="${HTTP_TIMEOUT:-10}" # per-request timeout (seconds)
RETRIES="${RETRIES:-1}"
TIMEOUT="${TIMEOUT:-1800}"        # wall-clock cap per tool invocation (seconds)

# Scope budgets — 0 means unlimited.
MAX_HOSTS="${MAX_HOSTS:-0}"       # live hosts carried into active scans
MAX_URLS="${MAX_URLS:-20000}"     # URLs probed/scanned
MAX_PARAMS="${MAX_PARAMS:-300}"   # parameter signatures tested
MAX_DNS="${MAX_DNS:-10000}"       # permutation candidates resolved
CRAWL_DEPTH="${CRAWL_DEPTH:-3}"
FUZZ_WORDS="${FUZZ_WORDS:-4000}"  # directory wordlist entries used

# Nuclei coverage — tag/severity filtered, no template-count cap.
NUCLEI_TAGS="${NUCLEI_TAGS:-cve,exposure,misconfig,tech,default-login,takeover}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-critical,high,medium,low}"
NUCLEI_EXCLUDE="${NUCLEI_EXCLUDE:-dos,fuzz,intrusive,bruteforce}"

# Paths.
OUTPUT_ROOT="${OUTPUT_ROOT:-$HOME/Automate}"
WORDLIST="${WORDLIST:-/usr/share/wordlists/dirb/common.txt}"

# Optional tools — auto-skip when their input/credentials are absent.
ENABLE_AMASS="${ENABLE_AMASS:-0}"          # off: times out on this host (libpostal)
ENABLE_SCREENSHOTS="${ENABLE_SCREENSHOTS:-1}"
ENABLE_OOB="${ENABLE_OOB:-0}"              # Nuclei Interactsh callbacks (external infra)
