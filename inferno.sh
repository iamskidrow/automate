#!/bin/bash
# Improved Reconnaissance Script

# Variables
site=$1
site_name=${site#*.}
domain=$(echo "$site" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
folder="$HOME/Automate"
wordlists="$HOME/wordlists"
threads=50
concurrency=25
httpcode="200,204,401,403,406"

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function for displaying messages
log_message() {
  echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
  echo -e "${GREEN}[+]${NC} $1"
}

log_warning() {
  echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
  echo -e "${RED}[-]${NC} $1"
}

# Function to check if a tool is installed
check_tool() {
  if ! command -v "$1" &> /dev/null; then
    log_error "$1 is not installed. Please install it before running this script."
    return 1
  fi
  return 0
}

# Function to check all required dependencies
check_dependencies() {
  log_message "Checking dependencies..."

  tools=("subfinder" "assetfinder" "httprobe" "gau" "httpx" "qsreplace" "naabu" "wafw00f"
         "subjack" "nuclei" "sqlmap" "crlfuzz" "ffuf" "dalfox")
  missing_tools=()

  for tool in "${tools[@]}"; do
    if ! check_tool "$tool"; then
      # shellcheck disable=SC2206
      missing_tools+=($tool)
    fi
  done

  if [ ${#missing_tools[@]} -ne 0 ]; then
    log_error "Missing tools: ${missing_tools[*]}"
    log_error "Please install the missing tools and try again."
    exit 1
  fi

  log_success "All dependencies satisfied!"
  return 0
}

# Function to create directories
setup_directories() {
  log_message "Setting up directories..."

  if [ ! -d "$folder" ]; then
    mkdir -p "$folder" || { log_error "Failed to create $folder"; exit 1; }
  fi

  if [ -d "$folder/$domain" ]; then
    # shellcheck disable=SC2115
    rm -rf "$folder/$domain" || { log_error "Failed to remove existing directory"; exit 1; }
  fi

  mkdir -p "$folder/$domain" || { log_error "Failed to create domain directory"; exit 1; }
  cd "$folder/$domain" || { log_error "Failed to change to domain directory"; exit 1; }

  # Create subdirectories for organized output
  mkdir -p "$folder/$domain/sqli" || { log_error "Failed to create sqli directory"; exit 1; }

  log_success "Directories setup complete. Results will be saved to $folder/$domain/"
}

# Function to gather subdomains with multiple tools
gather_subdomains() {
  log_message "Gathering subdomains using multiple tools..."

  # Run assetfinder and subfinder in parallel
  assetfinder --subs-only "$domain" > assetfinder_output.txt || {
    log_error "Assetfinder failed to execute correctly"
    touch assetfinder_output.txt
  }

  subfinder -silent -nW -d "$domain" -t $threads > subfinder_output.txt || {
    log_error "Subfinder failed to execute correctly"
    touch subfinder_output.txt
  }

  # Combine outputs, sort and remove duplicates
  sort -u assetfinder_output.txt subfinder_output.txt | httprobe -c $threads > subdomains.txt || {
    log_error "Httprobe failed to execute correctly"
    touch subdomains.txt
  }

  # Extract domain names only (no protocol/path)
  if [ -s subdomains.txt ]; then
    cat subdomains.txt | sed -e 's|^[^/]*//||' -e 's|/.*$||' | sort -u > subdomains-alt.txt
    count=$(wc -l < subdomains.txt)
    log_success "Found $count subdomains"
  else
    log_warning "No subdomains found"
    touch subdomains-alt.txt
  fi

  # Clean up intermediate files
  rm assetfinder_output.txt subfinder_output.txt
}

# Function to gather URLs
gather_urls() {
  log_message "Gathering URLs..."

  if [ -s subdomains-alt.txt ]; then
    cat subdomains-alt.txt | gau --blacklist eot,ttf,woff,woff2,svg,jpg,jpeg,gif,png,pdf,css,js --threads 30 2>/dev/null | \
    httpx -silent -threads $threads -mc $httpcode -o urls.txt || {
      log_error "URL gathering process failed"
      touch urls.txt
    }
  else
    echo "$domain" | gau --blacklist eot,ttf,woff,woff2,svg,jpg,jpeg,gif,png,pdf,css,js --threads 30 2>/dev/null | \
    httpx -silent -threads $threads -mc $httpcode -o urls.txt || {
      log_error "URL gathering process failed"
      touch urls.txt
    }
  fi

  if [ -s urls.txt ]; then
    count=$(wc -l < urls.txt)
    log_success "Found $count URLs"
  else
    log_warning "No URLs found"
  fi
}

# Function to extract parameters
extract_parameters() {
  log_message "Extracting URL parameters..."

  if [ -s urls.txt ]; then
    # Extract URLs with parameters (must have ? and =)
    cat urls.txt | sed -e '/?/!d' -e '/=/!d' | qsreplace -a > parameters.txt || {
      log_error "Parameter extraction failed"
      touch parameters.txt
    }

    if [ -s parameters.txt ]; then
      count=$(wc -l < parameters.txt)
      log_success "Found $count URLs with parameters"
    else
      log_warning "No parameters found"
    fi
  else
    touch parameters.txt
    log_warning "No URLs to extract parameters from"
  fi
}

# Function to scan ports
scan_ports() {
  log_message "Scanning for open ports..."

  if [ -s subdomains-alt.txt ]; then
    naabu -list subdomains-alt.txt -exclude-ports 443,80,8080,8443 -c $concurrency -silent -o ports.txt || {
      log_error "Port scanning failed"
      touch ports.txt
    }
  else
    naabu -host "$domain" -exclude-ports 443,80,8080,8443 -c $concurrency -silent -o ports.txt || {
      log_error "Port scanning failed"
      touch ports.txt
    }
  fi

  if [ -s ports.txt ]; then
    count=$(wc -l < ports.txt)
    log_success "Found $count open ports"
  else
    log_warning "No open ports found"
  fi
}

# Function to check for WAF
check_waf() {
  log_message "Checking for Web Application Firewalls..."

  if [ -s subdomains.txt ]; then
    wafw00f -i subdomains.txt -o waf.txt || {
      log_error "WAF detection failed"
      touch waf.txt
    }
  else
    wafw00f "$site" -o waf.txt || {
      log_error "WAF detection failed"
      touch waf.txt
    }
  fi

  if grep -q "WEB APPLICATION FIREWALL" waf.txt 2>/dev/null; then
    log_success "WAF detection complete"
  else
    log_warning "No WAF detected or detection failed"
  fi
}

# Function to check for CORS misconfigurations
check_cors() {
  log_message "Checking for CORS misconfigurations..."

  if [ -f cors.txt ]; then
    rm cors.txt
  fi
  touch cors.txt

  if [[ $(curl -s -I -H "Origin: https://evil.com" -X GET "$site" | grep "https://evil.com") ]]; then
    echo "Found: [$site] => [Origin: https://evil.com]" >> cors.txt
  fi

  if [[ $(curl -s -I -H "Origin: null" -X GET "$site" | grep "Access-Control-Allow-Origin: null") ]]; then
    echo "Found: [$site] => [Origin: null]" >> cors.txt
  fi

  if [[ $(curl -s -I -H "Origin:" -X GET "$site" | grep "Access-Control-Allow-Origin: null") ]]; then
    echo "Found: [$site] => [Origin:]" >> cors.txt
  fi

  if [[ $(curl -s -I -H "Origin: evil.$site_name" -X GET "$site" | grep "Access-Control-Allow-Origin: evil.$site_name") ]]; then
    echo "Found: [$site] => [Origin: evil.$site_name]" >> cors.txt
  fi

  if [[ $(curl -s -I -H "Origin: https://not$site_name" -X GET "$site" | grep "Access-Control-Allow-Origin: https://not$site_name.com") ]]; then
    echo "Found: [$site] => [Origin: https://not$site_name]" >> cors.txt
  fi

  if [[ $(curl -s -I -H "Origin: $site.evil.com" -X GET "$site" | grep "Access-Control-Allow-Origin: $site.evil.com") ]]; then
    echo "Found: [$site] => [Origin: $site.evil.com]" >> cors.txt
  fi

  # Test with special characters
  payloads=("!" "(" ")" "'" ";" "=" "^" "{" "}" "|" "~" '"' '`' "," "%60" "%0b")
  for payload in "${payloads[@]}"; do
    if curl -s -I -H "Origin: $site$payload.evil.com" -X GET "$site" | grep -q "$site$payload.evil.com"; then
      echo "Found: [$site] => [Origin: $site$payload.evil.com]" >> cors.txt
    fi
  done

  if [ -s cors.txt ]; then
    count=$(grep -c "Found:" cors.txt)
    log_success "Found $count CORS misconfigurations"
  else
    log_warning "No CORS misconfigurations found"
  fi
}

# Function to check for CRLF vulnerabilities
check_crlf() {
  log_message "Checking for CRLF vulnerabilities..."

  if [ -s subdomains.txt ]; then
    crlfuzz -l subdomains.txt -s -o crlf.txt || {
      log_error "CRLF testing failed"
      touch crlf.txt
    }
  else
    crlfuzz -u "$site" -s -o crlf.txt || {
      log_error "CRLF testing failed"
      touch crlf.txt
    }
  fi

  if [ -s crlf.txt ]; then
    count=$(wc -l < crlf.txt)
    log_success "Found $count potential CRLF vulnerabilities"
  else
    log_warning "No CRLF vulnerabilities found"
  fi
}

# Function to check for CMS
check_cms() {
  log_message "Checking for Content Management Systems..."

  # Since the original script had a placeholder here, we'll implement a basic
  # detection using common CMS paths and signatures
  touch cms.txt

  if [ -s subdomains.txt ]; then
    for subdomain in $(cat subdomains.txt); do
      # Check for WordPress
      if curl -s "$subdomain/wp-login.php" | grep -q "WordPress"; then
        echo "$subdomain - WordPress detected" >> cms.txt
      fi

      # Check for Joomla
      if curl -s "$subdomain/administrator" | grep -q "Joomla"; then
        echo "$subdomain - Joomla detected" >> cms.txt
      fi

      # Check for Drupal
      if curl -s "$subdomain/user/login" | grep -q "Drupal"; then
        echo "$subdomain - Drupal detected" >> cms.txt
      fi
    done
  else
    # Check main domain
    if curl -s "$site/wp-login.php" | grep -q "WordPress"; then
      echo "$site - WordPress detected" >> cms.txt
    fi

    if curl -s "$site/administrator" | grep -q "Joomla"; then
      echo "$site - Joomla detected" >> cms.txt
    fi

    if curl -s "$site/user/login" | grep -q "Drupal"; then
      echo "$site - Drupal detected" >> cms.txt
    fi
  fi

  if [ -s cms.txt ]; then
    count=$(wc -l < cms.txt)
    log_success "Identified $count CMS instances"
  else
    log_warning "No CMS detected"
  fi
}

# Function to check for subdomain takeover
check_takeover() {
  log_message "Checking for subdomain takeover vulnerabilities..."

  if [ -s subdomains.txt ]; then
    # Using subjack instead of SubOver as in original
    subjack -a -ssl -w subdomains.txt -t $threads -o takeover.txt || {
      log_error "Subdomain takeover check failed"
      touch takeover.txt
    }

    if [ -s takeover.txt ]; then
      log_success "Subdomain takeover check complete"
    else
      log_warning "No subdomain takeover vulnerabilities found"
    fi
  else
    touch takeover.txt
    log_warning "No subdomains to check for takeover"
  fi
}

# Function to run fuzzing
run_fuzzing() {
  log_message "Fuzzing directories and files..."

  if [ -f "$wordlists/ultimate.txt" ]; then
    wordlist="$wordlists/ultimate.txt"
  else
    log_warning "Wordlist not found at $wordlists/ultimate.txt. Using default wordlist."
    wordlist="/usr/share/wordlists/dirb/common.txt"
  fi

  if [ -s subdomains.txt ]; then
    # Take a subset of the first 5 subdomains for more focused fuzzing
    head -5 subdomains.txt > fuzz_targets.txt

    for target in $(cat fuzz_targets.txt); do
      ffuf -w "$wordlist" -u "$target/FUZZ" -s -mc 200,201,202,204,301,302,307,401,402,403,405,406,429,500 \
        -t 100 -o "ffuf_$(echo "$target" | sed 's/[^a-zA-Z0-9]/_/g').json" -of json || {
        log_error "Fuzzing failed for $target"
      }
    done

    # Combine results
    find . -name "ffuf_*.json" -exec jq -r '.results[] | .url' {} \; > fuzzing_results.txt

    if [ -s fuzzing_results.txt ]; then
      count=$(wc -l < fuzzing_results.txt)
      log_success "Found $count resources during fuzzing"
    else
      log_warning "No resources found during fuzzing"
    fi
  else
    ffuf -w "$wordlist" -u "$site/FUZZ" -s -mc 200,201,202,204,301,302,307,401,402,403,405,406,429,500 \
      -t 100 -o ffuf.json -of json || {
      log_error "Fuzzing failed for $site"
    }

    if [ -f ffuf.json ]; then
      jq -r '.results[] | .url' ffuf.json > fuzzing_results.txt
      count=$(wc -l < fuzzing_results.txt)
      log_success "Found $count resources during fuzzing"
    else
      log_warning "No resources found during fuzzing"
    fi
  fi
}

# Function to run Nuclei
run_nuclei() {
  log_message "Running Nuclei vulnerability scanner..."

  if [ -s urls.txt ]; then
    nuclei -silent -l urls.txt -nc -nts -bs 50 -c $concurrency -o nuclei.txt || {
      log_error "Nuclei scan failed"
      touch nuclei.txt
    }

    if [ -s nuclei.txt ]; then
      count=$(wc -l < nuclei.txt)
      log_success "Nuclei found $count potential vulnerabilities"
    else
      log_warning "No vulnerabilities found by Nuclei"
    fi
  else
    touch nuclei.txt
    log_warning "No URLs to scan with Nuclei"
  fi
}

# Function to run SQLMap
run_sqlmap() {
  log_message "Running SQLMap for SQL injection testing..."

  if [ -s parameters.txt ]; then
    sqlmap -m parameters.txt --answers="follow=Y" --batch --threads 10 \
    --random-agent --ignore-proxy --output-dir="$folder/$domain/sqli/" || {
      log_error "SQLMap scan failed"
    }

    if [ -d "$folder/$domain/sqli" ] && [ "$(ls -A "$folder/$domain/sqli")" ]; then
      log_success "SQLMap scan complete"
    else
      log_warning "No SQL injections found"
    fi
  else
    log_warning "No parameters to test with SQLMap"
  fi
}

# Function to run XSS testing with Dalfox
run_xss() {
  log_message "Scanning for XSS vulnerabilities with Dalfox..."

  if [ -s parameters.txt ]; then
    dalfox file parameters.txt --waf-evasion --silence -w --output dalfox.txt || {
      log_error "Dalfox scan failed"
      touch dalfox.txt
    }

    if [ -s dalfox.txt ]; then
      count=$(wc -l < dalfox.txt)
      log_success "Dalfox found $count potential XSS vulnerabilities"
    else
      log_warning "No XSS vulnerabilities found"
    fi
  else
    log_warning "No parameters to test with Dalfox"
  fi
}

# Main function
main() {
  clear
  echo "========================================"
  echo "    Comprehensive Web Recon Tool        "
  echo "========================================"
  echo ""

  # Check if domain is provided
  if [ -z "$site" ]; then
    log_error "No domain provided"
    echo "Usage: $0 https://www.domain.com"
    exit 1
  fi

  # Record start time
  start_time=$(date +%s)

  # Check dependencies
  check_dependencies

  # Setup directories
  setup_directories

  # Run each function and measure time
  function_start_time=$(date +%s)
  gather_subdomains
  log_message "Subdomain gathering took $(($(date +%s) - function_start_time)) seconds"

  function_start_time=$(date +%s)
  gather_urls
  log_message "URL gathering took $(($(date +%s) - function_start_time)) seconds"

  function_start_time=$(date +%s)
  extract_parameters
  log_message "Parameter extraction took $(($(date +%s) - function_start_time)) seconds"

  # Run the following tasks in parallel to optimize resource usage
  log_message "Starting parallel tasks..."

  scan_ports &
  port_pid=$!

  check_waf &
  waf_pid=$!

  check_cors &
  cors_pid=$!

  check_crlf &
  crlf_pid=$!

  check_cms &
  cms_pid=$!

  check_takeover &
  takeover_pid=$!

  # Wait for parallel tasks to complete
  wait $port_pid
  wait $waf_pid
  wait $cors_pid
  wait $crlf_pid
  wait $cms_pid
  wait $takeover_pid

  # Run fuzzing
  function_start_time=$(date +%s)
  run_fuzzing
  log_message "Fuzzing took $(($(date +%s) - function_start_time)) seconds"

  # Run vulnerability scanners in parallel
  log_message "Starting vulnerability scanners..."

  function_start_time=$(date +%s)
  run_nuclei &
  nuclei_pid=$!

  run_sqlmap &
  sqlmap_pid=$!

  run_xss &
  xss_pid=$!

  # Wait for vulnerability scanners to complete
  wait $nuclei_pid
  log_message "Nuclei scan took $(($(date +%s) - function_start_time)) seconds"

  wait $sqlmap_pid
  wait $xss_pid

  # Calculate total execution time
  end_time=$(date +%s)
  total_time=$((end_time - start_time))

  # Generate summary report
  echo "" > summary.txt
  echo "=== RECONNAISSANCE SUMMARY ===" >> summary.txt
  echo "Target: $site" >> summary.txt
  echo "Date: $(date)" >> summary.txt
  echo "" >> summary.txt
  echo "Subdomains found: $(wc -l < subdomains.txt 2>/dev/null || echo 0)" >> summary.txt
  echo "URLs discovered: $(wc -l < urls.txt 2>/dev/null || echo 0)" >> summary.txt
  echo "Parameter URLs: $(wc -l < parameters.txt 2>/dev/null || echo 0)" >> summary.txt
  echo "Open ports: $(wc -l < ports.txt 2>/dev/null || echo 0)" >> summary.txt
  echo "Nuclei findings: $(wc -l < nuclei.txt 2>/dev/null || echo 0)" >> summary.txt
  echo "CORS issues: $(grep -c "Found:" cors.txt 2>/dev/null || echo 0)" >> summary.txt
  echo "CRLF issues: $(wc -l < crlf.txt 2>/dev/null || echo 0)" >> summary.txt
  echo "XSS findings: $(wc -l < dalfox.txt 2>/dev/null || echo 0)" >> summary.txt
  echo "" >> summary.txt
  echo "Total execution time: $total_time seconds" >> summary.txt

  echo ""
  echo "========================================"
  log_success "Scan complete!"
  log_success "Total execution time: $total_time seconds"
  log_success "Results saved to: $folder/$domain/"
  log_success "Summary report saved to: $folder/$domain/summary.txt"
  echo "========================================"
}

# Run the main function
main