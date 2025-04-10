#!/bin/bash
# Ayon Chakraborty
# iamskidrow@gmail.com


# Variables
site=$1
site_name=${site#*.}
domain=$(echo $site | sed -e 's|^[^/]*//||' -e 's|/.*$||')
folder="$HOME/Automate"
wordlists="/Users/iamskidrow/wordlists"


# Checks before execution
if [[ -z $site ]]; then
  echo "Usage:"
  echo "$0 -d https://www.domain.com"
  echo ""
  exit 1
fi


cd $HOME
start_time=$(date +%s)


#Check if "Automate" exists in $HOME
if [ ! -d "$folder" ]
then
mkdir $folder 
fi

if [ -d "$folder/$domain" ] # Replacing if there are any previous directories
then
rm -rf "$folder/$domain"; mkdir "$folder/$domain"
else
mkdir "$folder/$domain" # Making a folder with the domain name
fi

# Path of scan data
cd "$folder/$domain"

# mkdir subdomains ips nuclei cors host-header-injection cmscheck urls fuzz sqli xss

clear
echo "[Output Path]"
echo "$folder/$domain/"
echo ""


# Gathering list of subdomains using multiple tools.
subdomains() {
  echo "[+] Getting Subdomains.."
  assetfinder --subs-only $domain >> assetfinder.txt &
  subfinder -silent -nW -d $domain >> subfinder.txt
}


# Checking for live domains; Creating seperate file with names only.
subdomains_filtering() {
  echo "[+] Filtering Subdomains.."
  sort -u assetfinder.txt subfinder.txt | httprobe -c 50 > subdomain-address.txt
  rm assetfinder.txt subfinder.txt
  cat subdomain-address.txt | sed -e 's|^[^/]*//||' -e 's|/.*$||' | sort -u > subdomain-names.txt
}


# Using gau to get all urls and using httpx to check working urls.
getallurls() {
  echo "[+] Getting urls and checking them.."
  cat subdomain-names.txt | gau --blacklist eot,ttf,woff,woff2,svg,jpg,jpeg,gif,png,pdf,css,js --threads 30  | httpx -silent -threads 50 -mc 200,204,401,403,406 -o urls.txt &> /dev/null
}


# Creates seperate list of urls having parameters.
url_parser() {
  echo "[+] Parsing them and creating a seperate file.."
  cat urls.txt | sed -e '/?/!d' -e '/=/!d' | qsreplace -a > parameters.txt
}


# # Dorking
# dork() {
#   echo "[+] Scanning site using dorks.."
#   while read s; do
#     go-dork -q "inurl:'login' site:'$s'" -p 10000
#   done < subdomain-address.txt
# }


# Extract Endpoints from JS File
# cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u


# Extract IPs from a File
# grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' file.txt


# Extract Endpoints from swagger.json
# curl -s https://domain.tld/v2/swagger.json | jq '.paths | keys[]'


# Checks for WAFs in every subdomain.
waf_check() {
  echo "[+] Checking for Firewalls.."
  wafw00f -i subdomain-address.txt -o waf.txt &> /dev/null
}


# Checks for open ports of every subdomain using naabu. 
ip_port_check() {
  echo "[+] Checking for open ports.."
  naabu -list subdomain-names.txt -exclude-ports 443,80,8080,8443 -c 50 -silent -o naabu.txt &> /dev/null
}


# Checks for any cms.
cmscheck() {
  echo "[+] Checking for Content Management Systems.."
  # cmscheck -d
}


# CRLF
crlf() {
  echo "[+] Looking for CRLF vulnerability.."
  crlfuzz -l subdomain-address.txt -s -o crlf.txt &> /dev/null
}


# Checks for Cors misconfigs.
cors() {
  echo "[+] Checking Cross-origin Resource Sharing misconfigurations.."

  if [[ $(curl -s -I -H "Origin: https://evil.com" -X GET $site | grep "https://evil.com") ]]; then
    echo "Found: [$site] => [Origin: https://evil.com]" >> cors.txt

  elif [[ $(curl -s -I -H "Origin: null" -X GET $site | grep "Access-Control-Allow-Origin: null") ]]; then
    echo "Found: [$site] => [Origin: null]" >> cors.txt

  elif [[ $(curl -s -I -H "Origin:" -X GET $site | grep "Access-Control-Allow-Origin: null") ]]; then
    echo "Found: [$site] => [Origin:]" >> cors.txt

  elif [[ $(curl -s -I -H "Origin: evil.$site_name" -X GET $site | grep "Access-Control-Allow-Origin: evil.$site_name") ]]; then
    echo "Found: [$site] => [Origin: evil.$site_name]" >> cors.txt

  elif [[ $(curl -s -I -H "Origin: https://not$site_name" -X GET $site | grep "Access-Control-Allow-Origin: https://not$site_name.com") ]]; then
    echo "Found: [$site] => [Origin: https://not$site_name]" >> cors.txt

  elif [[ $(curl -s -I -H "Origin: $site.evil.com" -X GET $site | grep "Access-Control-Allow-Origin: $site.evil.com") ]]; then
    echo "Found: [$site] => [Origin: $site.evil.com]" >> cors.txt

  elif [[ $(payloads=("!" "(" ")" "'" ";" "=" "^" "{" "}" "|" "~" '"' '`' "," "%60" "%0b"); for payload in ${payloads[*]}; do curl -s -I -H "Origin: $site$payload.evil.com" -X GET "$site"; done | grep "$site$payload.evil.com") ]]; then
    echo "Found: [$site] => [Origin: $site$payload.evil.com]" >> cors.txt
  fi
}


# Checks if subdomain takeover is possible.
subdomain_takeover() {
  echo "[+] Checking for subdomains takeovers.."
  # SubOver -a -t 50 -l subdomain-address.txt -v -o takeover.txt &> /dev/null
}


# Checking domains and urls for vulnerabilities.
vulnerability_scan() {
  echo "[+] Scanning for vulnerabilities.."
  nuclei -l subdomain-address.txt -silent -nc -nts -bs 50 -c 50 -o nuclei.txt &> /dev/null &
  dalfox file parameters.txt --waf-evasion --silence -w --output dalfox.txt &> /dev/null &
  sqlmap -m parameters.txt --answers="follow=Y" --batch --threads 10 --random-agent --ignore-proxy --output-dir="$folder/$domain/sqli/" &> /dev/null
}


# Fuzzing the site
fuzzing() {
  echo "[+] Fuzzing the target now.."

  # while read s; do
  #   ffuf -w $wordlists/ultimate.txt -u $site/FUZZ -s -mc 200,201,202,204,,301,302,307,401,402,403,405,406,429,500 -t 100 -o ffuf.txt
  # done < subdomain-address.txt
  
  # dirsearch
}


# Executing Functions

# Gathering Subdomains; Sorting & Filtering them.
subdomain_time=$(date +%s)
subdomains && subdomains_filtering
subdomain_time_end=$(date +%s)
echo "[DONE] Time took: $(($subdomain_time_end - $subdomain_time)) Seconds"
echo ""

# Getting URLs using gau and parsing them accordingly.
url_time=$(date +%s)
getallurls && url_parser
url_time_end=$(date +%s)
echo "[DONE] Time took: $(($url_time_end - $url_time)) Seconds"
echo ""

# # Scanning using dorks
# dork_time=$(date +%s)
# dork
# dork_time_end=$(date +%s)
# echo "[DONE] Time took: $(($dork_time_end - $dork_time)) Seconds"
# echo ""

# Checking for firewalls
waf_time=$(date +%s)
waf_check
waf_time_end=$(date +%s)
echo "[DONE] Time took: $(($waf_time_end - $waf_time)) Seconds"
echo ""

# Checking for open ports
ip_check_time=$(date +%s)
ip_port_check
ip_check_time_end=$(date +%s)
echo "[DONE] Time took: $(($ip_check_time_end - $ip_check_time)) Seconds"
echo ""

# Checking for cms
cmscheck_time=$(date +%s)
cmscheck
cmscheck_time_end=$(date +%s)
echo "[DONE] Time took: $(($cmscheck_time_end - $cmscheck_time)) Seconds"
echo ""

# Checking for open ports
crlf_time=$(date +%s)
crlf
crlf_time_end=$(date +%s)
echo "[DONE] Time took: $(($crlf_time_end - $crlf_time)) Seconds"
echo ""

# Checking for open ports
cors_time=$(date +%s)
cors
cors_time_end=$(date +%s)
echo "[DONE] Time took: $(($cors_time_end - $cors_time)) Seconds"
echo ""

# Checking for subdomain takeovers
subdomain_takeover_time=$(date +%s)
subdomain_takeover
subdomain_takeover_time_end=$(date +%s)
echo "[DONE] Time took: $(($subdomain_takeover_time_end - $subdomain_takeover_time)) Seconds"
echo ""

# Vulnerability scan execution
vulnerability_scan_time=$(date +%s)
vulnerability_scan
vulnerability_scan_time_end=$(date +%s)
echo "[DONE] Time took: $(($vulnerability_scan_time_end - $vulnerability_scan_time)) Seconds"
echo ""

# Fuzzing the site
fuzzing_time=$(date +%s)
fuzzing
fuzzing_time_end=$(date +%s)
echo "[DONE] Time took: $(($fuzzing_time_end - $fuzzing_time)) Seconds"
echo ""


end_time=$(date +%s)
echo "Total time took: $(($end_time - $start_time)) Seconds"



# https://github.com/six2dez/reconftw
# https://github.com/yogeshojha/rengine