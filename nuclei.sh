#!/bin/bash

# Coded By AryaSec1337
# Validasi apakah nuclei tersedia
if ! command -v nuclei &> /dev/null; then
  echo -e "\e[31m[✘] Error: nuclei tidak ditemukan. Harap instal terlebih dahulu.\e[0m"
  exit 1
fi

# Meminta input
read -p $'Masukkan domain: ' domain
if [[ -z "$domain" ]]; then
  echo -e "\e[31m[✘] Error: Domain tidak boleh kosong.\e[0m"
  exit 1
fi

# Daftar prompt AI nuclei
ai_prompts=(
  "Identify improperly configured OAuth authentication mechanisms."
  "Scan for JWT vulnerabilities where authentication can be bypassed."
  "Detect weak or publicly exposed API keys leading to authentication bypass."
  "Identify authentication bypass vulnerabilities due to weak JWT token implementations."
  "Identify login pages vulnerable to authentication bypass."
  "Identify cases where unauthorized users can access privileged resources by modifying URLs."
  "Scan for access control vulnerabilities that allow unauthorized access."
  "Detect improper user authorization and privilege escalation vulnerabilities."
  "Identify user input fields allowing shell command execution."
  "Check for traversal vulnerabilities allowing PHP file inclusion."
  "Identify directory traversal vulnerabilities using Windows-style file paths."
  "Find vulnerabilities where absolute file paths can be exploited for unauthorized access."
  "Identify directory traversal vulnerabilities allowing access to sensitive files."
  "Detect sensitive files exposed via traversal attacks."
  "Check for Local and Remote File Inclusion vulnerabilities in file upload and inclusion mechanisms."
  "Scan for plaintext passwords stored in environment files and config files."
  "Detect hardcoded API keys left inside JavaScript, Python, and other language files."
  "Scan for AWS, Google Cloud, and Azure credentials embedded in source files."
  "Identify hardcoded JSON Web Token (JWT) secrets that can be exploited for authentication bypass."
  "Detect SSH private keys left in public repositories or web directories."
  "Identify hardcoded database usernames and passwords in backend source code."
  "Scan for exposed API keys in source code, configuration files, and logs."
  "Find HTTP request smuggling vulnerabilities by testing different content-length and transfer encoding headers."
  "Detect insecure direct object references exposing unauthorized data."
  "Check for weak JWT implementations and misconfigurations."
  "Identify vulnerabilities where multiple parallel processes can manipulate shared resources."
  "Scan for insecure file upload mechanisms that allow RCE."
  "Identify unsafe function calls that may lead to remote command execution."
  "Detect RCE vulnerabilities through insecure file upload mechanisms."
  "Identify potential command injection vulnerabilities in input fields."
  "Find potential remote command execution in input fields."
  "Find cloud storage misconfigurations exposing sensitive data."
  "Identify web applications exposing admin panels without authentication."
  "Identify missing security headers such as CSP, X-Frame-Options, and HSTS."
  "Scan for applications running with default credentials left unchanged."
  "Scan for default credentials, exposed directories, and insecure headers."
  "Scan for SSRF vulnerabilities enabled due to misconfigured proxy servers."
  "Identify SSRF vulnerabilities that exploit insecure header handling."
  "Detect internal port scanning vulnerabilities using SSRF payloads."
  "Identify SSRF vulnerabilities that allow open redirection to attacker-controlled servers."
  "Find SSRF vulnerabilities allowing remote server requests."
  "Fuzz all parameters with sql injection detection payloads for mysql, mssql, postgresql, etc Use time base detection payloads"
  "Detect SQL injection vulnerabilities using time delay techniques."
  "Identify second-order SQL injection vulnerabilities where input is stored and executed later."
  "Identify SQL injection vulnerabilities using boolean-based conditions."
  "Detect SQL injection vulnerabilities where UNION statements can be leveraged to extract data."
  "Check for error messages revealing SQL queries."
  "Use time-based techniques to find blind SQL injection."
  "Identify XML External Entity attacks in web applications accepting XML input."
  "Scan for XSS vulnerabilities inside inline event handlers such as onmouseover, onclick."
  "Identify XSS vulnerabilities that bypass common web application firewalls."
  "Identify stored XSS vulnerabilities where malicious scripts persist in the application."
  "Find DOM-based XSS vulnerabilities where user input is reflected inside JavaScript execution."
  "Identify reflected XSS vulnerabilities via GET parameters."
  "Find common XSS patterns in response bodies."
)

# Warna
green="\e[32m"
red="\e[31m"
blue="\e[34m"
yellow="\e[33m"
reset="\e[0m"

# Scan tiap prompt
for prompt in "${ai_prompts[@]}"; do
  echo -e "${yellow}[●] Memindai: $prompt${reset}"
  hasil=$(nuclei -target "$domain" -ai "$prompt" -silent 2>/dev/null)

  if [[ -z "$hasil" ]]; then
    echo -e "${red}[✘] Tidak ditemukan kerentanan.${reset}\n"
  else
    echo -e "${green}[✔] Ditemukan kerentanan:${reset}"
    echo -e "$hasil\n"
  fi

done

echo -e "\n${green}[✓] Penilaian selesai pada domain: $domain${reset}"
exit 0
