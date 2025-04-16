#Coded By AryaSec1337
#Combintaion Tools

# nuclei_scanner_prompted.py

import re
import subprocess
import sys
import json
import os
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich import box
from datetime import datetime
os.makedirs("output-json", exist_ok=True)

console = Console()

# (categories dictionary tetap seperti sebelumnya)
# (DOMAIN_REGEX, validate_domain, log_results, print_categories tetap sama)

categories = {
    "1": {"name": "Authentication Bypass", "prompts": [
        "Identify improperly configured OAuth authentication mechanisms.",
        "Scan for JWT vulnerabilities where authentication can be bypassed.",
        "Detect weak or publicly exposed API keys leading to authentication bypass.",
        "Identify authentication bypass vulnerabilities due to weak JWT token implementations.",
        "Identify login pages vulnerable to authentication bypass."
    ]},
    "2": {"name": "Broken Access Control", "prompts": [
        "Identify cases where unauthorized users can access privileged resources by modifying URLs.",
        "Scan for access control vulnerabilities that allow unauthorized access.",
        "Detect improper user authorization and privilege escalation vulnerabilities."
    ]},
    "3": {"name": "Command Injection", "prompts": [
        "Identify user input fields allowing shell command execution."
    ]},
    "4": {"name": "Directory Traversal", "prompts": [
        "Check for traversal vulnerabilities allowing PHP file inclusion.",
        "Identify directory traversal vulnerabilities using Windows-style file paths.",
        "Find vulnerabilities where absolute file paths can be exploited for unauthorized access.",
        "Identify directory traversal vulnerabilities allowing access to sensitive files.",
        "Detect sensitive files exposed via traversal attacks."
    ]},
    "5": {"name": "LFI/RFI Detection", "prompts": [
        "Check for Local and Remote File Inclusion vulnerabilities in file upload and inclusion mechanisms."
    ]},
    "6": {"name": "Hardcoded Credentials", "prompts": [
        "Scan for plaintext passwords stored in environment files and config files.",
        "Detect hardcoded API keys left inside JavaScript, Python, and other language files.",
        "Scan for AWS, Google Cloud, and Azure credentials embedded in source files.",
        "Identify hardcoded JSON Web Token (JWT) secrets that can be exploited for authentication bypass.",
        "Detect SSH private keys left in public repositories or web directories.",
        "Identify hardcoded database usernames and passwords in backend source code.",
        "Scan for exposed API keys in source code, configuration files, and logs.",
        "Scan js files and search for endpoints that includes parameters"
    ]},
    "7": {"name": "HTTP Smuggling Detection", "prompts": [
        "Find HTTP request smuggling vulnerabilities by testing different content-length and transfer encoding headers."
    ]},
    "8": {"name": "Insecure Direct Object References (IDOR)", "prompts": [
        "Detect insecure direct object references exposing unauthorized data."
    ]},
    "9": {"name": "JWT Token Vulnerabilities", "prompts": [
        "Check for weak JWT implementations and misconfigurations."
    ]},
    "10": {"name": "Race Condition", "prompts": [
        "Identify vulnerabilities where multiple parallel processes can manipulate shared resources."
    ]},
    "11": {"name": "Remote Code Execution (RCE)", "prompts": [
        "Scan for insecure file upload mechanisms that allow RCE.",
        "Identify unsafe function calls that may lead to remote command execution.",
        "Detect RCE vulnerabilities through insecure file upload mechanisms.",
        "Identify potential command injection vulnerabilities in input fields.",
        "Find potential remote command execution in input fields."
    ]},
    "12": {"name": "Security Misconfiguration", "prompts": [
        "Find cloud storage misconfigurations exposing sensitive data.",
        "Identify web applications exposing admin panels without authentication.",
        "Identify missing security headers such as CSP, X-Frame-Options, and HSTS.",
        "Scan for applications running with default credentials left unchanged.",
        "Scan for default credentials, exposed directories, and insecure headers.",
        "Identify outdated or vulnerable software, including web servers, frameworks, and third-party libraries, by checking for known CVEs, deprecated versions, and security misconfigurations.",
        "Detect the real IP address of a website protected by Cloudflare by analyzing misconfigurations, exposed headers, DNS records, and historical data leaks."
    ]},
    "13": {"name": "Server-Side Request Forgery (SSRF)", "prompts": [
        "Scan for SSRF vulnerabilities enabled due to misconfigured proxy servers.",
        "Identify SSRF vulnerabilities that exploit insecure header handling.",
        "Detect internal port scanning vulnerabilities using SSRF payloads.",
        "Identify SSRF vulnerabilities that allow open redirection to attacker-controlled servers.",
        "Find SSRF vulnerabilities allowing remote server requests."
    ]},
    "14": {"name": "SQL Injection", "prompts": [
        "Fuzz all parameters with sql injection detection payloads for mysql, mssql, postgresql, etc Use time base detection payloads",
        "Detect SQL injection vulnerabilities using time delay techniques.",
        "Identify second-order SQL injection vulnerabilities where input is stored and executed later.",
        "Identify SQL injection vulnerabilities using boolean-based conditions.",
        "Detect SQL injection vulnerabilities where UNION statements can be leveraged to extract data.",
        "Check for error messages revealing SQL queries.",
        "Use time-based techniques to find blind SQL injection."
    ]},
    "15": {"name": "XML External Entity (XXE)", "prompts": [
        "Identify XML External Entity attacks in web applications accepting XML input."
    ]},
    "16": {"name": "XSS (Cross-Site Scripting)", "prompts": [
        "Scan for XSS vulnerabilities inside inline event handlers such as onmouseover, onclick.",
        "Identify XSS vulnerabilities that bypass common web application firewalls.",
        "Identify stored XSS vulnerabilities where malicious scripts persist in the application.",
        "Find DOM-based XSS vulnerabilities where user input is reflected inside JavaScript execution.",
        "Identify reflected XSS vulnerabilities via GET parameters.",
        "Find common XSS patterns in response bodies."
    ]},
    "99": {"name": "Scan Semua", "prompts": []}
}

for key, cat in categories.items():
    if key != "99":
        categories["99"]["prompts"].extend(cat.get("prompts", []))

DOMAIN_REGEX = re.compile(r"^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$")

def validate_domain(domain: str) -> bool:
    return bool(DOMAIN_REGEX.match(domain))

def strip_ansi(text: str) -> str:
    return re.sub(r"\x1B\[[0-9;]*[a-zA-Z]", "", text)

def parse_plain_output(output: str):
    clean = strip_ansi(output)
    matches = re.findall(
        r"\[(?P<issue>[^\]]+)\]\s+\[(?P<category>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<url>https?://\S+)",
        clean
    )
    results = []
    for match in matches:
        issue, category, severity, url = match
        severity_clean = severity.strip().lower()

        # Tambahkan pewarnaan
        if severity_clean == 'low':
            sev_color = f"[green]{severity.strip()}[/green]"
        elif severity_clean == 'medium':
            sev_color = f"[orange3]{severity.strip()}[/orange3]"
        elif severity_clean == 'high':
            sev_color = f"[red]{severity.strip()}[/red]"
        elif severity_clean == 'critical':
            sev_color = f"[bold red]{severity.strip()}[/bold red]"
        else:
            sev_color = severity.strip()

        results.append({
            "Issue": issue.strip(),
            "Category": category.strip(),
            "Severity": sev_color,
            "URL": url.strip()
        })
    return results


def log_results(file, data):
    with open(file, "a") as f:
        f.write(data + "\n")

def print_categories():
    table = Table(title="\U0001F50E  Kategori Scan", box=box.ROUNDED, highlight=True)
    table.add_column("No", justify="center", style="cyan", no_wrap=True)
    table.add_column("Kategori", style="magenta")
    for k, v in sorted(categories.items(), key=lambda x: int(x[0]) if x[0] != "99" else 999):
        table.add_row(k, v["name"])
    console.print(table)

def scan(domain: str, selected: str):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    logfile = f"scan_result_{timestamp}.log"

    console.print(f"\n\U0001F4DD [bold yellow]Scanning kategori:[/bold yellow] {categories[selected]['name']}\n")

    for i, prompt in enumerate(categories[selected].get("prompts", []), 1):
        console.print(f"[bold cyan]Menjalankan Prompt {i}:[/bold cyan] {prompt}")
        log_results(logfile, f"[{datetime.now().isoformat()}] Prompt {i}: {prompt}")

        try:
            result = subprocess.run(
                ["nuclei", "-target", domain, "-ai", prompt, "-silent", "-ut"],
                capture_output=True,
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error saat eksekusi nuclei (prompt {i}):[/red] {e.stderr}")
            continue

        if not result.stdout.strip():
            console.print("[yellow]⛔ Tidak ditemukan kerentanan untuk prompt ini.[/yellow]")
            continue

        lines = result.stdout.strip().split("\n")
        vuln_found = False

        for line in lines:
            try:
                entry = json.loads(line)
                issue = entry.get("templateID", "-")
                value = entry.get("matcher-name") or (entry.get("extracted-results") or ["-"])[0]
                category = entry.get("info", {}).get("Category", "-")
                severity = entry.get("info", {}).get("Severity", "unknown")
                url = entry.get("host") or entry.get("matched-at", "-")

                block = f"✅ Kerentanan ditemukan:\nIssue     : {issue}\nCategory  : {category}\nSeverity  : {severity}\nURL       : {url}\n"
                console.print(block)
                log_results(logfile, block)
                vuln_found = True
            except json.JSONDecodeError as e:
                console.print(f"[dim]Gagal decode JSON: {e}[/dim]")
                parsed = parse_plain_output(line)
                if parsed:
                    for item in parsed:
                        block = f"✅ Kerentanan ditemukan:\nIssue     : {item.get('Issue', '-')}\nCategory  : {item.get('Category', '-')}\nSeverity  : {item.get('Severity', '-')}\nURL       : {item.get('URL', '-')}\n"
                        console.print(block)
                        log_results(logfile, block)
                        vuln_found = True
                else:
                    console.print("[grey]Output tidak bisa diparse menjadi JSON maupun plaintext match.[/grey]")

        if not vuln_found:
            console.print("[yellow]⛔ Tidak ditemukan kerentanan untuk prompt ini.[/yellow]")

    console.print(f"\n[green]Scan selesai. Hasil disimpan di file:[/green] {logfile}")

def main():
    ascii_art = r"""
    _   __           __     _    ____                             __ 
   / | / /_  _______/ /__  (_)  / __ \_________  ____ ___  ____  / /_
  /  |/ / / / / ___/ / _ \/ /  / /_/ / ___/ __ \/ __ `__ \/ __ \/ __/
 / /|  / /_/ / /__/ /  __/ /  / ____/ /  / /_/ / / / / / / /_/ / /_  
/_/ |_/\__,_/\___/_/\___/_/  /_/   /_/   \____/_/ /_/ /_/ .___/\__/  
                                                       /_/           
    """

    info = """
    Author    : AryaSec1337
    Description: Combination Nuclei + Ai Prompt
    """

    print(ascii_art + info)

    domain = Prompt.ask("Masukkan domain", default="https://example.com")
    if not validate_domain(domain):
        console.print("[bold red]Format domain tidak valid. Contoh: https://target.com[/bold red]")
        sys.exit(1)

    print_categories()
    selected = Prompt.ask("\nMasukkan nomor kategori (atau 99 untuk semua)")
    if selected not in categories:
        console.print("[bold red]Kategori tidak valid[/bold red]")
        sys.exit(1)

    scan(domain, selected)

if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()
