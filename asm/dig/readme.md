Project Name: DNS-ASM Recon Suite
A lightweight, modular Bash utility for Attack Surface Management (ASM) and DNS infrastructure auditing.

This tool automates the collection of critical DNS records (ANY, A, SPF) and enriches them with IP metadata, WHOIS ownership details, and Shodan InternetDB insights.

Key Features
SPF Auditing: Identifies sender policy frameworks for mail security assessment.
ANY Record Discovery: Pulls SOA, MX, and Name Server data to map administrative boundaries.
Automated Enrichment: Resolves discovered hostnames to IPv4/IPv6 addresses and performs automated WHOIS parsing.
Shodan Integration: Queries the InternetDB API for open ports and vulnerabilities associated with discovered IPs.
Clean Output: Generates structured CSVs and JSON files ready for intake into Splunk, ELK, or Excel.

Usage
Bash
chmod +x dns_recon.sh
./dns_recon.sh -i targets.txt -f client_name -o ./reports/
