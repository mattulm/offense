#!/bin/bash 

# Target Domain configuration 
DOMAIN="domain.com" 
OUTPUT_DIR="./Recon" 
JSON_OUT="$OUTPUT_DIR/subdomains.json" 

# Ensure output directory exists mkdir -p "$OUTPUT_DIR" 
echo "[*] Launching passive discovery on $DOMAIN..." 

# Professional subfinder workflow: 
# -all: Maximize source coverage 
# -silent: Output only the results 
# -duc: Skip overhead update checks 
# -oJ: Structured JSON output for downstream tools 

subfinder -d "$DOMAIN" -all -silent -duc -oJ -o "$JSON_OUT" 

# Verify discovery results 
if [[ -s "$JSON_OUT" ]]; then 
	echo "[+] Discovery complete. Results found:" 
	echo "------------------------------------------------" 
	# Parse JSON to display the host and the source that discovered it 
	cat "$JSON_OUT" | jq -r '"Host: \(.host) | Source: \(.source)"' 
	echo "------------------------------------------------" 
	echo "[*] Full JSON report saved to: $JSON_OUT" 
else 
	echo "[-] No subdomains found or error during execution." 
fi
