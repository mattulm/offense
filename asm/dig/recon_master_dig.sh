#!/bin/bash

## --- Defaults and Argument Parsing ---
d=$(date +"%Y%m%d")
t=$(date +"%H%M")
prefix="recon"
out_dir="."

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -i|--input) input_file="$2"; shift ;;
        -f|--filename) prefix="$2"; shift ;;
        -o|--output) out_dir="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$input_file" ]; then
    echo "Usage: $0 -i <input_list> [-f <prefix>] [-o <output_dir>]"
    exit 1
fi

# Create output directory if specified and missing
mkdir -p "$out_dir"

## --- Module 1: SPF Records ---
run_spf_check() {
    local out="$out_dir/${prefix}.${d}.${t}.spf.txt"
    echo "--- Pulling SPF records to $out ---"
    for i in $(cat "$input_file"); do
        echo "$i" >> "$out"
        dig +short -t txt "$i" | grep "v=spf1" >> "$out"
    done
}

## --- Module 2: ANY Records & Server Mapping ---
run_any_enumeration() {
    local any_csv="$out_dir/${prefix}.${d}.${t}.any.csv"
    local srv_csv="$out_dir/${prefix}.${d}.${t}.servers.csv"
    
    echo "domain, dns_ttl, class, dns_record_type, server, email, serial, refresh, retry, expire, soa_ttl" > "$any_csv"
    echo "hostname, ip_version, ip_address" > "$srv_csv"

    for i in $(cat "$input_file"); do
        echo "Checking ANY: $i"
        dig -t any "$i" | grep -E "ER SE|SWER SEC" -A3 | grep -v ";" | awk '{ print $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11 }' | sed 's/ /, /g' >> "$any_csv"
    done
    sed -i '/, , , , , , , , , , /d' "$any_csv"

    # Map Server IPs
    for srv in $(cut -f5 -d"," "$any_csv" | sort -u | grep -v -E "server|domain"); do
        host "$srv" | grep "has add" | awk -v s="$srv" '{print s", ipv4, "$4}' >> "$srv_csv"
        host "$srv" | grep "has IPv" | awk -v s="$srv" '{print s", ipv6, "$5}' >> "$srv_csv"
    done
}

## --- Module 3: Endpoint Enumeration & WHOIS ---
run_endpoint_enum() {
    local a_csv="$out_dir/${prefix}.${d}.${t}.A.csv"
    local whois_csv="$out_dir/${prefix}.${d}.${t}.whois.csv"
    local shodan_json="$out_dir/${prefix}.${d}.${t}.shodan.json"

    echo "hostname, dns_ttl, class, record_type, ip_address" > "$a_csv"
    echo "IP, NetRange, CIDR, Organization" > "$whois_csv"
    
    for i in $(grep -v "hostname" "$input_file"); do
        dig -t A "$i" | grep "ER SE" -A3 | grep -v ";" | awk '{ print $1, $2, $3, $4, $5 }' | sed 's/ /, /g' >> "$a_csv"
    done
    sed -i '/, , , , /d' "$a_csv"

    # WHOIS and Shodan
    for ip in $(cut -f5 -d"," "$a_csv" | sort -u | grep -v "ip_address"); do
        local raw_whois="$out_dir/temp_whois.txt"
        whois "$ip" > "$raw_whois"
        
        netrange=$(grep -E -i -m 1 'NetRange|inetnum' "$raw_whois" | cut -f2 -d":" | tr -d ' ' | sed 's/[#$%*@().]/-/g')
        cidr=$(grep -E -i -m 1 'route|CIDR' "$raw_whois" | cut -f2 -d":" | tr -d ' ' | sed 's/[#$%*@().]/-/g')
        org=$(grep -E -i -m 1 'Organization|role' "$raw_whois" | cut -f2 -d":" | tr -d ' ' | sed 's/[#$%*@().]/-/g')
        
        echo "$ip, $netrange, $cidr, $org" >> "$whois_csv"
        curl -s -A "Mozilla/5.0" "https://internetdb.shodan.io/$ip" | jq . >> "$shodan_json"
        rm "$raw_whois"
    done
}

## --- Execution ---
run_spf_check
run_any_enumeration
run_endpoint_enum

echo "Completed. Files written to: $out_dir using prefix: $prefix"
