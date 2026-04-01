import socket
import argparse
import os
import sys

def get_snmp_banner(target, community="public", timeout=2.0):
    """Sends a raw SNMPv2c sysDescr GET request."""
    # SNMPv2c GET OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
    packet = bytearray([
        0x30, 0x26, 0x02, 0x01, 0x01, 0x04, len(community)
    ])
    packet.extend(community.encode())
    packet.extend([
        0xa0, 0x1f, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x11, 
        0x30, 0x0f, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 
        0x01, 0x01, 0x01, 0x00, 0x05, 0x00
    ])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    try:
        sock.sendto(packet, (target, 161))
        data, _ = sock.recvfrom(4096)
        # Extract printable string from response
        banner = "".join(chr(b) if 32 <= b <= 126 else "" for b in data[30:])
        return banner.strip()
    except (socket.timeout, ConnectionRefusedError):
        return None
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        sock.close()

def main():
    parser = argparse.ArgumentParser(description="M&A SNMP Discovery Tool")
    parser.add_argument("-t", "--target", help="Single target IP")
    parser.add_argument("-f", "--file", help="File containing list of IPs (one per line)")
    parser.add_argument("-c", "--community", default="public", help="SNMP community string (default: public)")
    args = parser.parse_args()

    # --- 1. Validation ---
    if not args.target and not args.file:
        print("[!] Error: You must provide either a single target (-t) or a file list (-f).")
        sys.exit(1)

    targets = []
    if args.target:
        targets.append(args.target)
    
    if args.file:
        if not os.path.isfile(args.file):
            print(f"[!] Error: File '{args.file}' not found.")
            sys.exit(1)
        if not os.access(args.file, os.R_OK):
            print(f"[!] Error: Cannot read file '{args.file}' (Permission denied).")
            sys.exit(1)
        
        with open(args.file, 'r') as f:
            targets.extend([line.strip() for line in f if line.strip()])

    # --- 2. Execution ---
    results = {"Success": [], "Failed": []}
    
    print(f"[*] Starting audit of {len(targets)} hosts...")
    print("-" * 50)

    for ip in targets:
        banner = get_snmp_banner(ip, args.community)
        if banner:
            print(f"[+] {ip}: {banner}")
            results["Success"].append((ip, banner))
        else:
            print(f"[-] {ip}: No Response")
            results["Failed"].append(ip)

    # --- 3. Summary Report ---
    print("\n" + "="*50)
    print("M&A AUDIT SUMMARY")
    print("="*50)
    print(f"Total Hosts Scanned: {len(targets)}")
    print(f"Exposed (Responsive): {len(results['Success'])}")
    print(f"Filtered/Closed:     {len(results['Failed'])}")
    print("-" * 50)
    
    if results["Success"]:
        print("\nIDENTIFIED TECHNOLOGY:")
        # Simple deduplication of technology types found
        tech_found = set([b for _, b in results["Success"]])
        for tech in tech_found:
            count = sum(1 for _, b in results["Success"] if b == tech)
            print(f" - [{count}x] {tech}")
    
    print("="*50)

if __name__ == "__main__":
    main()
