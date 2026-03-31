import socket
import struct
import sys
import argparse

def ntp_query(target, mode, opcode):
    # NTP Mode 6 (Control) or Mode 7 (Private)
    # Header: Leap(0), Version(2), Mode(mode) -> 0x16 or 0x17
    # Opcode is the specific command (e.g., 2 for Read Variables, 42 for Monlist)
    header = struct.pack('!BBHHHHH', (0 << 6 | 2 << 3 | mode), opcode, 1, 0, 0, 0, 0)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    
    try:
        sock.sendto(header, (target, 123))
        data, addr = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()

def main():
    parser = argparse.ArgumentParser(description="Remote NTP Information Gatherer")
    parser.add_argument("-t", "--target", required=True, help="Target IP address in Warsaw")
    args = parser.parse_args()

    print(f"[*] Auditing NTP at {args.target}...")

    # 1. Try Read Variables (Mode 6, Opcode 2)
    var_data = ntp_query(args.target, 6, 2)
    if var_data:
        print("\n[+] SYSTEM INFORMATION (READVAR):")
        # Extract the ASCII string from the payload (skipping the 12-byte header)
        print(var_data[12:].decode('ascii', errors='ignore'))
    else:
        print("[-] Mode 6 (ReadVar) timed out or restricted.")

    # 2. Try Monlist (Mode 7, Opcode 42)
    mon_data = ntp_query(args.target, 7, 42)
    if mon_data:
        print("\n[!] VULNERABILITY ALERT: MONLIST ENABLED")
        print(f"    Target leaked a response of {len(mon_data)} bytes.")
        print("    This confirms the server can be used for DDoS amplification")
        print("    and internal network mapping.")
    else:
        print("[-] Mode 7 (Monlist) timed out or disabled (Good for security).")

if __name__ == "__main__":
    main()
