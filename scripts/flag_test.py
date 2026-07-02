#!/usr/bin/env python3
import argparse
import sys
from scapy.all import IP, TCP, send, conf

def send_bad_flags(target_ip, port, count):
    print(f"Starting TCP Flag Test against {target_ip}:{port}...")
    conf.verb = 0

    # 1. SYN-FIN (Classic invalid state)
    print(f"Sending {count} SYN-FIN packets...")
    for i in range(count):
        p = IP(dst=target_ip)/TCP(dport=port, sport=20000+(i%10000), flags='SF')
        send(p)
    
    # 2. Xmas Scan (FIN, PSH, URG)
    print(f"Sending {count} Xmas packets (FIN+PSH+URG)...")
    for i in range(count):
        p = IP(dst=target_ip)/TCP(dport=port, sport=30000+(i%10000), flags='FPU')
        send(p)

    # 3. NULL Scan (No flags)
    print(f"Sending {count} NULL packets...")
    for i in range(count):
        p = IP(dst=target_ip)/TCP(dport=port, sport=40000+(i%10000), flags='')
        send(p)

    print("\nDone! These packets should be dropped silently by XDP.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PacketYeeter TCP Flag Tester")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--port", type=int, default=80, help="Target port")
    parser.add_argument("--count", type=int, default=10, help="Number of packets per type")
    
    args = parser.parse_args()
    
    send_bad_flags(args.target, args.port, args.count)
