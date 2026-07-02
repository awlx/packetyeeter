#!/usr/bin/env python3
import argparse
import sys
import time
from scapy.all import IPv6, IP, TCP, send, conf

def flood(target_ip, port, count, ipv6=False):
    print(f"Starting SYN Flood against {target_ip}:{port} (IPv6={ipv6})...")
    
    if ipv6:
        # IPv6 Packet
        # Randomize source slightly or just flood
        # Note: Scapy automatically handles some fields, but for a flood we want raw speed.
        # send() is layer 3, sendp() is layer 2.
        
        # Disable verbose
        conf.verb = 0
        
        for i in range(count):
            # Create a packet
            # We randomize user port to simulate distinct connections or same 
            # PacketYeeter tracks per (saddr, sport, daddr, dport)
            # So varying sport creates new "connections"
            
            p = IPv6(dst=target_ip)/TCP(dport=port, sport=10000+(i%50000), flags='S')
            send(p)
            
            if i % 100 == 0:
                sys.stdout.write(f"\rSent {i} packets...")
                sys.stdout.flush()
    else:
        # IPv4
        conf.verb = 0
        for i in range(count):
            p = IP(dst=target_ip)/TCP(dport=port, sport=10000+(i%50000), flags='S')
            send(p)
            if i % 100 == 0:
                sys.stdout.write(f"\rSent {i} packets...")
                sys.stdout.flush()

    print(f"\nDone! Sent {count} packets.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PacketYeeter Flood Tester")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--port", type=int, default=80, help="Target port")
    parser.add_argument("--count", type=int, default=100, help="Number of packets")
    parser.add_argument("-6", "--ipv6", action="store_true", help="Use IPv6")
    
    args = parser.parse_args()
    
    flood(args.target, args.port, args.count, args.ipv6)
