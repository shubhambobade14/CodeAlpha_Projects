#!/usr/bin/env python3
"""Authorized local network packet inspection with Scapy."""
import argparse
import csv
from datetime import datetime
from pathlib import Path
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw, get_if_list

FIELDS = ['timestamp', 'source', 'destination', 'protocol', 'source_port', 'destination_port', 'length', 'payload_preview']

def parse_packet(packet, show_payload=False):
    if IP in packet:
        network = packet[IP]
    elif IPv6 in packet:
        network = packet[IPv6]
    else:
        return None
    protocol = 'OTHER'
    src_port = dst_port = ''
    if TCP in packet:
        protocol = 'TCP'
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        protocol = 'UDP'
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport
    elif ICMP in packet:
        protocol = 'ICMP'
    elif IPv6 in packet and network.nh == 58:
        protocol = 'ICMPv6'
    preview = ''
    if show_payload and Raw in packet:
        preview = bytes(packet[Raw].load)[:32].hex(' ')
    timestamp = datetime.fromtimestamp(float(packet.time)).astimezone().isoformat(timespec='seconds')
    return {'timestamp': timestamp, 'source': network.src, 'destination': network.dst,
            'protocol': protocol, 'source_port': src_port, 'destination_port': dst_port,
            'length': len(packet), 'payload_preview': preview}

def main():
    parser = argparse.ArgumentParser(description='Basic authorized network sniffer')
    parser.add_argument('--interface', help='Network interface name')
    parser.add_argument('--count', type=int, default=20, help='Number of captured packets (default: 20)')
    parser.add_argument('--filter', default='ip or ip6', help='BPF capture filter')
    parser.add_argument('--output', default='packets.csv', help='CSV report path')
    parser.add_argument('--show-payload', action='store_true', help='Include first 32 payload bytes as hex (may contain sensitive data)')
    parser.add_argument('--list-interfaces', action='store_true', help='List available interfaces and exit')
    args = parser.parse_args()
    if args.list_interfaces:
        for name in get_if_list():
            print(name)
        return
    if args.count < 1:
        parser.error('--count must be at least 1')
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    print(f'Capturing up to {args.count} packets. Press Ctrl+C to stop.')
    print('Only capture traffic you are authorized to inspect.')
    with output.open('w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        def handle(packet):
            row = parse_packet(packet, args.show_payload)
            if row is None:
                return
            writer.writerow(row)
            file.flush()
            ports = f" {row['source_port']} -> {row['destination_port']}" if row['source_port'] != '' else ''
            print(f"{row['timestamp']} {row['protocol']:6} {row['source']} -> {row['destination']}{ports} len={row['length']}")
            if row['payload_preview']:
                print(f"  Payload (hex): {row['payload_preview']}")
        try:
            sniff(iface=args.interface, filter=args.filter, count=args.count, prn=handle, store=False)
        except KeyboardInterrupt:
            print('\nCapture stopped by user.')
        except (OSError, RuntimeError, ValueError) as exc:
            print(f'Capture error: {exc}')
            raise SystemExit(1) from exc
    print(f'CSV saved to {output}')

if __name__ == '__main__':
    main()
