import argparse
import csv
import pyshark
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.http import HTTPRequest
import os

def extract_http_info(pkt_sc):
    """Extract HTTP host and requested URL from the packet."""
    if pkt_sc.haslayer(HTTPRequest):
        http_layer = pkt_sc[HTTPRequest]
        host = http_layer.Host.decode() if http_layer.Host else 'N/A'
        path = http_layer.Path.decode() if http_layer.Path else 'N/A'
        return host, path
    return 'N/A', 'N/A'

def print_packet_info(pkt_sh, writer):
    """Write detailed packet information to the CSV writer.
    pkt_sh is the PyShark representation of the packet.
    writer is the CSV writer object.
    """
    try:
        # Initialize host and path
        host, path = 'N/A', 'N/A'
        
        # Extract raw packet data
        pkt_sc = bytes.fromhex(pkt_sh.frame_raw.value)
        ether_pkt_sc = Ether(pkt_sc)
        
        ip_pkt_sc = ether_pkt_sc[IP] if IP in ether_pkt_sc else None
        if ip_pkt_sc:
            proto = ip_pkt_sc.fields['proto']
            if proto == 17:
                udp_pkt_sc = ip_pkt_sc[UDP] if UDP in ip_pkt_sc else None
                if udp_pkt_sc:
                    l4_payload_bytes = bytes(udp_pkt_sc.payload)
                    l4_proto_name = 'UDP'
                    l4_sport = udp_pkt_sc.sport
                    l4_dport = udp_pkt_sc.dport
            elif proto == 6:
                tcp_pkt_sc = ip_pkt_sc[TCP] if TCP in ip_pkt_sc else None
                if tcp_pkt_sc:
                    l4_payload_bytes = bytes(tcp_pkt_sc.payload)
                    l4_proto_name = 'TCP'
                    l4_sport = tcp_pkt_sc.sport
                    l4_dport = tcp_pkt_sc.dport
                    host, path = extract_http_info(tcp_pkt_sc)
            else:
                l4_proto_name = 'Other'
                l4_sport = l4_dport = 'N/A'
                l4_payload_bytes = b''
        else:
            l4_proto_name = 'Non-IP'
            l4_sport = l4_dport = 'N/A'
            l4_payload_bytes = b''
        
        # Safely extract attributes and handle missing ones
        number = getattr(pkt_sh, 'number', 'N/A')
        sniff_time = getattr(pkt_sh, 'sniff_time', 'N/A')
        highest_layer = getattr(pkt_sh, 'highest_layer', 'N/A')
        info = getattr(pkt_sh, 'info', 'N/A')
        src_ip = getattr(pkt_sh.ip, 'src', 'N/A') if hasattr(pkt_sh, 'ip') else 'N/A'
        dst_ip = getattr(pkt_sh.ip, 'dst', 'N/A') if hasattr(pkt_sh, 'ip') else 'N/A'
        length = getattr(pkt_sh, 'length', 'N/A')

        # Write packet info to CSV
        writer.writerow([number, sniff_time, highest_layer, l4_proto_name, info, src_ip, l4_sport, dst_ip, l4_dport, length, l4_payload_bytes.hex(), host, path])
        
        return True
    except AttributeError as e:
        print(f'Failed to parse packet: {e}')
        return False
    except Exception as e:
        print(f'Unexpected error parsing packet: {e}')
        return False

def live_capture(interface, packet_count, csv_filename):
    """Capture live packets from the specified network interface, write details to CSV."""

    capture = pyshark.LiveCapture(interface=interface, use_json=True, include_raw=True)
    frame_num = 0

    try:
        # Open CSV file for writing
        with open(csv_filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # Write header row
            writer.writerow(['Number', 'Sniff Time', 'Highest Layer', 'Layer 4 Protocol', 'Info', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Length', 'Payload', 'Host', 'Path'])

            for pkt in capture.sniff_continuously(packet_count=packet_count):
                frame_num += 1
                print_packet_info(pkt, writer)
        
        print('{} packets captured and saved to {}'.format(frame_num, os.path.abspath(csv_filename)))

    except Exception as e:
        print(f'Error while writing to CSV file: {e}')

def command_line_args():
    """Helper called from main() to parse the command line arguments"""

    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', metavar='<network interface>',
                        help='network interface to capture packets from', required=True)
    parser.add_argument('--count', metavar='<packet count>', type=int, default=10,
                        help='number of packets to capture')
    parser.add_argument('--output', metavar='<output file>', default='packets.csv',
                        help='CSV file to save packet details')
    args = parser.parse_args()
    return args

def main():
    """Program main entry"""
    args = command_line_args()
    live_capture(args.interface, args.count, args.output)

if __name__ == '__main__':
    main()
