import csv
import time
import pyshark
import mysql.connector as mysql
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.http import HTTPRequest

DB_CONFIG = {
    'user': 'user2',
    'password': 'password2',
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

pending_packet_inserts = []


def connect_to_db():
    connection = mysql.connect(**DB_CONFIG)
    cursor = connection.cursor()
    return cursor, connection


def close_db_connection(cursor, connection):
    if cursor:
        cursor.close()
    if connection:
        connection.close()


def packets_to_db(db_name):

    while True:
        cursor, connection = connect_to_db()

        packet_count = len(pending_packet_inserts)

        if packet_count == 0:
            print("No packets to insert")
            time.sleep(2)
            return

        packet_batch = pending_packet_inserts[:packet_count]

        try:
            if connection.is_connected():
                cursor = connection.cursor()
                cursor.execute(f"USE {db_name}")

                insert_query = """
                INSERT INTO captured_packets (timestamp, highest_layer, l4_protocol, info, source_ip, source_port, 
                                            destination_ip, destination_port, packet_length, payload, http_host, http_path)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """

                for packet in packet_batch:
                    # Convert all packet fields to strings or appropriate types
                    packet = tuple(str(field) if not isinstance(field, (int, float)) else field for field in packet)
                    cursor.execute(insert_query, packet)

                connection.commit()
                print("Packet information inserted successfully")

        except mysql.Error as e:
            print(f"2 Error while connecting to MySQL: {e}")
        
        finally:
            del pending_packet_inserts[:packet_count]

            if connection.is_connected():
                cursor.close()
                connection.close()
                print("MySQL connection is closed")


def extract_http_info(pkt_sc):
    """Extract HTTP host and requested URL from the packet."""
    if pkt_sc.haslayer(HTTPRequest):
        http_layer = pkt_sc[HTTPRequest]
        host = http_layer.Host.decode() if http_layer.Host else None
        path = http_layer.Path.decode() if http_layer.Path else None
        return host, path
    return None, None


def dissect_packet(pkt_sh, writer):
    try:
        # Initialize host and path
        host, path = None, None

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
                l4_sport = l4_dport = None
                l4_payload_bytes = b''
        else:
            l4_proto_name = 'Non-IP'
            l4_sport = l4_dport = None
            l4_payload_bytes = b''

        # Safely extract attributes and handle missing ones
        # number = getattr(pkt_sh, 'number', None)
        sniff_time = getattr(pkt_sh, 'sniff_time', None)
        highest_layer = getattr(pkt_sh, 'highest_layer', None)
        info = getattr(pkt_sh, 'info', None)
        src_ip = getattr(pkt_sh.ip, 'src', None) if hasattr(pkt_sh, 'ip') else None
        dst_ip = getattr(pkt_sh.ip, 'dst', None) if hasattr(pkt_sh, 'ip') else None
        length = getattr(pkt_sh, 'length', None)

        # Write packet info to CSV
        pending_packet_inserts.append((sniff_time, highest_layer, l4_proto_name, info, src_ip, l4_sport, dst_ip, l4_dport, length, l4_payload_bytes.hex(), host, path))
        
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

    try:
        writer = None
        # # Open CSV file for writing
        # with open(csv_filename, 'w', newline='') as csvfile:
        #     writer = csv.writer(csvfile)
        #     # Write header row
        #     writer.writerow(['Number', 'Sniff Time', 'Highest Layer', 'Layer 4 Protocol', 'Info', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Length', 'Payload', 'Host', 'Path'])

        for packet in capture.sniff_continuously(packet_count=packet_count):
            print(f'Packet: {packet.number}')
            dissect_packet(packet, writer)

    except Exception as e:
        print(f'Error while writing to CSV file: {e}')