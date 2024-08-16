import binascii
import datetime
from datetime import datetime
import os
import threading
import time
from venv import logger
import pyshark
import mysql.connector as mysql
from scapy.all import sniff, Ether, IP, IPv6, UDP, TCP, ICMP, DNS, ARP, Raw, wrpcap, rdpcap, PcapReader
from scapy.layers.http import HTTPRequest

DB_CONFIG_1 = {
    'user': 'user1',
    'password': 'password1',
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password',
}

DB_CONFIG_2 = {
    'user': 'user2',
    'password': 'password2',
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

db_name = ''
output_dir = ''
pending_sql_statements = []

pcap_file_count = 0
pcap_files_dissected = 0


def connect_to_db():
    connection = mysql.connect(**DB_CONFIG_1)
    cursor = connection.cursor()
    return cursor, connection


def close_db_connection(cursor, connection):
    if cursor:
        cursor.close()
    if connection:
        connection.close()


def update_terminal():
    global pcap_file_count, pcap_files_dissected
    cursor = None
    connection = None
    if not cursor or not connection or not connection.is_connected():
        cursor, connection = connect_to_db()
        cursor.execute(f"USE {db_name}")
        if not connection:
            time.sleep(2)
            
    try:
        cursor.execute("SELECT COUNT(*) FROM captured_packets")
        row_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM captured_packets WHERE is_analyzed = 0;")
        unanalyzed_packets = cursor.fetchone()[0]
        percentage_analyzed = 0 if row_count == 0 else (row_count - unanalyzed_packets) / row_count * 100
        
        print(f"PCAP files created: {pcap_file_count} | PCAP files dissected: {pcap_files_dissected} | Pending SQL statements: {len(pending_sql_statements)}") 
        print(f"Unanalyzed packets: {unanalyzed_packets} | Analyzed packets: {row_count - unanalyzed_packets} | Percentage analyzed: {percentage_analyzed:.2f}%\n")
        close_db_connection(cursor, connection)
    
    except mysql.Error as e:
        print(f"Error while connecting to MySQL: {e}")
        close_db_connection(cursor, connection)
        

def find_oldest_pcap(directory):
    try:
        files = [f for f in os.listdir(directory) if f.endswith('.pcap')]
        files.sort()
    except FileNotFoundError:
        print(f"Directory {directory} not found.")
        return None
    return files[0] if files else None


def packets_to_db():
    cursor, connection = connect_to_db()
    cursor.execute(f"USE {db_name}")

    while True:
        if not cursor or not connection or not connection.is_connected():
            cursor, connection = connect_to_db()
            cursor.execute(f"USE {db_name}")
            if not connection:
                time.sleep(2)
                continue
        try:
            while pending_sql_statements:
                try:
                    # print(len(pending_sql_statements))
                    cursor.execute(*pending_sql_statements.pop(0))
                except mysql.Error as e:
                    print(f"Error executing SQL statement: {e}")
            
                connection.commit()
            else:
                time.sleep(0.5)
        except mysql.Error as e:
            print(f"Error while connecting to MySQL: {e}")
            close_db_connection(cursor, connection)
        except Exception as e:
            print(e)
            close_db_connection(cursor, connection)


def dissect_packet():
    global pending_sql_statements, pcap_files_dissected

    while True:
        if len(pending_sql_statements) > 100000:
            print(f"Pausing processing. Pending SQL statements: {len(pending_sql_statements)} Time: {datetime.now()}")
            while len(pending_sql_statements) >= 1000:
                time.sleep(5)
            else:
                print(f"Resuming processing. Pending SQL statements: {len(pending_sql_statements)} Time: {datetime.now()}")

        pcap_file = find_oldest_pcap(output_dir)

        if not pcap_file:
            time.sleep(15)
            continue

        packets = pyshark.FileCapture(os.path.join(output_dir, pcap_file), keep_packets=False, include_raw=True, use_json=True)
        pcap_files_dissected += 1

        for pkt in packets:
            try:
                pkt_info = ''
                timestamp = datetime.fromtimestamp(
                    float(pkt.sniff_timestamp)
                )

                ip_source = None
                ip_dest = None
                source_port = None
                dest_port = None
                payload = None

                if hasattr(pkt, 'ip'):
                    ip_source = pkt.ip.src
                    ip_dest = pkt.ip.dst
                    if hasattr(pkt, 'transport_layer') and pkt.transport_layer:
                        source_port = pkt[pkt.transport_layer].srcport if hasattr(pkt, pkt.transport_layer) else None
                        dest_port = pkt[pkt.transport_layer].dstport if hasattr(pkt, pkt.transport_layer) else None
                    elif hasattr(pkt, 'igmp'):
                        ip_source = pkt.ip.src_host
                        ip_dest = pkt.ip.dst_host
                        source_port = pkt.igmp.srcport if hasattr(pkt.igmp, 'srcport') else None
                        dest_port = pkt.igmp.dstport if hasattr(pkt.igmp, 'dstport') else None
                    if hasattr(pkt, 'icmp'):
                        source_port = pkt.icmp.type if hasattr(pkt, 'icmp') and hasattr(pkt.icmp, 'type') else None
                        dest_port = pkt.icmp.code if hasattr(pkt, 'icmp') and hasattr(pkt.icmp, 'code') else None
                elif hasattr(pkt, 'arp'):
                    ip_source = pkt.arp.src_proto_ipv4 if hasattr(pkt, 'arp') and hasattr(pkt.arp, 'src_proto_ipv4') else None
                    ip_dest = pkt.arp.dst_proto_ipv4 if hasattr(pkt.arp, 'dst_proto_ipv4') else None
                
                if hasattr(pkt, 'tcp'):
                    if hasattr(pkt.tcp, 'payload'):
                        payload = pkt.tcp.payload
                elif hasattr(pkt, 'udp'):
                    if hasattr(pkt.udp, 'payload'):
                        payload = pkt.udp.payload

                if hasattr(pkt, 'http'):
                    try:
                        # print(f"Requested URL: {pkt.http.full_uri}")
                        pkt_info = pkt.http.full_uri
                    except AttributeError:
                        try:
                            pkt_info = pkt.http.uri
                        except AttributeError:
                            pkt_info = None
                
                packet_length = pkt.length if pkt.length else 0

                pending_sql_statements.append((
                    """INSERT INTO captured_packets (timestamp, source_mac, dest_mac, l1_protocol, l2_protocol, l3_protocol, l4_protocol, info, source_ip, source_port, 
                                                destination_ip, destination_port, packet_length, payload, is_analyzed)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        str(timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')),
                        str(pkt.eth.src) if hasattr(pkt, 'eth') and pkt.eth.src else None,
                        str(pkt.eth.dst) if hasattr(pkt, 'eth') and pkt.eth.dst else None,
                        str(pkt.layers[0].layer_name) if len(pkt.layers) > 0 else None,
                        str(pkt.layers[1].layer_name) if len(pkt.layers) > 1 else None,
                        str(pkt.layers[2].layer_name) if len(pkt.layers) > 2 else None,
                        str(pkt.layers[3].layer_name) if len(pkt.layers) > 3 else None,
                        str(pkt_info) if pkt_info else None,
                        str(ip_source) if ip_source else None,
                        str(source_port) if source_port else None,
                        str(ip_dest) if ip_dest else None,
                        str(dest_port) if dest_port else None,
                        packet_length,
                        # str(pkt.layers[-1]) if len(pkt.layers) > 0 else None
                        # binascii.hexlify(pkt.get_raw_packet()).decode('utf-8') if len(pkt.layers) > 0 else None,
                        str(payload),
                        False
                    )
                ))
            except AttributeError as e:
                print(f'Failed to parse packet due to attribute error: {e} - Packet layers: {pkt}')
            except Exception as e:
                print(f'Packet layers: {pkt}')
                print(f'Unexpected error parsing packet: {e}')
        
        packets.close()
        # Delete the pcap file
        os.remove(os.path.join(output_dir, pcap_file))
        # print("Deleted PCAP")


def write_to_pcap(file_name, captured_packets):
    # print("\nSaving PCAP file...")
    wrpcap(file_name, captured_packets)
    # print(f"PCAP file saved as {file_name}")


def capture_traffic(database_name, output_directory, interface_name, packet_limit, timeout):
    """Captures traffic on the specified interface and stores packets in a list."""
    global db_name, output_dir, pcap_file_count
    db_name = database_name
    output_dir = output_directory
    print(f"Capturing traffic on {interface_name}...")

    while True:
        captured_packets = []
        packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")
        try:
            captured_packets.append(sniff(iface=interface_name, timeout=timeout, count=packet_limit))
            packet_time_ended = datetime.now().strftime("%Y-%m-%d_%H-%M")
            file_name = os.path.join(output_dir, f"{interface_name}-({packet_time_started})-({packet_time_ended}).pcap")

            pcap_file_count += 1
            threading.Thread(target=write_to_pcap, args=(file_name, captured_packets)).start()
            threading.Thread(target=update_terminal).start()

        except Exception as e:
            print(f"Error capturing traffic on {interface_name}: {e}")
