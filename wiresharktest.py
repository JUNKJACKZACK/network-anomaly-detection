import datetime
from datetime import datetime
import os
import threading
import time
from scapy.all import sniff, wrpcap

DATABASE_NAME = 'network'  # Database name
INTERFACE_NAME = 'ens160'  # Replace 'eth0' with the desired interface name
OUTPUT_DIR = "pcap_files"
os.makedirs(OUTPUT_DIR, exist_ok=True)
PACKET_COUNT = 100000  # Number of packets to capture

def write_to_pcap(file_name, captured_packets):
    print("\nSaving PCAP file...")
    wrpcap(file_name, captured_packets)
    print(f"PCAP file saved as {file_name}")

def capture_traffic(output_directory, interface_name, packet_limit):
    """Captures traffic on the specified interface and stores packets in a list."""
    global output_dir
    output_dir = output_directory

    while True:
        captured_packets = []
        start_time = time.time()
        packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")
        try:
            print(f"Capturing traffic on {interface_name}...")
            # Scan/Sniff the network
            captured_packets.append(sniff(iface=interface_name, count=packet_limit))

            packet_time_ended = datetime.now().strftime("%Y-%m-%d_%H-%M")
            print(f"Capture completed in {time.time() - start_time} seconds.")

            # Write captured packets to a PCAP file
            # FYI: Comment these three lines if PCAP creation is not needed.
            file_name = os.path.join(output_dir, f"{interface_name}-({packet_time_started})-({packet_time_ended}).pcap")
            threading.Thread(target=write_to_pcap, args=(file_name, captured_packets)).start()
        except Exception as e:
            print(f"Error capturing traffic on {interface_name}: {e}")


if __name__ == '__main__':
    capture_traffic(OUTPUT_DIR, INTERFACE_NAME, PACKET_COUNT)
