from datetime import datetime
import os
import threading
from database import create_and_config_database
from capture import capture_traffic, dissect_packet, packets_to_db
from analysis import analyze_packets, update_tables

# Hardcoded values
DATABASE_NAME = 'network'  # Database name
INTERFACE_NAME = 'ens160'  # Replace 'eth0' with the desired interface name
OUTPUT_DIR = "pcap_files"
os.makedirs(OUTPUT_DIR, exist_ok=True)
PACKET_COUNT = 100000  # Number of packets to capture
TIMEOUT = 600
CSV_PACKET_LIMIT = 1000000 # Number of packets to write to insert into database before writing to CSV

is_backup = True

if __name__ == '__main__':
    create_and_config_database(DATABASE_NAME)
    
    # Pass arguments to live_capture using args
    thread1 = threading.Thread(
        target=capture_traffic,
        args=(
            DATABASE_NAME,OUTPUT_DIR, INTERFACE_NAME, PACKET_COUNT, TIMEOUT
        )
    )
    thread2 = threading.Thread(target=dissect_packet)
    thread3 = threading.Thread(target=packets_to_db)
    # thread4 = threading.Thread(target=analyze_packets, args=(DATABASE_NAME,))
    # thread5 = threading.Thread(target=update_tables)

    thread1.start()
    thread2.start()
    thread3.start()
    # thread4.start()
    # thread5.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Terminating threads...")