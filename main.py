from datetime import datetime
import threading
from setup import create_and_config_database
from capture import live_capture
from capture import packets_to_db

# Hardcoded values
DATABASE_NAME = 'network'  # Database name
INTERFACE_NAME = 'ens160'  # Replace 'eth0' with the desired interface name
PACKET_COUNT = 100000  # Number of packets to capture
CSV_FILENAME = 'packets.csv'  # CSV file to save packet details

if __name__ == '__main__':
    print('Starting packet capture...')
    print(datetime.now())
    
    # Create threads
    thread1 = threading.Thread(target=create_and_config_database)
    
    # Pass arguments to live_capture using args
    thread2 = threading.Thread(target=live_capture, args=(INTERFACE_NAME, PACKET_COUNT, CSV_FILENAME))
    
    # Pass arguments to packets_to_db using args
    thread3 = threading.Thread(target=packets_to_db, args=(DATABASE_NAME,))
    
    # Start threads
    thread1.start()
    thread2.start()
    thread3.start()

    thread1.join()
    thread2.join()
    thread3.join()