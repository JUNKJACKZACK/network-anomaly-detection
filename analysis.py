import datetime
from datetime import datetime
import os
import threading
import mysql.connector as mysql
import time
from scapy.all import sniff, wrpcap

DB_CONFIG_4 = {
    'user': 'user4',
    'password': 'password4',
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

db_name = ''

mac_addresses = []
ip_addresses = []
macs_previous_ips = {}
pending_sql_statements = []


def connect_to_db():
    connection = mysql.connect(**DB_CONFIG_4)
    cursor = connection.cursor()
    return cursor, connection


def close_db_connection(cursor, connection):
    if cursor:
        cursor.close()
    if connection:
        connection.close()

    print("MySQL connection is closed23")
    time.sleep(1)


def update_local_arrays(cursor):
    global mac_addresses, ip_addresses

    # Fetch all MAC addresses
    cursor.execute("SELECT mac_address FROM mac_addresses;")
    fetched_mac_addresses = [record[0] for record in cursor.fetchall()]

    for mac in fetched_mac_addresses:
        if mac not in mac_addresses:
            mac_addresses.append(mac)

    # Fetch all IP addresses
    cursor.execute("SELECT ip_address FROM ip_addresses;")
    fetched_ip_addresses = [record[0] for record in cursor.fetchall()]

    for ip in fetched_ip_addresses:
        if ip not in ip_addresses:
            ip_addresses.append(ip)

    # Fetch all previous IP addresses associated with MAC addresses
    cursor.execute("SELECT mac_address, ip_address FROM macs_previous_ips;")
    fetched_macs_previous_ips = cursor.fetchall()

    for record in fetched_macs_previous_ips:
        if record[0] in macs_previous_ips:
            if record[1] not in macs_previous_ips[record[0]]:
                macs_previous_ips[record[0]].append(record[1])
        else:
            macs_previous_ips[record[0]] = [record[1]]


def update_tables():
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
                for i in range(1000):
                    try:
                        cursor.execute(*pending_sql_statements.pop(0))
                        connection.commit()
                    except mysql.Error as e:
                        print(f"Error executing SQL statement: {e}")
            else:
                time.sleep(0.5)
            
        except mysql.Error as e:
            print(f"Error while connecting to MySQL: {e}")
            close_db_connection(cursor, connection)

        except Exception as e:
            print(e)
            close_db_connection(cursor, connection)


def analyze_mac(cursor, connection, mac_address, timestamp):
    sql_statements = [
        """
        INSERT INTO mac_addresses (
            mac_address,
            first_seen,
            last_seen
        ) VALUES (%s, %s, %s);
        """,
        "UPDATE mac_addresses SET last_seen = %s WHERE mac_address = %s;"
    ]

    if mac_address:
        try:
            if mac_address in mac_addresses:
                pending_sql_statements.append(
                    (
                        sql_statements[1],
                        (timestamp, mac_address)
                    )
                )
            else:
                cursor.execute(
                    "SELECT * FROM mac_addresses WHERE mac_address = %s;",
                    (mac_address,)
                )

                if cursor.fetchone() is None:
                    cursor.execute(sql_statements[0], (mac_address, timestamp, timestamp))
                    connection.commit()

                update_local_arrays(cursor)

        except mysql.Error as err:
            print(f"Error 1: {err}")


def analyze_ip(cursor, connection, mac_address, ip_address, timestamp):
    global local_ip_record, local_previous_ips

    sql_statements = [
        """
        INSERT INTO ip_addresses (
            ip_address,
            first_seen,
            last_seen
        ) VALUES (%s, %s, %s);
        """,
        """
        UPDATE ip_addresses
        SET last_seen = %s
        WHERE ip_address = %s;
        """,
        """
        INSERT INTO macs_previous_ips (
            mac_address,
            ip_address,
            first_seen,
            last_seen
        ) VALUES (%s, %s, %s, %s);
        """,
        """
        UPDATE macs_previous_ips
        SET last_seen = %s
        WHERE mac_address = %s
        AND ip_address = %s;
        """
    ]

    if ip_address:
        try:
            if ip_address in ip_addresses:
                pending_sql_statements.append(
                    (
                        sql_statements[1],
                        (timestamp, ip_address)
                    )
                )
            else:
                cursor.execute(
                    "SELECT * FROM ip_addresses WHERE ip_address = %s;",
                    (ip_address,)
                )

                if cursor.fetchone() is None:
                    cursor.execute(sql_statements[0], (ip_address, timestamp, timestamp))
                    connection.commit()

                update_local_arrays(cursor)

            # Check if the IP address is already associated with the MAC address
            if mac_address in macs_previous_ips:
                if ip_address in macs_previous_ips[mac_address]:
                    pending_sql_statements.append(
                        (
                            sql_statements[3],
                            (timestamp, mac_address, ip_address)
                        )
                    )
                else:
                    cursor.execute(
                        """
                        SELECT * FROM macs_previous_ips
                        WHERE mac_address = %s
                        AND ip_address = %s;
                        """,
                        (mac_address, ip_address)
                    )

                    if cursor.fetchone() is None:
                        cursor.execute(sql_statements[2], (mac_address, ip_address, timestamp, timestamp))
                        connection.commit()
                        update_local_arrays(cursor)
                        
        except mysql.Error as err:
            print(f"Error 2: {err}")


def analyze_packets(database_name):
    global db_name
    db_name = database_name

    cursor, connection = connect_to_db()
    cursor.execute(f"USE {db_name}")
    update_local_arrays(cursor)

    update_queries = [
        "UPDATE mac_stats SET tx_packet_count = tx_packet_count + 1 WHERE mac = %s;",
        "UPDATE mac_stats SET rx_packet_count = rx_packet_count + 1 WHERE mac = %s;",
    ]

    while True:
        try:
            if not cursor or not connection or not connection.is_connected():
                cursor, connection = connect_to_db()
            cursor.execute(f"USE {db_name}")
        except mysql.Error as err:
            print(f"Error connecting to database: {err}")
            time.sleep(0.5)  # Wait before retrying to avoid spamming the database
            continue

        if len(pending_sql_statements) <= 25000:
            try:
                cursor.execute(
                    """
                    SELECT * FROM captured_packets
                    WHERE is_analyzed = 0
                    ORDER BY id ASC
                    LIMIT 250;
                    """
                )
                packets = cursor.fetchall()
            except mysql.Error as err:
                print(f"Error fetching packets: {err}")
                time.sleep(1)

        """
        ** Variables used for clarity and troubleshooting **

        id = packet[0]
        timestamp = packet[1]
        source_mac = packet[2]
        dest_mac = packet[3]
        l1_protocol = packet[4]
        l2_protocol = packet[5]
        l3_protocol = packet[6]
        l4_protocol = packet[7]
        info = packet[8]
        source_ip = packet[9]
        source_port = packet[10]
        destination_ip = packet[11]
        destination_port = packet[12]
        packet_length = packet[13]
        payload = packet[14]
        is_analyzed = packet[15]
        """

        try:
            if packets:
                for packet in packets:
                    analyze_mac(cursor, connection, packet[2], packet[1])
                    analyze_mac(cursor, connection, packet[3], packet[1])
                    analyze_ip(cursor, connection, packet[2], packet[9], packet[1])
                    analyze_ip(cursor, connection, packet[3], packet[11], packet[1])
                    cursor.execute("UPDATE captured_packets SET is_analyzed = 1 WHERE id = %s;", (packet[0],))
                    for update_query in update_queries:
                        cursor.execute(update_query, (packet[2],))
                        cursor.execute(update_query, (packet[3],))
                    
                    connection.commit()
            else:
                time.sleep(30)
                close_db_connection(cursor, connection)
                continue
        except mysql.Error as err:
            print(f"MySQL Error: {err}")
        except Exception as e:
            print(f"Error: {e}")
            close_db_connection(cursor, connection)
            continue

        
