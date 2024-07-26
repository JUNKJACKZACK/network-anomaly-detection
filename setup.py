import sys
import mysql.connector as mysql

DATABASE_NAME = "network"
TABLE_NAME = "captured_packets"

DB_CONFIG = {
    'user': 'user1',
    'password': 'password1',
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}


def connect_to_db():
    connection = mysql.connect(**DB_CONFIG)
    cursor = connection.cursor()
    return cursor, connection


def close_db_connection(cursor, connection):
    if cursor:
        cursor.close()
    if connection:
        connection.close()


def execute_queries(cursor, queries):
    cursor.execute(f"USE {DATABASE_NAME}")

    try:
        for query in queries:
            cursor.execute(query)
    except mysql.Error as err:
        print(f"Error executing queries: {err} {query}")
        sys.exit()


def create_database(cursor):
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DATABASE_NAME}")
    except mysql.Error as err:
        print(f"Error creating database: {err}")
        sys.exit()


def create_tables(cursor):
    global local_nic_record

    tables = [
        """
        CREATE TABLE IF NOT EXISTS csv_files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            file_name VARCHAR(255),
            start_datetime DATETIME,
            end_datetime DATETIME
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS ip_addresses (
            ip_address VARCHAR(45) PRIMARY KEY,
            is_ipv6 TINYINT DEFAULT 0,
            first_seen DATETIME,
            last_seen DATETIME,
            hostname VARCHAR(255),
            subnet VARCHAR(45),
            lease_expires DATETIME,
            last_known_location VARCHAR(255)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS captured_packets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME,
            highest_layer VARCHAR(250),
            l4_protocol VARCHAR(50),
            info TEXT,
            source_ip VARCHAR(45),
            source_port VARCHAR(45),
            destination_ip VARCHAR(45),
            destination_port VARCHAR(45),
            packet_length INT,
            payload LONGBLOB,
            http_host VARCHAR(250),
            http_path TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS nic_record (
            mac_address VARCHAR(17) PRIMARY KEY,
            last_known_ip VARCHAR(45),
            first_seen DATETIME,
            last_seen DATETIME,
            manufacturer VARCHAR(255),
            last_known_location VARCHAR(255),
            FOREIGN KEY (last_known_ip)
                REFERENCES ip_addresses(ip_address) ON DELETE SET NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS nic_previous_ips (
            id INT AUTO_INCREMENT PRIMARY KEY,
            mac_address VARCHAR(17),
            ip_address VARCHAR(45),
            first_seen DATETIME,
            last_seen DATETIME,
            FOREIGN KEY (mac_address)
                REFERENCES nic_record(mac_address) ON DELETE CASCADE,
            FOREIGN KEY (ip_address)
                REFERENCES ip_addresses(ip_address) ON DELETE SET NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS devices (
            id INT AUTO_INCREMENT PRIMARY KEY,
            associated_NIC VARCHAR(17),
            device_name VARCHAR(255),
            device_type VARCHAR(255),
            operating_system VARCHAR(255),
            manufacturer VARCHAR(255),
            model VARCHAR(255),
            serial_number VARCHAR(255),
            location VARCHAR(255),
            FOREIGN KEY (associated_NIC)
                REFERENCES nic_record(mac_address) ON DELETE SET NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS nic_stats (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nic VARCHAR(17),
            last_updated DATETIME,
            is_source TINYINT DEFAULT 0,
            tx_packet_count INT DEFAULT 0,
            rx_packet_count INT DEFAULT 0,
            sent_arp_count INT,
            FOREIGN KEY (nic)
                REFERENCES nic_record(mac_address) ON DELETE SET NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS network_stats (
            id INT AUTO_INCREMENT PRIMARY KEY,
            stat_name VARCHAR(255),
            average_packet_size FLOAT,
            mean_packet_size FLOAT,
            average_packet_rate FLOAT,
            mean_packet_rate FLOAT,
            total_packets INT,
            peak_packet_rate FLOAT,
            peak_packet_rate_time VARCHAR(50),
            peak_bandwidth FLOAT,
            peak_bandwidth_time VARCHAR(50),
            most_common_protocol VARCHAR(10),
            most_common_source_ip VARCHAR(45),
            most_common_destination_ip VARCHAR(45),
            packet_error_rate FLOAT,
            duplicate_packet_amount INT,
            duplication_source_ip VARCHAR(45),
            duplication_destination_ip VARCHAR(45),
            started_calculation VARCHAR(50),
            last_calculation VARCHAR(50),
            time_period VARCHAR(10)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS baselines (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nic VARCHAR(17),
            baseline_type VARCHAR(255),
            established_time DATETIME,
            ended_time DATETIME,
            last_updated DATETIME,
            packet_count INT,
            average_packet_size FLOAT,
            mean_packet_size FLOAT,
            average_packet_rate FLOAT,
            mean_packet_rate FLOAT,
            peak_packet_rate FLOAT,
            finalized TINYINT DEFAULT 0,
            FOREIGN KEY (nic)
                REFERENCES nic_record(mac_address) ON DELETE SET NULL
        )
        """,
    ]

    execute_queries(cursor, tables)


def create_triggers(cursor):
    triggers = [
        """
        CREATE TRIGGER IF NOT EXISTS update_last_seen_trigger
            AFTER UPDATE ON nic_record
            FOR EACH ROW
            BEGIN
                UPDATE nic_stats
                SET last_updated = NEW.last_seen
                WHERE nic = NEW.mac_address;
            END;
        """,
        """
        CREATE TRIGGER IF NOT EXISTS insert_new_row_trigger
            AFTER INSERT ON nic_record
            FOR EACH ROW
            BEGIN
                INSERT INTO nic_stats (nic)
                VALUES (NEW.mac_address);
            END;
        """
    ]

    execute_queries(cursor, triggers)
    

def create_and_config_database():
    try:
        cursor, connection = connect_to_db()
        create_database(cursor)
        create_tables(cursor)
        create_triggers(cursor)
        connection.commit()
    except mysql.Error as err:
        print(f"Error creating database or tables: {err}")
        sys.exit()
    finally:
        close_db_connection(cursor, connection)