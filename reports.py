import sys
import datetime
from datetime import datetime
import time
import mysql.connector as mysql

DB_CONFIG_3 = {
    'user': 'user3',
    'password': 'password3',
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}


def connect_to_db():
    connection = mysql.connect(**DB_CONFIG_3)
    cursor = connection.cursor()
    return cursor, connection


def close_db_connection(cursor, connection):
    if cursor:
        cursor.close()
    if connection:
        connection.close()


def execute_query(cursor, query):
    cursor.execute(f"USE network")

    try:
        cursor.execute(query)
    except mysql.Error as err:
        print(f"Error executing queries: {err} {query}")


def generate_sql_statement(record):
    multiple_mac_addresses = record[12]

    if multiple_mac_addresses is True:
        

def time_check():
    cursor = None
    connection = None
    if not cursor or not connection or not connection.is_connected():
        cursor, connection = connect_to_db()
        cursor.execute(f"USE network")
        if not connection:
            time.sleep(5)

    """
    id = record[0]
    priority = record[1]
    request_name = record[2]
    date_requested = record[3] 
    date_completed = record[4] 
    last_updated = record[5]
    occurrence = record[6] 
    occurrence_interval = record[7] 
    start_immidiately = record[8] 
    report_start_time = record[9] 
    report_continous = record[10] 
    report_end_time = record[11] 
    multiple_mac_addresses = record[12]
    mac_address = record[13]     
    multiple_ip_addresses = record[14]
    ip_address = record[15]
    mac_address_source = record[16]
    ip_address_source = record[17]
    mac_address_destination = record[18]
    ip_address_destination = record[19]
    port_number = record[20]
    port_source = record[21]
    port_destination = record[22]
    protocol = record[23]
    track_packet_count = record[24]
    status = record[25]
    """

    while True:
        cursor.execute("SELECT * FROM report_requests WHERE status = 'active'")
        records = cursor.fetchall()
        if records:
            for record in records:
                # Check if report is continuous
                if record[10] is True:
                    pass
                elif record[10] is False:
                    pass
                else:
                    pass
                
                # Check if report end time has passed
                if record[11] >= datetime.now():
                    sql_statement = generate_sql_statement(record)
                    execute_query(cursor, "UPDATE report_requests SET status = 'completed' WHERE id = %s", (record[0],))
                elif record[11] <= datetime.now():
                   cursor.execute("UPDATE report_requests SET status = 'completed' WHERE id = %s", (record[0],))
                else:
                    pass




