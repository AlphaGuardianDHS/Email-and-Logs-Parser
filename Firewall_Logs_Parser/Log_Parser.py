#!/usr/bin/env python3
# CYSE 493 - CINA Alphaguardian
# Individual research by Tung Truong

import re
import csv
import requests
import mysql.connector


def parse_blocked_firewall_events(firewall_log, suspicious_ips):
    # Load log entries from the log file, match them with "Blocked" events,
    # sort them by source IP address and source port, and return the sorted events.

    # Load log entries from the log file
    with open(firewall_log, 'r') as f:
        logs = f.readlines()

    with open(suspicious_ips, 'r') as f:
        # sus_ips = set(line.strip() for line in f)
        sus_ips = f.readlines()
    # Define regular expression patterns to match log entries
    src_ip = re.compile(r'(SRC=\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
    dst_port = re.compile(r'(DPT=\d+)')
    time_stamp = re.compile(r'(\d{2}:\d{2}:\d{2})')

    blocked_events = []
    for log in logs:
        src_ip_match = src_ip.findall(log)
        dst_port_match = dst_port.findall(log)
        time_stamp_match = time_stamp.findall(log)
        blocked_events.append((time_stamp_match, src_ip_match, dst_port_match))

    blocked_events.sort(key=lambda x: (x[1], x[2]))

    found_sus_ip = []
    for sus in sus_ips:
        if sus in blocked_events:
            found_sus_ip.append(sus)

    with open('firewall_output2.txt', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp:', 'SRC:', 'DPT:'])
        writer.writerows(blocked_events)

    with open('sus.txt', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Found: '])
        writer.writerows(found_sus_ip)


def check_ip_with_abuseipdb(api_key, firewall_log):
    # Check the source IP addresses in the firewall log against AbuseIPDB and write the results to a CSV file.

    # Load the log entries from the firewall log file
    with open(firewall_log, 'r') as f:
        logs = f.readlines()

    src_ip = re.compile(r'(SRC=\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
    # Extract the source IP addresses from the log entries
    src_ips = []
    for log in logs:
        src_ip1 = src_ip.findall(log)
        src_ips.append(src_ip1)

    # Remove duplicates from the list of source IP addresses
    # src_ips = list(set(src_ips))

    # Check each source IP address against AbuseIPDB
    results = []
    for src_ip in src_ips:
        response = requests.get(f'https://api.abuseipdb.com/api/v2/check?ip={src_ip}',
                                headers={'Key': api_key, 'Accept': 'application/json'})
        data = response.json()
        abuse = data['data']['abuseConfidenceScore']
        results.append((src_ip, abuse))

    # Write the results to a CSV file
    with open('firewall_output.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Source IP', 'Abuse Score'])
        writer.writerows(results)


def upload_to_database(anomalies):
    """
    Connect to the database, insert the anomalies into the database,
    commit the changes, and close the connection.
    """
    # Connect to the database
    conn = mysql.connector.connect(
        host='host_name',
        user='user_name',
        password='password',
        database='alphaguardian.us'
    )

    # Insert the anomalies into the database
    cursor = conn.cursor()
    cursor.executemany('INSERT INTO anomalies (timestamp, device, event, src_ip) VALUES (%s, %s, %s, %s)', anomalies)

    # Commit the changes and close the connection
    conn.commit()
    cursor.close()
    conn.close()



parse_blocked_firewall_events('FirewallLog.txt', 'suspicious_ips.txt')
check_ip_with_abuseipdb("d6c1d5f34c2ee761d44209a228a99db25d9e6bb1d0bb4b386e585312dfbf39573fb6141e8d57677d",
                           "firewall_output2.txt")
upload_to_database('firewall_output2.txt')