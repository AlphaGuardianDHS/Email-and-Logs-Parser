#!/usr/bin/env python3
# CYSE 493 - CINA Alphaguardian
# Individual research by Tung Truong

import os
import re
import csv
import email

def extract_email_headers(eml_folder, csv_file):
    ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    rows = []

    for file_name in os.listdir(eml_folder):
        if file_name.endswith(".eml"):
            file_path = os.path.join(eml_folder, file_name)
            with open(file_path, "r") as f:
                message = email.message_from_file(f)
                from_field = email.message.get("From")
                headers = dict(message.items())
                sender_ip = ""
                for field in ["Received", "X-Originating-IP", "X-Sender-IP"]:
                    if field in headers:
                        ip_addresses = re.findall(ip_pattern, headers[field])
                        if len(ip_addresses) > 0:
                            sender_ip = ip_addresses[0]
                rows.append([file_name, from_field, sender_ip])
                rows.append("\n\n")
    with open(csv_file, "w") as f:
        writer = csv.writer(f)
        writer.writerow(["File Name: ", "From: ", "Sender IP: "])
        writer.writerow(rows)

extract_email_header("Phish_Email_Directory", "Output_file_Directory")