#!/usr/bin/env python3
# CYSE 493 - CINA Alphaguardian
# Individual research by Tung Truong

import os
import re
import csv
from email import Message

def extract_message(msg_folder, txt_folder):
    header_pattern = re.compile(r"^(.*?):\s*(.*?)\s*$")
    header_fields = ['Filename', 'Subject', 'From', 'To', 'Cc', 'Bcc', 'IP Addresses']
    with open(os.path.expanduser("Output csv file"), 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([header_fields])
    for file_name in os.listdir(msg_folder):
        if file_name.endswith(".eml"):
            file_path = os.path.join(msg_folder, file_name)

            msg = Message(file_path)
            if msg.body is not None:
                with open(os.path.join(txt_folder, f"{os.path.splitext(file_name)[0]}.txt"), "w") as f:
                    f.write(msg.body)
                headers = {}
                with open(os.path.join(txt_folder, f"{os.path.splitext(file_name)[0]}.txt"), "r") as f:
                    for line in f:
                        match = re.match(header_pattern, line)
                        if match:
                            key = match.group(1)
                            value = match.group(2)
                            if key in headers:
                                headers[key] += ", " + value
                            else:
                                headers[key] = value
            else:
                print(f"No body found in {file_name}")

extract_message("Phish_eml_directory", "Output_Directory")