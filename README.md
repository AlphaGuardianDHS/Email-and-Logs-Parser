# Email-and-Logs-Parser

[*] CYSE 493 - CINA AlphaGuardian - support by Dr. Jim Jones (Director and digital forensics lead for Mason's DHS Center of Excellence for Criminal Investigations and Network Analysis (https://cina.gmu.edu/).
[*] Individual research by Tung Truong
[*] Overview of the project, our interest as a group is to discover cybercriminal network infrastructure by inferring their network node for reconnaissance purposes. As a result, security experts may be able to look back in time to better understand cyber attacks, detect malware infections, detect system and device misuse, and recover lost data.
[*] Part of my interested design is to optimize our network discovery analysis with email parser which could parse out headers information that are helpful for our analysis.
[*] We perform our analysis on emails that were reported as "spam" for this particular design. Since this is by far the best method we have discovered for gathering information from cybercriminals who use email infrastructure for phishing, spam, and other purposes. 
[*] Having understood the project's goal and intention, I researched and designed a program that could assist the team in parsing out these spam emails for headers, but only for information such as "Sender", "Sender IP addresses", and "Subject".


[*] *********ALERT PLEASE READ*********
[*] Before reading and testing the design. I just want to warn users that some parts of the design may contain malware. I strongly advise using a Virtual Machine to implement the design.

[*] Email_Parser --> How does the program work?

[*] The user must download all spam emails from the spam folder and format them with the extension ".msg" and convert them to text in order to analyze the header and avoid malware or packed executable files that may be embedded within the emails.
[*] The best way I discovered while working on the design is to convert ".msg" to ".eml," which reveals the email header.
[*] Once the file has been converted to ".eml," run "eml parser.py" to parse out the Filename, Sender, and Sender IP addresses and output the csv file to wherever you want to save the result on your machine.

[*] You could also use "Message Extraction.py" to extract the message from the email. Some of them may contain links to malicious websites or potentially unwanted programs, but because we have them in text format, the risk has been mitigated.


[*] The program design was tested with Dr.Jone provided spam emails

ip_counts.txt        --> Count how many time a particular IP address appear in Firewall log

firewall_output2.txt --> Display timestamps, IP addresses, and destination ports. The purpose of timestamp is to analyze
				 the frequency of the IP address i.e. how often a particular IP address occur
				 and at what time of the day it usually hit the firewall
