# CodeAlpha Network Sniffer

A basic network sniffer built with Python and Scapy for the CodeAlpha Cyber Security Internship (Task 1).

## What it shows for each packet
- Source and destination IP address
- Protocol (TCP, UDP, ICMP)
- Source and destination ports
- First 30 bytes of the payload

## Setup
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

## Run
    sudo venv/bin/python sniffer.py

Press Ctrl+C to stop. The total packets captured is printed at the end.

## Notes
- Root permission is needed to capture packets.
- HTTPS (TCP/UDP port 443) payloads are encrypted, so they look random.
- Use this tool only on networks you own or have permission to monitor.
