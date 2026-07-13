# Network Packet Analyzer

## Project Description

This project is a simple Network Packet Analyzer developed in Python using the Scapy library. It captures live network packets, analyzes them, and displays useful information such as protocol, IP addresses, ports, packet size, and capture time.

The program also exports captured packet information to a CSV file and generates a protocol distribution graph using Matplotlib.

---

## Features

- Capture 50 live network packets
- Detect TCP, UDP, ICMP, and ARP packets
- Display packet details
- Export packet information to CSV
- Show protocol statistics
- Show packet size statistics
- Filter packets by protocol
- Find the most frequently used Source and Destination IP addresses
- Find the most frequently used Source and Destination Ports
- Generate a Protocol Distribution graph

---

## Technologies Used

- Python
- Scapy
- Matplotlib
- CSV Module

---

## Project Structure

```
CN Project
│
├── src
│   ├── main.py
│   ├── packet_functions.py
│   ├── graph.py
│   └── packet_analyzer_full.py
│
├── output
│   ├── captured_packets.csv
│   └── protocol_distribution.png
│
├── screenshots
│
├── README.md
├── requirements.txt
└── LICENSE
```

---

## Installation

Install the required libraries:

```bash
pip install -r requirements.txt
```

---

## How to Run

Open the project folder and run:

```bash
python src/main.py
```

The program will:

- Capture live packets
- Display packet information
- Save packet data to a CSV file
- Generate a protocol distribution graph

---

## Output Files

- captured_packets.csv
- protocol_distribution.png

---

## Authors

Developed as part of the Computer Networks course project.