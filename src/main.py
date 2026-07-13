from packet_functions import *
from graph import protocol_graph
from scapy.all import *
import csv

packets = sniff(count=50)

print(packets)

tcp_count = 0
udp_count = 0
icmp_count = 0
arp_count = 0
total_count = 0

with open("output/captured_packets.csv","w",newline="") as myfile:
    writer = csv.writer(myfile)

    writer.writerow([
        "Protocol",
        "Source IP",
        "Destination IP",
        "Source Port",
        "Destination Port",
        "Packet Size",
        "Capture Time"
    ])

    for packet in packets:
        total_count += 1

        Length = length(packet)
        SourceIP, DestinationIP = address(packet)
        Capturetime = capturetime(packet)
        protocol = get_protocol(packet)

        if(protocol == "TCP"):
            SourcePort, DestinationPort = ports(packet)
            tcp_count += 1
            display_packet(protocol,SourceIP,DestinationIP,Length,Capturetime,SourcePort,DestinationPort)

        elif(protocol == "UDP"):
            SourcePort,DestinationPort = ports(packet)
            udp_count += 1
            display_packet(protocol,SourceIP,DestinationIP,Length,Capturetime,SourcePort,DestinationPort)

        elif(protocol == "ICMP"):
            icmp_count += 1
            display_packet(protocol,SourceIP,DestinationIP,Length,Capturetime)

        elif(protocol == "ARP"):
            arp_count += 1
            display_packet(protocol,SourceIP,DestinationIP,Length,Capturetime)

        if(packet.haslayer(TCP) or packet.haslayer(UDP)):
            SourcePort,DestinationPort = ports(packet)
            writer.writerow([
                protocol,
                SourceIP,
                DestinationIP,
                SourcePort,
                DestinationPort,
                Length,
                Capturetime
            ])

        elif(packet.haslayer(ICMP) or packet.haslayer(ARP)):
            writer.writerow([
                protocol,
                SourceIP,
                DestinationIP,
                "None",
                "None",
                Length,
                Capturetime
            ])

display_distsize(packets,total_count)
display_statistics(tcp_count,udp_count,icmp_count,arp_count,total_count)
filter_by_protocol(packets)
ips_ports(packets)
protocol_graph(tcp_count,udp_count,icmp_count,arp_count)