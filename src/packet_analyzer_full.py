from scapy.all import *
from datetime import datetime
import csv
import matplotlib.pyplot as plt

packets = sniff(count = 50)

print(packets)

tcp_count = 0
udp_count = 0
icmp_count = 0
arp_count = 0
total_count = 0

def Protocol(packet):
 if(packet.haslayer(TCP)):
    return "TCP"   
 elif(packet.haslayer(UDP)):
    return "UDP"
 elif(packet.haslayer(ICMP)):
    return "ICMP"
 elif(packet.haslayer(ARP)):
    return "ARP"

def length(packet):
    return len(packet)

def ports(packet):
   if packet.haslayer(TCP):
    return packet[TCP].sport,packet[TCP].dport

   elif packet.haslayer(UDP):
    return packet[UDP].sport,packet[UDP].dport
    
def address(packet):
    if(packet.haslayer(IP)):
        return packet[IP].src,packet[IP].dst
    
    elif(packet.haslayer(IPv6)):
        return packet[IPv6].src,packet[IPv6].dst
        
    elif(packet.haslayer(ARP)):
        return packet[ARP].psrc,packet[ARP].pdst
    
def capturetime(packet):
   capturetime = datetime.fromtimestamp(packet.time)
   return capturetime.strftime("%Y-%m-%d %H:%M:%S")

def display_statistics(tcp_count,udp_count,icmp_count,arp_count,total_count):
    print("==========SUMMARY==========")
    print("TCP: ", tcp_count)
    print("UDP: ", udp_count)
    print("ICMP: ", icmp_count)
    print("ARP: ", arp_count)
    print("Total Packets: ", total_count)

def display_distsize(total_count):
   largest_packet_size = length(packets[0])
   smallest_packet_size = length(packets[0])
   total_size = 0
   for packet in packets:
    Length = length(packet)
    if Length > largest_packet_size:
       largest_packet_size = Length
       total_size += Length
    elif Length < smallest_packet_size:
       smallest_packet_size = Length
       total_size += Length
    else:
       total_size += Length 
   average = total_size/total_count
   print("==========Size Distribution==========")
   print("Largest Packet Size: ", largest_packet_size)
   print("Smallest Packet Size: ", smallest_packet_size)
   print("Total Size: ",total_size)
   print("Average Size: ",average)
       
def filter_by_protocol():
    choice = input("Enter Protocol: ").upper()
    found = False
    for packet in packets:
         protocol = Protocol(packet)
         if(protocol == choice):
          found = True
          Length = length(packet)
          SourceIP,DestinationIP = address(packet)
          Capturetime = capturetime(packet)
          if(protocol == "TCP") or (protocol == "UDP"):
           SourcePort,DestinationPort = ports(packet)
           display_packet(protocol,SourceIP,DestinationIP,Length,Capturetime,SourcePort,DestinationPort)
          else:
           display_packet(protocol,SourceIP,DestinationIP,Length,Capturetime)
    if(found == False):
     print("Not Found")

def ips_ports():
    Ips = {
       "Source Ip": {
          
       },

       "Destination Ip": {
          
        }
    }

    Ports = {
       "Source Port": {
          
        },

       "Destination Port" : {
           

        }
    }   

    for packet in packets:
     SourceIP,DestinationIP = address(packet)
     protocol = Protocol(packet)
     if(SourceIP in Ips["Source Ip"]):
        Ips["Source Ip"][SourceIP] +=1
     elif(SourceIP not in Ips["Source Ip"]):
        Ips["Source Ip"][SourceIP]  = 1
     if(DestinationIP in Ips["Destination Ip"]):
        Ips["Destination Ip"][DestinationIP] += 1
     elif(DestinationIP not in Ips["Destination Ip"]):
        Ips["Destination Ip"][DestinationIP] = 1
     if(protocol == "TCP") or  (protocol == "UDP"):
       SourcePort,DestinationPort = ports(packet)
       if(SourcePort in Ports["Source Port"]):
        Ports["Source Port"][SourcePort] += 1
       elif(SourcePort not in  Ports["Source Port"]):
        Ports["Source Port"][SourcePort] = 1
       if(DestinationPort in  Ports["Destination Port"]):
        Ports["Destination Port"][DestinationPort] += 1   
       elif(DestinationPort not in  Ports["Destination Port"]):
        Ports["Destination Port"][DestinationPort] = 1

    highest_count = 0
    top_ip = ""
    top_port = 0  
    for SourceIP in Ips["Source Ip"]:
      counter = Ips["Source Ip"][SourceIP]
      if counter > highest_count:
       highest_count = counter
       top_ip = SourceIP
    print("Top Used Source IP: ",top_ip)
    print("Number of times used: ", highest_count)
    highest_count = 0
    top_ip = ""
    for DestinationIP in Ips["Destination Ip"]:
      counter = Ips["Destination Ip"][DestinationIP]
      if counter > highest_count:
       highest_count = counter
       top_ip = DestinationIP
    print("Top Used Destination IP: ",top_ip)
    print("Number of times used: ", highest_count)
    highest_count = 0
    top_ip = ""
    for SourcePort in Ports["Source Port"]:
      counter = Ports["Source Port"][SourcePort]
      if counter > highest_count:
       highest_count = counter
       top_port = SourcePort
    print("Top Used Source Port: ",top_port)
    print("Number of times used: ", highest_count)
    highest_count = 0
    top_port = ""
    for DestinationPort in Ports["Destination Port"]:
      counter = Ports["Destination Port"][DestinationPort]
      if counter > highest_count:
       highest_count = counter
       top_port = DestinationPort
    print("Top Used Destination Port: ",top_port)
    print("Number of times used: ", highest_count)
    highest_count = 0
    top_ip = "" 

def display_packet(protocol, SourceIP, DestinationIP, Length, Capturetime,SourcePort = "",DestinationPort = ""):
    if(protocol == "TCP") or (protocol == "UDP"):
     print(protocol)
     print("Source IP: ",SourceIP)
     print("Destination IP: ",DestinationIP)
     print("Source Port: ",SourcePort)
     print("Destination Port: ",DestinationPort)
     print("Length of Packet: ",Length)
     print("Time: ",Capturetime) 
     print("=" * 50)
    elif(protocol == "ICMP") or (protocol == "ARP"):
     print(protocol)
     print("Source IP: ",SourceIP)
     print("Destination IP: ",DestinationIP)
     print("Length of Packet: ",Length)
     print("Time: ",Capturetime) 
     print("=" * 50)    
       
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
    SourceIP,DestinationIP = address(packet)
    Capturetime = capturetime(packet)
    protocol = Protocol(packet)
    if(protocol == "TCP"):
       SourcePort,DestinationPort = ports(packet)
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
           
    if(packet.haslayer(TCP)) or (packet.haslayer(UDP)):
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
    elif(packet.haslayer(ARP)) or (packet.haslayer(ICMP)):
     writer.writerow([
       protocol,
       SourceIP,
       DestinationIP,
       "None",
       "None",
       Length,
       Capturetime
   ])     
     
def protocol_graph(tcp_count,udp_count,icmp_count,arp_count):
   labels = ["TCP","UDP","ICMP","ARP"]
   values = [tcp_count,udp_count,icmp_count,arp_count]
   plt.bar(labels,values)
   plt.title("Protocol Distribution")
   plt.xlabel("Protocols")
   plt.ylabel("Number of Packets")
   plt.savefig("output/protocol_distribution.png")
   plt.show()
   
display_distsize(total_count)

display_statistics(tcp_count,udp_count,icmp_count,arp_count,total_count)

filter_by_protocol()

ips_ports()

protocol_graph(tcp_count,udp_count,icmp_count,arp_count)

