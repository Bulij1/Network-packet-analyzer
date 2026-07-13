import matplotlib.pyplot as plt

def protocol_graph(tcp_count,udp_count,icmp_count,arp_count):
   labels = ["TCP","UDP","ICMP","ARP"]
   values = [tcp_count,udp_count,icmp_count,arp_count]
   plt.bar(labels,values)
   plt.title("Protocol Distribution")
   plt.xlabel("Protocols")
   plt.ylabel("Number of Packets")
   plt.savefig("output/protocol_distribution.png")
   plt.show()