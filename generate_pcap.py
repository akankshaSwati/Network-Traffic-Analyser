from scapy.all import *

# Create a list of Ethernet frames with custom payloads
eth_frames = [
    Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / IP(dst="192.168.1.1", src="192.168.1.2") / TCP(),
    Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / IP(dst="192.168.1.2", src="192.168.1.1") / UDP(),
    Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / IP(dst="192.168.1.1", src="192.168.1.2") / ICMP(),
    Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / IP(dst="8.8.8.8", src="192.168.1.1") / UDP(sport=12345, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.example.com")),
]

# Write the frames to a PCAP file
wrpcap("custom_packets.pcap", eth_frames)
