from scapy.all import *

# Create a list of Ethernet frames with custom payloads
eth_frames = [
    Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / IP(dst="192.168.1.1", src="192.168.1.2") / TCP(),
    Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / IP(dst="192.168.1.2", src="192.168.1.1") / UDP(),
]

# Write the frames to a PCAP file
wrpcap("custom_packets.pcap", eth_frames)
