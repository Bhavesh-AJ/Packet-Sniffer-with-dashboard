from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap
import random

packets = []

# 🔢 how many you want
COUNT = 50   # change this to increase data

# 🟢 NORMAL TRAFFIC
for _ in range(COUNT):
    packets.append(IP(dst="8.8.8.8")/TCP(dport=80))
    packets.append(IP(dst="1.1.1.1")/UDP(dport=53))
    packets.append(IP(dst="192.168.1.1")/ICMP())

# 🔴 SUSPICIOUS TRAFFIC (same amount)
for _ in range(COUNT):
    packets.append(IP(dst="192.168.1.10")/TCP(dport=22)/Raw(load="password=1234"))
    packets.append(IP(dst="10.0.0.5")/TCP(dport=23)/Raw(load="login=admin"))
    packets.append(IP(dst="172.16.0.2")/TCP(dport=4444)/Raw(load="hack attempt"))

# 🔀 shuffle so it's mixed
random.shuffle(packets)

# 💾 Save file
wrpcap("test.pcap", packets)

print("✅ Balanced test.pcap created!")