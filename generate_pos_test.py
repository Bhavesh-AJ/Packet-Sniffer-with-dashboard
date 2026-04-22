from scapy.all import IP, TCP, UDP, ICMP, wrpcap
import random

packets = []

# Safe IP ranges
ips = [f"192.168.1.{i}" for i in range(1, 50)]
targets = ["8.8.8.8", "1.1.1.1", "142.250.183.14"]

# SAFE PORTS ONLY (avoid suspicious ones like 22, 23, 4444, etc.)
safe_ports = [80, 443, 53, 123]

for _ in range(500):  # increase if needed
    src = random.choice(ips)
    dst = random.choice(targets)

    proto = random.choice(["TCP", "UDP", "ICMP"])

    if proto == "TCP":
        pkt = IP(src=src, dst=dst) / TCP(dport=random.choice(safe_ports))
    elif proto == "UDP":
        pkt = IP(src=src, dst=dst) / UDP(dport=random.choice(safe_ports))
    else:
        pkt = IP(src=src, dst=dst) / ICMP()

    packets.append(pkt)

# Save file
wrpcap("test_safe.pcap", packets)

print("✅ Safe PCAP generated: test_safe.pcap")