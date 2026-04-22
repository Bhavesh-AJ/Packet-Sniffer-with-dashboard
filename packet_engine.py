from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

SUSPICIOUS_PORTS = {
    22: "SSH Brute Force",
    23: "TELNET",
    3306: "MySQL",
    4444: "Backdoor",
    8080: "Proxy"
}

KEYWORDS = [b"password", b"login", b"admin"]

def analyze_pcap(file):
    packets = rdpcap(file)

    stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0, "Suspicious": 0}
    results = []

    for p in packets:
        if IP not in p:
            continue

        protocol = "Other"
        port = None

        if TCP in p:
            protocol = "TCP"
            port = p[TCP].dport
            stats["TCP"] += 1
        elif UDP in p:
            protocol = "UDP"
            port = p[UDP].dport
            stats["UDP"] += 1
        elif ICMP in p:
            protocol = "ICMP"
            stats["ICMP"] += 1
        else:
            stats["Other"] += 1

        suspicious = False
        reason = []

        # Port check
        if port in SUSPICIOUS_PORTS:
            suspicious = True
            reason.append(SUSPICIOUS_PORTS[port])

        # Payload check
        if Raw in p:
            payload = p[Raw].load.lower()
            for k in KEYWORDS:
                if k in payload:
                    suspicious = True
                    reason.append(k.decode())

        if suspicious:
            stats["Suspicious"] += 1

        results.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "src": p[IP].src,
            "dst": p[IP].dst,
            "protocol": protocol,
            "port": port,
            "size": len(p),
            "alert": ", ".join(reason) if suspicious else "None"
        })

    return stats, results