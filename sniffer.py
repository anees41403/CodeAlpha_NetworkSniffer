from scapy.all import sniff, IP, TCP, UDP, Raw

protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
total = 0

def show(packet):
    global total
    if not packet.haslayer(IP):
        return

    total += 1
    number = packet[IP].proto
    name = protocols.get(number, "Other")

    print("Packet number:", total)
    print("Source:", packet[IP].src)
    print("Destination:", packet[IP].dst)
    print("Protocol:", name, "(" + str(number) + ")")

    if packet.haslayer(TCP):
        print("Ports:", packet[TCP].sport, "->", packet[TCP].dport)
    elif packet.haslayer(UDP):
        print("Ports:", packet[UDP].sport, "->", packet[UDP].dport)

    if packet.haslayer(Raw):
        print("Payload (first 30 bytes):", bytes(packet[Raw].load)[:30])

    print("-" * 30)

print("Sniffer started. Press Ctrl+C to stop.")
try:
    sniff(prn=show, store=False)
except KeyboardInterrupt:
    pass
print("Stopped. Total IP packets captured:", total)

