from scapy.all import sniff, IP, TCP, UDP, Raw

total = 0


def show(packet):
    global total

    if not packet.haslayer(IP):
        return

    total += 1
    protocol = packet[IP].proto

    name = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }.get(protocol, "Other")

    print("\nPacket number:", total)
    print("Source: [HIDDEN]")
    print("Destination: [HIDDEN]")
    print("Protocol:", name, "(" + str(protocol) + ")")

    if packet.haslayer(TCP):
        print("Ports:", packet[TCP].sport, "->", packet[TCP].dport)
    elif packet.haslayer(UDP):
        print("Ports:", packet[UDP].sport, "->", packet[UDP].dport)

    if packet.haslayer(Raw):
        print("Payload: [HIDDEN]")

    print("-" * 30)


print("Network Sniffer Started")
print("IP addresses and payload are hidden.")
print("Press Ctrl+C to stop.")

try:
    sniff(filter="ip", prn=show, store=False)
except KeyboardInterrupt:
    pass

print("\nSniffer stopped. Total IP packets captured:", total)
