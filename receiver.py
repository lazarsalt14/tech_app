"""
receiver.py
By: Nishanth Senthil Kumar
Roll No: EE23B049

Listens for custom Ethernet frames and extracts the data payload.

Usage:
    python3 receiver.py
Then, you will be prompted for:
    - Interface (e.g., en0)
    - Sender MAC address (e.g., d6:08:37:6e:50:a8)
"""

from scapy.all import sniff, Ether, Raw

def handle_packet(packet, sender_mac):
    """
    Callback for sniff() that handles each captured packet.
    Only prints packets from the specified sender MAC and EtherType 0x1234.
    """
    if Ether in packet and packet.type == 0x1234 and packet.haslayer(Raw):
        src_mac = packet[Ether].src.lower()
        if src_mac == sender_mac.lower():
            data = packet[Raw].load.rstrip(b'\x00')  #remove padding
            try:
                message = data.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                message = str(data)
            print(f"Received message from {src_mac}: '{message}'")

def main():
    interface = input("Enter network interface (e.g., en0): ").strip()
    sender_mac = input("Enter sender MAC address (e.g., d6:08:37:6e:50:a8): ").strip()

    print(f"\n[*] Listening on {interface} for Ethernet frames from {sender_mac}...\n")

    sniff(iface=interface,prn=lambda pkt: handle_packet(pkt, sender_mac),store=0,lfilter=lambda p: Ether in p and p.type == 0x1234)  

if __name__ == "__main__":
    main()
