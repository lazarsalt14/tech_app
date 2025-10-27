"""
sender.py
By: Nishanth Senthil Kumar
Roll No: EE23B049

Sends a custom Ethernet frame containing a message to a specific MAC address.

Usage:
    python3 sender.py
Then, you will be prompted for:
    - Interface (e.g., en0)
    - Destination MAC address (e.g., d6:08:37:6e:50:a8)
    - Message to send
    you can get mac address by running 'ifconfig <interface_name> | grep ether' on the destination device
"""

from scapy.all import Ether, sendp

def main():
    interface = input("Enter interface (e.g., en0): ").strip()
    dest_mac = input("Enter destination MAC address (e.g., d6:08:37:6e:50:a8): ").strip()
    message = input("Enter message to send: ").encode()

    frame = Ether(dst=dest_mac, type=0x1234) / message

    print(f"\nUsing interface: {interface}")
    print(f"Sending message '{message.decode()}' to {dest_mac} ...")

    sendp(frame, iface=interface, verbose=False)
    print("Frame sent successfully!")

if __name__ == "__main__":
    main()
