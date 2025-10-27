''' 
By: Nishanth Senthil Kumar 
Roll Number : EE23B049
Input : On running the python script, please enter the file name (.pcap file)
Output : A Table on terminal, containing the relevant information 
'''

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from prettytable import PrettyTable


def get_channel(packet):
    '''Extract the channel number from 802.11 elements.'''
    channel = None
    element = packet.getlayer(Dot11Elt)

    while element:
        
        if element.ID == 3 and len(element.info) == 1:
            #info is a byte array
            if isinstance(element.info, bytes):
                channel = element.info[0]
            else:
                channel = int(element.info)
            break

        #HT Information (802.11n, may include 5GHz)
        elif element.ID == 61 and len(element.info) > 0:
            channel = element.info[0]
            break

        #VHT Operation (802.11ac)
        elif element.ID == 192 and len(element.info) > 1:
            channel = element.info[1]
            break

        element = element.payload.getlayer(Dot11Elt)

    return channel



def get_band(channel):
    """Return the frequency band from channel number."""
    if channel is None:
        return "Unknown"
    if 1 <= channel <= 14:
        return "2.4GHz"
    if 36 <= channel <= 165:
        return "5GHz"
    return "Unknown"



def get_bandwidth(packet):
    ht_info = packet.getlayer(Dot11Elt, ID=61)
    vht_info = packet.getlayer(Dot11Elt, ID=192)

    if vht_info and len(vht_info.info) >= 3:
        width_code = vht_info.info[2]

        if width_code == 0:
            return "20/40MHz"
        elif width_code == 1:
            return "80MHz"
        elif width_code == 2:
            return "160MHz"
        elif width_code == 3:
            return "80+80MHz"

    elif ht_info:
        return "20/40MHz"

    return "20MHz"



def detect_protocol(packet, band, supported_rates):
    """This is to find the version of 802.11 protocol being used"""
    has_ht = packet.getlayer(Dot11Elt, ID=45)     # 802.11n
    has_ht_info = packet.getlayer(Dot11Elt, ID=61)
    has_vht = packet.getlayer(Dot11Elt, ID=191)   # 802.11ac
    has_he = packet.getlayer(Dot11Elt, ID=255)    # 802.11ax

    if has_he:
        return "802.11ax (Wi-Fi 6)"
    elif has_vht:
        return "802.11ac (Wi-Fi 5)"
    elif has_ht or has_ht_info:
        return "802.11n (Wi-Fi 4)"
    else:

        basic_rates = set()
        for r in supported_rates:
            basic_rates.add(r)

        if basic_rates.issubset({1, 2, 5.5, 11}):
            return "802.11b"
        elif band == "2.4GHz":
            return "802.11g"
        elif band == "5GHz":
            return "802.11a"
        else:
            return "Unknown"



def analyze_wifi_networks(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[!] File not found: {pcap_file}")
        return

    networks = {}

    for packet in packets:
        if not packet.haslayer(Dot11Beacon):
            continue

        dot11 = packet[Dot11]
        fc_field = dot11.FCfield

        #the way bssid and sender/receiver ids are encoded in header file depend on whether the packet is from sta(laptop) to ap or vice versa 
        if fc_field & 0x1:     # To DS
            bssid = dot11.addr1
        elif fc_field & 0x2:   # From DS
            bssid = dot11.addr2
        else:
            bssid = dot11.addr3

        if not bssid:
            continue

        #ssid is stored in the first id of Dot11Elt frames, if it is empty, then it is hidden for privacy purposes by the sender
        ssid_element = packet.getlayer(Dot11Elt, ID=0)
        if ssid_element and ssid_element.info:
            try:
                ssid = ssid_element.info.decode(errors='ignore').strip()
            except Exception:
                ssid = "<Hidden SSID>"
        else:
            ssid = "<Hidden SSID>"

        if ssid == "":
            ssid = "<Hidden SSID>"

        #getting supported rates (the thing gives it in units of 500kbps )
        supported_rates = []
        rate_element = packet.getlayer(Dot11Elt, ID=1)
        if rate_element and rate_element.info:
            for rate in rate_element.info:
                supported_rates.append(rate / 2.0)

        #important params
        channel = get_channel(packet)
        band = get_band(channel)
        bandwidth = get_bandwidth(packet)

        #to identify protocol
        protocol = detect_protocol(packet, band, supported_rates)

        #extracting RSSI from RadioTap header frame (not actually part of 802.11 protocol, captured in monitor mode)
        rssi = None
        if packet.haslayer(RadioTap):
            radio = packet[RadioTap]
            if hasattr(radio, "dBm_AntSignal"):
                rssi = radio.dBm_AntSignal
            elif hasattr(radio, "fields") and "dBm_AntSignal" in radio.fields:
                rssi = radio.fields["dBm_AntSignal"]

        
        if bssid not in networks:
            networks[bssid] = {
                "ssid": ssid,
                "protocol": protocol,
                "band": band,
                "channel": channel,
                "bandwidth": bandwidth,
                "rssi_values": []
            }

        #sometimes it gives a positive value which is wrong, rssi is always negative
        if rssi is not None and isinstance(rssi, (int, float)) and rssi < 0:
            networks[bssid]["rssi_values"].append(rssi)

    #using pretty tablt to display neatly (gpted this)
    table = PrettyTable()
    table.field_names = ["SSID", "BSSID", "Protocol", "Band", "Channel", "Bandwidth", "Avg RSSI (dBm)"]

    for bssid in networks:
        info = networks[bssid]

        if len(info["rssi_values"]) > 0:
            avg_rssi = round(float(sum(info["rssi_values"])/len(info["rssi_values"])), 2)
        else:
            avg_rssi = "N/A"

        table.add_row([
            info["ssid"],
            bssid,
            info["protocol"],
            info["band"],
            info["channel"],
            info["bandwidth"],
            avg_rssi
        ])

    print("\nDetected Wireless Networks:\n")
    print(table)


def main():
    pcap_file = input("Enter .pcap filename (e.g., capture.pcap): ").strip()
    if not pcap_file.endswith(".pcap"):
        print("[!] Please input a valid .pcap file")
        return
    analyze_wifi_networks(pcap_file)
 

if __name__ == "__main__":
    main()
