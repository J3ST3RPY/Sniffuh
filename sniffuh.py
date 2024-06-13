import os
import signal
import sys
import time
from colorama import Fore, Style
from scapy.all import ARP, ICMP, IP, Ether, TCP, UDP, sniff, srp, rdpcap, wrpcap

devices = {}
manuf_file = "manuf.txt"
packets = []
protocols = {"ARP": 0, "ICMP": 0, "IP": 0, "TCP": 0, "UDP": 0}
timestamp = None


def discover_devices(ip_range):
    manufacturer_data = load_manufacturer_data()
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    packet = ether / arp_request
    result = srp(packet, timeout=3, verbose=False)[0]
    devices = []
    for sent, received in result:
        mac_address = received.hwsrc
        ip_address = received.psrc
        manufacturer = manufacturer_data.get(mac_address[:8].upper(), "Unknown")
        devices.append({'ip': ip_address, 'mac': mac_address, 'manufacturer': manufacturer})
    return devices


def get_manufacturer(mac):
    if not hasattr(get_manufacturer, 'manuf_data'):
        get_manufacturer.manuf_data = load_manuf_file()
    oui = mac[:8].replace(':', '').upper()
    manufacturer = get_manufacturer.manuf_data.get(oui, "Unknown")
    return manufacturer


def load_manuf_file():
    manuf_data = {}
    with open(manuf_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line and not line.startswith('#'):
                parts = line.split('\t')
                if len(parts) >= 2:
                    mac_prefix = parts[0].strip()
                    manufacturer = parts[1].strip()
                    manuf_data[mac_prefix] = manufacturer
    return manuf_data


def load_manufacturer_data():
    manufacturer_data = {}
    with open("manuf.txt", "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                mac_prefix, manufacturer = line.split("\t", 1)
                manufacturer_data[mac_prefix.strip()] = manufacturer.strip()
    return manufacturer_data


def main():
    print(Fore.RED + """
        
  ██████  ███▄    █  ██▓  █████▒ █████▒█    ██  ██░ ██ 
▒██    ▒  ██ ▀█   █ ▓██▒▓██   ▒▓██   ▒ ██  ▓██▒▓██░ ██▒
░ ▓██▄   ▓██  ▀█ ██▒▒██▒▒████ ░▒████ ░▓██  ▒██░▒██▀▀██░
  ▒   ██▒▓██▒  ▐▌██▒░██░░▓█▒  ░░▓█▒  ░▓▓█  ░██░░▓█ ░██ 
▒██████▒▒▒██░   ▓██░░██░░▒█░   ░▒█░   ▒▒█████▓ ░▓█▒░██▓
▒ ▒▓▒ ▒ ░░ ▒░   ▒ ▒ ░▓   ▒ ░    ▒ ░   ░▒▓▒ ▒ ▒  ▒ ░░▒░▒
░ ░▒  ░ ░░ ░░   ░ ▒░ ▒ ░ ░      ░     ░░▒░ ░ ░  ▒ ░▒░ ░
░  ░  ░     ░   ░ ░  ▒ ░ ░ ░    ░ ░    ░░░ ░ ░  ░  ░░ ░
      ░           ░  ░                   ░      ░  ░  
Basic Toolkit For Network Analyizing                                                       
""")
    print("Type 'help' to display available commands.")
    while True:
        command = input("\033[92m>>>\033[0m ").strip().lower()
        if command == "start":
            start_sniffing()
        elif command == "stats":
            print_statistics()
        elif command == "devices":
            print_devices()
        elif command == "ls":
            list_directory()
        elif command.startswith("read "):
            filename = command[5:]
            read_pcap(filename)
        elif command in ["quit", "exit", "e"]:
            print("\033[91mExiting...\033[0m")
            sys.exit(0)
        elif command == "cls" or command == "clear":
            os.system('clear' if os.name == 'posix' else 'cls')
        elif command == "help":
            print("\033[1m\033[95m======= Available Commands =======\033[0m")
            print("start    - Start sniffing packets")
            print("stats    - Display packet statistics")
            print("devices  - Display devices on the network")
            print("ls       - List files in the current directory")
            print("read <filename> - Read packets from a pcap file")
            print("exit (e) - Exit the program")
            print("cls (clear) - Clear the screen")
        else:
            print(Fore.RED + "Invalid command. Type 'help' to see available commands." + Style.RESET_ALL)


def packet_callback(packet):
    global timestamp
    packets.append(packet)
    update_statistics(packet)
    update_devices(packet)
    print_packet_info(packet)


def print_devices():
    ip_range = "192.168.1.1/24"
    devices = discover_devices(ip_range)
    print("\n" + Fore.RED + Style.BRIGHT + "======= Devices on Network =======" + Style.RESET_ALL)
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Manufacturer: {device['manufacturer']}")


def print_packet_info(packet):
    global timestamp
    protocol_info = []
    if ARP in packet:
        protocol_info.append(Fore.RED + "ARP Packet" + Style.RESET_ALL)
        src_mac = packet[ARP].hwsrc
        src_ip = packet[ARP].psrc
        dest_ip = packet[ARP].pdst
        devices[src_mac] = src_ip
    elif IP in packet:
        protocol_info.append(Fore.RED + "IP Packet" + Style.RESET_ALL)
        if TCP in packet:
            protocol_info.append(Fore.CYAN + "TCP Packet" + Style.RESET_ALL)
        elif UDP in packet:
            protocol_info.append(Fore.YELLOW + "UDP Packet" + Style.RESET_ALL)
        elif ICMP in packet:
            protocol_info.append(Fore.RED + "ICMP Packet" + Style.RESET_ALL)
    protocol_info_str = ' '.join(protocol_info)
    packet_summary = packet.summary()
    if len(packet_summary) > 100:
        packet_summary = packet_summary[:100] + "..."
    print(f"{timestamp} {protocol_info_str} {packet_summary}")


def print_statistics():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(Fore.RED + Style.BRIGHT + "======= Packet Sniffer Statistics =======" + Style.RESET_ALL)
    total_packets = sum(protocols.values())
    print(f"Total Packets: {total_packets}")
    print(f"ARP Packets: {protocols['ARP']}")
    print(f"IP Packets: {protocols['IP']}")
    print(f"TCP Packets: {protocols['TCP']}")
    print(f"UDP Packets: {protocols['UDP']}")
    print(f"ICMP Packets: {protocols['ICMP']}")


def read_pcap(filename):
    global packets
    packets = rdpcap(filename)
    print(f"Read {len(packets)} packets from {filename}")
    print("\n" + Fore.RED + Style.BRIGHT + "======= Devices in the pcap file =======" + Style.RESET_ALL)
    devices_in_pcap = {}
    for packet in packets:
        if ARP in packet:
            src_mac = packet[ARP].hwsrc
            src_ip = packet[ARP].psrc
            devices_in_pcap[src_mac] = src_ip
        elif Ether in packet and IP in packet:
            src_mac = packet[Ether].src
            src_ip = packet[IP].src
            devices_in_pcap[src_mac] = src_ip
    for mac, ip in devices_in_pcap.items():
        manufacturer = get_manufacturer(mac)
        oui = mac[:8].replace(':', '').upper()
        oui_with_colon = ':'.join([oui[i:i + 2] for i in range(0, len(oui), 2)])  # Add colons back
        matched_manufacturer = "Unknown"
        with open(manuf_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith(oui_with_colon):
                    matched_manufacturer = line.strip().split('\t', 1)[1]  # Extract only the manufacturer
                    break
        print(f"OUI: {oui}, MAC: {mac}, IP: {ip}, Manufacturer: {matched_manufacturer}")


def save_packets():
    global timestamp
    filename = f"captured_{timestamp}.pcap"
    wrpcap(filename, packets)
    print(f"Packets saved to {filename}.")


def signal_handler(sig, frame):
    print("\nReturning to main menu.")
    save_option = input("Do you want to save the captured packets? (y/n): ").strip().lower()
    if save_option == 'y':
        save_packets()
    main()


def start_sniffing():
    global timestamp
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    print(Fore.RED + Style.BRIGHT + "Sniffing started..." + Style.RESET_ALL)
    print("Press Ctrl+C to return to the main menu.")

    try:
        sniff(prn=packet_callback)
    except KeyboardInterrupt:
        print("\nReturning to main menu.")
        save_option = input("Do you want to save the captured packets? (y/n): ").strip().lower()
        if save_option == 'y':
            save_packets()
        main()


def list_directory():
    print("\n" + Fore.RED + Style.BRIGHT + "======= Files in Current Directory =======" + Style.RESET_ALL)
    files = os.listdir()
    for file in files:
        print(file)


def update_devices(packet):
    if ARP in packet:
        src_mac = packet[ARP].hwsrc
        src_ip = packet[ARP].psrc
        devices[src_mac] = src_ip


def update_statistics(packet):
    if ARP in packet:
        protocols["ARP"] += 1
    elif IP in packet:
        protocols["IP"] += 1
        if TCP in packet:
            protocols["TCP"] += 1
        elif UDP in packet:
            protocols["UDP"] += 1
        elif ICMP in packet:
            protocols["ICMP"] += 1


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()
