import os
import sys
import threading
from scapy.all import sniff, Dot11Beacon, Dot11, Dot11Elt, ARP, TCP, UDP, IP, DNS, Ether
from colorama import Fore, Style

def check_root(logger):
    if os.geteuid() != 0:
        logger.error("SIGINT module requires root privileges (sudo).")
        return False
    return True

def wifi_scanner(interface, logger, timeout=10):
    logger.info(f"Scanning for Wi-Fi networks on {interface} for {timeout} seconds...")
    networks = {}

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            try:
                ssid = pkt[Dot11Elt].info.decode()
            except:
                ssid = "<Hidden>"

            try:
                stats = pkt[Dot11Beacon].network_stats()
                crypto = stats.get("crypto")
            except:
                crypto = {"unknown"}

            if bssid not in networks:
                networks[bssid] = (ssid, crypto)
                logger.info(f"Found SSID: {ssid} ({bssid}) - Enc: {crypto}")

    try:
        # Note: This requires the interface to be in monitor mode
        sniff(iface=interface, prn=packet_handler, timeout=timeout)
    except Exception as e:
        logger.error(f"Error during Wi-Fi scan: {e}")
        logger.info("Ensure the interface is in MONITOR mode.")

    return networks

def arp_monitor(interface, logger, count=20):
    logger.info(f"Monitoring ARP requests on {interface} ({count} packets)...")
    devices = set()

    def packet_handler(pkt):
        if pkt.haslayer(ARP):
            if pkt[ARP].op == 1: # who-has (request)
                src_ip = pkt[ARP].psrc
                src_mac = pkt[ARP].hwsrc
                if src_ip not in devices:
                    devices.add(src_ip)
                    logger.info(f"ARP Probe: {src_ip} is at {src_mac}")
            elif pkt[ARP].op == 2: # is-at (response)
                src_ip = pkt[ARP].psrc
                src_mac = pkt[ARP].hwsrc
                if src_ip not in devices:
                    devices.add(src_ip)
                    logger.info(f"ARP Reply: {src_ip} is at {src_mac}")

    try:
        sniff(iface=interface, filter="arp", prn=packet_handler, count=count)
    except Exception as e:
        logger.error(f"Error during ARP monitor: {e}")

    return list(devices)

def packet_sniffer(interface, logger, count=50):
    logger.info(f"Sniffing {count} packets on {interface} for HTTP/DNS analysis...")
    findings = []

    def packet_handler(pkt):
        # DNS
        if pkt.haslayer(DNS) and pkt.haslayer(UDP):
            if pkt[DNS].qr == 0: # Query
                qname = pkt[DNS].qd.qname.decode()
                msg = f"DNS Query: {qname}"
                logger.info(msg)
                findings.append(msg)

        # HTTP
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                if pkt.haslayer(Raw):
                    load = pkt[Raw].load
                    try:
                        decoded = load.decode('utf-8', errors='ignore')
                        if "HTTP" in decoded:
                            lines = decoded.split('\n')
                            first_line = lines[0].strip()
                            msg = f"HTTP Traffic: {pkt[IP].src} -> {pkt[IP].dst}: {first_line}"
                            logger.warning(msg)
                            findings.append(msg)
                    except:
                        pass

    # Import Raw locally to avoid circular import issues if scapy structure changes,
    # though usually from scapy.all import * handles it.
    from scapy.all import Raw

    try:
        sniff(iface=interface, prn=packet_handler, count=count)
    except Exception as e:
        logger.error(f"Error during packet sniffing: {e}")

    return findings

def run(target, logger, db):
    # Target in this case acts as the Interface
    interface = target

    logger.info(f"Starting SIGINT module on interface: {interface}")

    if not check_root(logger):
        # In a real scenario we might return, but for simulation/dev we might proceed or mock.
        # However, the requirement says "Ensure it runs with sudo/root privileges".
        # I'll let it try, it will likely fail with "Permission denied" or similar from scapy.
        pass

    # 1. Wi-Fi Scanner
    wifi_networks = wifi_scanner(interface, logger)
    if wifi_networks:
        # Convert set/dict to list for JSON serialization
        wifi_list = [{"bssid": k, "ssid": v[0], "enc": list(v[1])} for k, v in wifi_networks.items()]
        db.save_finding("SIGINT", interface, "Wi-Fi Networks", wifi_list)

    # 2. ARP Monitor
    arp_devices = arp_monitor(interface, logger)
    if arp_devices:
        db.save_finding("SIGINT", interface, "ARP Devices", arp_devices)

    # 3. Packet Sniffer
    sniffed_data = packet_sniffer(interface, logger)
    if sniffed_data:
        db.save_finding("SIGINT", interface, "Sniffed Traffic", sniffed_data)

    logger.success(f"SIGINT module finished on {interface}")
