import socket
import subprocess
from scapy.all import ARP, Ether, srp
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, network: str = None):
        self.network = network or self._get_local_network()

    def _get_local_network(self) -> str:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            return f"{'.'.join(ip.split('.')[:3])}.0/24"
        except Exception as e:
            logger.error(f"Error getting local network: {e}")
            return "192.168.1.0/24"

    def scan_network(self) -> List[Dict]:
        devices = []
        try:
            arp = ARP(pdst=self.network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            result = srp(packet, timeout=2, verbose=False)[0]

            for sent, received in result:
                device = {
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "hostname": self._get_hostname(received.psrc)
                }
                devices.append(device)

            logger.info(f"Found {len(devices)} devices on the network.")
            return devices

        except Exception as e:
            logger.error(f"Error scanning network: {e}")
            return []

    def _get_hostname(self, ip: str) -> str:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"

    def get_gateway(self) -> Dict:
        try:
            result = subprocess.run(["ip", "route", "show"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "default" in line:
                    parts = line.split()
                    gateway_ip = parts[2]
                    gateway_mac = self._get_mac_from_ip(gateway_ip)
                    return {"ip": gateway_ip, "mac": gateway_mac}
        except Exception as e:
            logger.error(f"Error getting gateway: {e}")
        return {"ip": None, "mac": None}

    def _get_mac_from_ip(self, ip: str) -> str:
        try:
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            result = srp(packet, timeout=2, verbose=False)[0]
            if result:
                return result[0][1].hwsrc
        except:
            pass
        return None 

            