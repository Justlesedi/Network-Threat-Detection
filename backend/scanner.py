import socket
import subprocess
from scapy.all import ARP, Ether, srp, IP, ICMP
from typing import List, Dict, Set
import logging
import ipaddress
import threading

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, network: str = None):
        self.network = network or self._get_local_network()
        self.local_subnet = self._get_subnet_from_network(self.network)
        self.scanning = False
        self.scan_progress = 0

    def _get_local_network(self) -> str:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            return f"{'.'.join(ip.split('.')[:3])}.0/24"
        except Exception as e:
            logger.error(f"Error getting local network: {e}")
            return "192.168.1.0/24"

    def _get_subnet_from_network(self, network: str) -> str:
        try:
            net = ipaddress.ip_network(network, strict=False)
            return str(net.network_address)
        except:
            return ".".join(network.split(".")[:3])

    def _get_device_subnet(self, ip: str) -> str:
        try:
            parts = ip.split(".")
            return ".".join(parts[:3])
        except:
            return None

    def is_foreign_device(self, ip: str) -> bool:
        device_subnet = self._get_device_subnet(ip)
        local_subnet = self._get_subnet_from_network(self.network)
        return device_subnet != local_subnet

    def scan_network(self, callback=None) -> Dict:
        self.scanning = True
        self.scan_progress = 0
        devices = []
        foreign_devices = []

        try:
            logger.info(f"Starting network scan on {self.network}")
            if callback:
                callback({"status": "scanning", "progress": 10})

            arp = ARP(pdst=self.network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            result = srp(packet, timeout=3, verbose=False)[0]
            
            total = len(result)
            for idx, (sent, received) in enumerate(result):
                ip = received.psrc
                mac = received.hwsrc
                hostname = self._get_hostname(ip)
                
                device = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "is_foreign": self.is_foreign_device(ip)
                }
                
                if device["is_foreign"]:
                    foreign_devices.append(device)
                else:
                    devices.append(device)

                progress = int((idx / total) * 80) + 10
                if callback:
                    callback({
                        "status": "scanning",
                        "progress": progress,
                        "current_device": hostname or ip
                    })

            if callback:
                callback({"status": "scanning", "progress": 90})

            logger.info(f"Found {len(devices)} local devices, {len(foreign_devices)} foreign devices")
            
            self.scanning = False
            if callback:
                callback({"status": "complete", "progress": 100})

            return {
                "local_devices": devices,
                "foreign_devices": foreign_devices,
                "total_devices": len(devices) + len(foreign_devices),
                "network": self.network
            }

        except Exception as e:
            logger.error(f"Error scanning network: {e}")
            self.scanning = False
            return {"error": str(e), "local_devices": [], "foreign_devices": []}

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
            