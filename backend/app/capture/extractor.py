"""Packet metadata extraction module.

Parses network packets and extracts structured metadata (IPs, ports, protocol,
size, timestamp) while completely ignoring packet payloads to protect privacy.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP


def extract_metadata(packet: Any) -> Optional[Dict[str, Any]]:
    """Extract metadata from a Scapy packet without reading payload content.

    Returns a clean dictionary or None if the packet is unhandled.
    """
    try:
        # Timestamp formatted to ISO 8601 UTC
        packet_time = getattr(packet, "time", None)
        if packet_time is not None:
            ts = datetime.fromtimestamp(float(packet_time), tz=timezone.utc).isoformat()
        else:
            ts = datetime.now(timezone.utc).isoformat()

        packet_size = len(packet)

        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        protocol: Optional[str] = None

        # 1. Check for IPv4 Layer
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if packet.haslayer(TCP):
                protocol = "TCP"
                tcp_layer = packet[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
            elif packet.haslayer(UDP):
                protocol = "UDP"
                udp_layer = packet[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = f"IP_PROTO_{ip_layer.proto}"

        # 2. Check for ARP Layer
        elif packet.haslayer(ARP):
            arp_layer = packet[ARP]
            protocol = "ARP"
            src_ip = arp_layer.psrc
            dst_ip = arp_layer.pdst

        else:
            # Non-IP / Non-ARP frame (e.g. raw layer 2 protocol)
            return None

        return {
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_size": packet_size,
        }

    except Exception:
        # Gracefully handle malformed or unexpected packets
        return None


def format_packet_output(extracted: Dict[str, Any]) -> str:
    """Format extracted packet metadata into a clean, human-readable terminal line.

    Examples:
    [18:42:31] TCP 192.168.1.10:52144 -> 142.250.190.46:443 | 1420 bytes
    [18:42:32] ICMP 192.168.1.10 -> 8.8.8.8 | 74 bytes
    [18:42:33] ARP 192.168.1.10 -> 192.168.1.1 | 42 bytes
    """
    try:
        # Extract time part HH:MM:SS
        iso_str = extracted.get("timestamp", "")
        if "T" in iso_str:
            time_part = iso_str.split("T")[1].split(".")[0]
        else:
            time_part = iso_str[:8]
    except Exception:
        time_part = "--:--:--"

    protocol = extracted.get("protocol", "UNKNOWN")
    src_ip = extracted.get("src_ip", "unknown")
    dst_ip = extracted.get("dst_ip", "unknown")
    src_port = extracted.get("src_port")
    dst_port = extracted.get("dst_port")
    size = extracted.get("packet_size", 0)

    # Format endpoints based on whether ports are present
    if src_port is not None and dst_port is not None:
        src_endpoint = f"{src_ip}:{src_port}"
        dst_endpoint = f"{dst_ip}:{dst_port}"
    else:
        src_endpoint = f"{src_ip}"
        dst_endpoint = f"{dst_ip}"

    return f"[{time_part}] {protocol:<5} {src_endpoint} -> {dst_endpoint} | {size} bytes"
