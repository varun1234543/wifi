"""Packet sniffer module using Scapy.

Captures network packets visible to the local network interface in managed/promiscuous
mode (passive defensive monitoring). Does NOT use monitor mode or inspect payloads.
"""

import sys
from typing import Callable, Dict, List, Optional
from scapy.all import conf, get_if_list, sniff
from app.capture.extractor import extract_metadata, format_packet_output


def list_interfaces() -> List[Dict[str, str]]:
    """List network interfaces with human-readable information."""
    interfaces = []
    try:
        # On Windows, conf.ifaces contains detailed NetworkInterface objects
        for iface_name in get_if_list():
            iface_obj = conf.ifaces.dev_from_name(iface_name)
            name = getattr(iface_obj, "name", iface_name)
            description = getattr(iface_obj, "description", "")
            ip = getattr(iface_obj, "ip", "No IP")
            mac = getattr(iface_obj, "mac", "No MAC")

            interfaces.append({
                "id": iface_name,
                "name": name,
                "description": description,
                "ip": ip,
                "mac": mac,
            })
    except Exception:
        # Fallback to basic interface list
        for iface_name in get_if_list():
            interfaces.append({
                "id": iface_name,
                "name": iface_name,
                "description": "",
                "ip": "Unknown",
                "mac": "Unknown",
            })
    return interfaces


def display_interfaces() -> None:
    """Print available interfaces to terminal in a neat table."""
    interfaces = list_interfaces()
    print("\n" + "=" * 70)
    print("AVAILABLE NETWORK INTERFACES")
    print("=" * 70)
    for idx, iface in enumerate(interfaces, start=1):
        print(f"[{idx}] {iface['name']}")
        if iface['description']:
            print(f"    Description : {iface['description']}")
        print(f"    IP Address  : {iface['ip']}")
        print(f"    Interface ID: {iface['id']}")
        print("-" * 70)


def resolve_interface(target: Optional[str]) -> Optional[str]:
    """Validate and resolve an interface name or number to a valid Scapy interface."""
    if not target:
        return None

    interfaces = list_interfaces()

    # Check if target is a 1-based number index
    if target.isdigit():
        idx = int(target) - 1
        if 0 <= idx < len(interfaces):
            return interfaces[idx]["id"]

    # Match by ID, name, or description
    target_lower = target.lower()
    for iface in interfaces:
        if (
            target_lower == iface["id"].lower()
            or target_lower == iface["name"].lower()
            or target_lower in iface["description"].lower()
        ):
            return iface["id"]

    return target


def start_sniffing(
    interface: Optional[str] = None,
    packet_callback: Optional[Callable[[dict], None]] = None,
    filter_expr: Optional[str] = None,
    packet_count: int = 0,
) -> None:
    """Start passive packet sniffing on the specified interface.

    :param interface: Interface name, ID, or index (or None for default)
    :param packet_callback: Optional custom callback receiving the extracted dict
    :param filter_expr: Optional BPF filter expression (e.g. 'ip or arp')
    :param packet_count: Number of packets to capture (0 = infinite until Ctrl+C)
    """
    resolved_iface = resolve_interface(interface)
    total_captured = 0

    print(f"\n[*] Initializing packet sniffer...")
    if resolved_iface:
        print(f"[*] Target Interface: {resolved_iface}")
    else:
        print(f"[*] Target Interface: Default system interface ({conf.iface})")

    print("[*] Capture Mode: Passive Local Monitoring (No payload storage)")
    print("[*] Press Ctrl+C at any time to stop capturing.\n")

    def packet_handler(raw_packet):
        nonlocal total_captured
        metadata = extract_metadata(raw_packet)
        if metadata:
            total_captured += 1
            if packet_callback:
                packet_callback(metadata)
            else:
                # Default terminal output
                print(format_packet_output(metadata))

    try:
        sniff(
            iface=resolved_iface,
            prn=packet_handler,
            store=False,  # CRITICAL: do not accumulate packets in RAM
            filter=filter_expr or "ip or arp",
            count=packet_count,
        )
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user (Ctrl+C).")
    except Exception as exc:
        print(f"\n[!] Error starting capture: {exc}", file=sys.stderr)
        print("[!] Tip: Ensure Npcap is installed on Windows and you have permissions.", file=sys.stderr)
        print("[!] Available interfaces are:", file=sys.stderr)
        display_interfaces()
    finally:
        print(f"[*] Total packets processed in this session: {total_captured}")
