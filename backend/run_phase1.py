"""Phase 1 Runner Script: Packet Capture & Terminal Output.

Usage:
    # 1. List available network interfaces
    python run_phase1.py --list

    # 2. Run capture on default interface
    python run_phase1.py

    # 3. Run capture on a specific interface by index or name
    python run_phase1.py --iface 1
    python run_phase1.py --iface "Wi-Fi"

    # 4. Capture a fixed number of packets for quick verification
    python run_phase1.py --count 10
"""

import argparse
import os
import sys

# Ensure backend directory is in sys.path
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.capture.sniffer import display_interfaces, start_sniffing


def main():
    parser = argparse.ArgumentParser(
        description="Phase 1: Wi-Fi Traffic Monitoring & Metadata Extraction (Defensive Only)"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all network interfaces available on this system and exit",
    )
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Interface number (e.g. 1, 2) or name (e.g. 'Wi-Fi') to monitor",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture before stopping (0 = continuous)",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default="ip or arp",
        help="BPF filter string (default: 'ip or arp')",
    )

    args = parser.parse_args()

    if args.list:
        display_interfaces()
        return

    start_sniffing(
        interface=args.iface,
        filter_expr=args.filter,
        packet_count=args.count,
    )


if __name__ == "__main__":
    main()
