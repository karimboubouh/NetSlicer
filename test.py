#!/usr/bin/env python3
"""
Cross-Platform Network Slicer
Works on both Linux (tc) and macOS (dummynet/pfctl)
"""
import platform
import random
import os
import sys
import subprocess
from scapy.all import *

# =====================
# Configuration
# =====================
INTERFACE = "en0"  # Change to your network interface
SLICE_CONFIG = {
    1: {"bw": "10mbit"},  # TOS 1
    2: {"bw": "5mbit"},  # TOS 2
    3: {"bw": "1mbit"}  # TOS 3
}

# =====================
# Platform Detection
# =====================
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"


# =====================
# Traffic Control Base
# =====================
class TrafficController:
    @staticmethod
    def cleanup():
        pass

    @staticmethod
    def create_slices():
        pass


class LinuxTrafficController(TrafficController):
    @staticmethod
    def cleanup():
        subprocess.run(["tc", "qdisc", "del", "dev", INTERFACE, "root"],
                       stderr=subprocess.DEVNULL)

    @staticmethod
    def create_slices():
        # Create priority queue with 3 bands
        subprocess.run(["tc", "qdisc", "add", "dev", INTERFACE, "root",
                        "handle", "1:", "prio", "bands", "3"])

        for tos, config in SLICE_CONFIG.items():
            slice_id = tos - 1
            subprocess.run([
                "tc", "filter", "add", "dev", INTERFACE,
                "parent", "1:", "protocol", "ip",
                "prio", "1", "u32",
                "match", "ip", "tos", hex(tos), "0xff",
                "action", "skbedit", "priority", str(slice_id)
            ])
            subprocess.run([
                "tc", "qdisc", "add", "dev", INTERFACE,
                "parent", f"1:{slice_id + 1}", "tbf",
                "rate", config["bw"], "burst", "15k", "latency", "50ms"
            ])


class MacTrafficController(TrafficController):
    @staticmethod
    def cleanup():
        subprocess.run(["dnctl", "-q", "flush"], stderr=subprocess.DEVNULL)
        subprocess.run(["pfctl", "-F", "all"], stderr=subprocess.DEVNULL)

    @staticmethod
    def create_slices():
        # Enable packet filter
        subprocess.run(["pfctl", "-e"])

        # Create dummynet pipes
        pipe_config = []
        for tos, config in SLICE_CONFIG.items():
            pipe_id = tos
            subprocess.run([
                "dnctl", "pipe", str(pipe_id), "config",
                "bw", config["bw"]
            ])
            pipe_config.append(
                f"dummynet proto ip from any to any tos {tos} pipe {pipe_id}"
            )

        # Apply PF rules
        subprocess.run(["pfctl", "-a", "network_slicer", "-f", "-"],
                       input="\n".join(pipe_config).encode())


# =====================
# Packet Processing
# =====================
class PacketProcessor:
    @staticmethod
    def classify(packet):
        """Dummy classifier: Random TOS assignment"""
        return random.choice(list(SLICE_CONFIG.keys()))

    @staticmethod
    def modify_packet(packet):
        if IP not in packet:
            return None

        new_tos = PacketProcessor.classify(packet)
        packet[IP].tos = new_tos

        # Force checksum recalculation
        del packet[IP].chksum
        if TCP in packet:
            del packet[TCP].chksum
        elif UDP in packet:
            del packet[UDP].chksum

        return packet


# =====================
# Main Application
# =====================
def setup_network():
    """Initialize network configuration"""
    if IS_LINUX:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        LinuxTrafficController.create_slices()
    elif IS_MACOS:
        subprocess.run(["sysctl", "-w", "net.inet.ip.fw.enable=1"])
        MacTrafficController.create_slices()


def cleanup_network():
    """Clean up network configuration"""
    if IS_LINUX:
        LinuxTrafficController.cleanup()
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"])
    elif IS_MACOS:
        MacTrafficController.cleanup()
        subprocess.run(["sysctl", "-w", "net.inet.ip.fw.enable=0"])


def packet_handler(packet):
    processed = PacketProcessor.modify_packet(packet)
    if processed:
        send(processed, verbose=0)
        print(f"Processed packet with TOS: {processed[IP].tos}")


def main():
    if os.geteuid() != 0:
        print("This script requires root privileges!", file=sys.stderr)
        sys.exit(1)

    try:
        print(f"Starting network slicer on {platform.system()}")
        print("Slice configurations:")
        for tos, config in SLICE_CONFIG.items():
            print(f"  TOS {tos}: {config['bw']}")

        setup_network()
        sniff(iface=INTERFACE, prn=packet_handler, filter="ip", store=0)

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        cleanup_network()
        print("Network cleanup complete")


if __name__ == "__main__":
    # Initialize proper traffic controller
    if IS_LINUX:
        TrafficController = LinuxTrafficController
    elif IS_MACOS:
        TrafficController = MacTrafficController
    else:
        print("Unsupported platform!", file=sys.stderr)
        sys.exit(1)

    main()