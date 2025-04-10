import platform
import random
import time
import traceback

from prettytable import PrettyTable
from scapy.all import sniff
from scapy.fields import ShortField
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet
# from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from termcolor import colored

from core.parser import Args
from core.slice_layer import SliceLayer
from utils.helpers import log
from utils.metrics import PacketMetrics


class Sniffer:
    def __init__(self, args, scanner, classifier):
        self.args: Args = args
        self.interface = scanner.interface
        self.filters = scanner.filters
        self.classifier = classifier
        self.platform = platform.system()
        self.socket = None
        self.metrics = PacketMetrics()

    def start_sniffing(self):
        log('cyan', "Sniffing starts in 1 seconds on Linux... Press Ctrl+C to stop.")
        time.sleep(1)
        sniff(prn=self.process_packet, store=0, iface=self.interface, filter=self.filters)

    def process_packet(self, packet):
        try:
            self.metrics.update(packet_size=len(packet))
            packet = self.add_slice_info(packet)
            if self.args.display_metrics:
                self.display_metrics()
            if self.args.display_packets:
                self.display_packet(packet)
            if self.classifier:
                self.classifier.classify_packet(packet)
        except KeyboardInterrupt:
            log("cyan", "Sniffing interrupted by Ctrl+C")
        except Exception as e:
            print(f"Warning: {e}")
            traceback.print_exc()

    @classmethod
    def add_slice_info(cls, packet):
        """Change the value of TOS of the IP packet"""
        # packet_with_slice_id = packet / SliceLayer(SID=slice_id)
        if IP not in packet:
            return None
        tos = random.randint(1, 4)
        packet[IP].tos = tos
        del packet[IP].chksum
        if TCP in packet:
            del packet[TCP].chksum
        elif UDP in packet:
            del packet[UDP].chksum

        return packet

    def display_packet(self, packet):
        """
        Displays the packet layers in a PrettyTable.
        Only layers whose protocol name is mentioned in self.filters are displayed.
        If self.filters is empty, all layers are shown.
        """
        if self.filters and self.filters.strip():
            requested = {token.strip().lower() for token in self.filters.split("or")}
            requested.add('ether')
            requested.add('slice')
        else:
            requested = None  # means show all layers

        # Helper function to map a Scapy layer to OSI layer and extract details.
        def get_layer_info(layer):
            layer_name = layer.__class__.__name__
            # Determine OSI layer and key details
            if layer_name in ["Ether", "Ethernet"]:
                details = f"src: {layer.src}, dst: {layer.dst}"
            elif layer_name.startswith("IP"):
                details = f"src: {layer.src}, dst: {layer.dst}"
            elif layer_name in ["TCP", "UDP"]:
                details = f"sport: {layer.sport}, dport: {layer.dport}"
            elif layer_name == "ICMP":
                details = f"type: {layer.type}"
            elif layer_name == "SliceLayer":
                details = f"SID: {layer.SID}"
            else:
                details = layer.summary()
            return layer_name, details

        # Create the PrettyTable.
        table = PrettyTable()
        table.field_names = [
            colored("Protocol", "cyan", attrs=["bold"]),
            colored("Source", "cyan", attrs=["bold"]),
            colored("Destination", "cyan", attrs=["bold"]),
            colored("Header Size (B)", "cyan", attrs=["bold"]),
            colored("Payload Size (B)", "cyan", attrs=["bold"]),
        ]
        table.align["Details"] = "l"

        # Traverse the packet layers.
        current_layer = packet
        while current_layer and current_layer != b"":
            scapy_layer, details = get_layer_info(current_layer)
            src = ""
            dst = ""
            if scapy_layer in ["Ether", "Ethernet"]:
                src = current_layer.src
                dst = current_layer.dst
            elif scapy_layer.startswith("IP"):
                src = current_layer.src
                dst = current_layer.dst
            elif scapy_layer in ["TCP", "UDP"]:
                src = current_layer.sport
                dst = current_layer.dport
            elif scapy_layer in ["TCP", "UDP"]:
                src = current_layer.sport
                dst = current_layer.dport
            elif scapy_layer in ["SliceLayer"]:
                src = "--"
                dst = "--"
            # Determine header size and payload size.
            header_size = len(current_layer)
            payload_size = len(current_layer.payload) if current_layer.payload and current_layer.payload != b"" else 0
            if scapy_layer == "SliceLayer":
                payload_size = f"SID={current_layer.SID}"

            # Decide whether to add this layer based on self.filters.
            # If 'requested' is not None, add the layer only if one of the requested tokens
            # is a substring of the scapy layer name (case-insensitive).
            if requested is None or any(req in scapy_layer.lower() for req in requested):
                # Color the protocol text: green for TCP/UDP, yellow otherwise.
                color = "green" if scapy_layer in ["TCP", "UDP"] else ("blue" if scapy_layer == "SliceLayer" else "yellow")
                table.add_row([
                    colored(scapy_layer, color),
                    src,
                    dst,
                    header_size,
                    payload_size,
                ])
            current_layer = current_layer.payload
        print(table)

    def display_metrics(self):
        pps = self.metrics.pps()
        throughput = self.metrics.throughput()
        count = self.metrics.packet_count
        data = self.metrics.total_data / 1024
        unit = "KB"
        if data > 1024:
            unit = "MB"
            data /= 1024
        print(
            colored(
                f"Packets/s: {pps} | Throughput: {throughput} KB/s | Total Packets: {count} | "
                f"Total data: {round(data, 2)} {unit}",
                "magenta",
                attrs=["bold"],
            )
        )

    def stop(self):
        if self.socket:
            self.socket.close()
