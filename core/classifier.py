from typing import Dict

from scapy.packet import Packet
from termcolor import cprint

from core.network_slice import NetworkSlice


class PacketClassifier:
    def __init__(self, slices, args):
        self.args = args
        self.slices: Dict[str: NetworkSlice] = slices

    def classify_packet(self, packet: Packet):
        """
        Route a packet to the appropriate slice based on DSCP/TOS value
        """
        if not packet.haslayer("IP"):
            print("Warning: Non-IP packet cannot be sliced")
            return

        dscp = packet["IP"].tos
        if dscp == 0x2E:
            ns: NetworkSlice = self.slices["urllc"]
            ns.process_packet(packet)
            cprint(f">> Packet {packet} send to URLLC Slice", "blue", attrs=["bold"])
        elif dscp == 0x0A:
            ns: NetworkSlice = self.slices["urllc"]
            ns.process_packet(packet)
            cprint(f">> Packet {packet} send to URLLC Slice", "green", attrs=["bold"])
        elif dscp == 0x00:
            ns: NetworkSlice = self.slices["urllc"]
            ns.process_packet(packet)
            cprint(f">> Packet {packet} send to URLLC Slice", "black", attrs=["bold"])
        else:
            cprint(f">> Packet {packet} is not classified!", "grey", attrs=["bold"])
