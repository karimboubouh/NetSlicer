from scapy.packet import Packet
from termcolor import cprint

from core.network_slice import NetworkSlice
from core.slice_layer import SliceLayer


class PacketClassifier:
    def __init__(self, slices, args):
        self.args = args
        self.slices: NetworkSlice = slices

    def classify_packet(self, packet: Packet):
        """
        Process the packet by reading the Slice tag SID and direct it to the correct network slice
        """
        if packet.haslayer(SliceLayer):
            sid = packet[SliceLayer].SID
            packet = self.remove_slice_layer(packet)
            cprint(f">> Packet send to Slice Number {sid}", "black", attrs=["bold"])
            self.slicer.handle_packet(packet, sid)

    def remove_slice_layer(self, packet: Packet):
        parent = packet
        while parent.payload:
            if parent.payload.__class__.__name__ == "SliceLayer":
                parent.payload = parent.payload.payload
                break
            parent = parent.payload
        return packet
