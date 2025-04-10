import subprocess

from scapy.packet import Packet
from termcolor import cprint


class NetworkSlice:
    def __init__(self, slice_id, tos, policy, args):
        self.slice_id = slice_id
        self.tos = tos
        self.args = args
        self.interface = args.interface
        self.current_packet: Packet | None = None
        self.configure(policy)

        self.stats = {
            'urllc': 0,
            'eMBB': 0,
            'mMTC': 0,
            'ns3': 0,
            'ns4': 0,
        }

    def configure(self, policy):
        self.configure_slice(
            self.args.interface,
            self.slice_id,
            self.tos,
            policy.bandwidth
        )

    def cleanup(self):
        pass

    def handle_packet(self, packet: Packet, sid: int):
        if sid == 0:
            self.URLLC_slice(packet)
        elif sid == 1:
            self.eMBB_slice(packet)
        elif sid == 2:
            self.mMTC_slice(packet)
        elif sid == 3:
            self.ns4_slice(packet)
        elif sid == 4:
            self.ns5_slice(packet)
        else:
            cprint("[!] Unknown slice id %d" % sid, color='red')

    def URLLC_slice(self, packet):

        self.stats['urllc'] += 1
        cprint(">> Packet arrived to the URLLC NS", "blue", attrs=['bold'])

    def eMBB_slice(self, packet):
        self.stats['eMBB'] += 1
        cprint(">> Packet arrived to the eMBB NS", "blue", attrs=['bold'])

    def mMTC_slice(self, packet):
        self.stats['mMTC'] += 1
        cprint(">> Packet arrived to the mMTC NS", "blue", attrs=['bold'])

    def ns4_slice(self, packet):
        self.stats['ns3'] += 1
        cprint(">> Packet arrived to the NS 3", "blue", attrs=['bold'])

    def ns5_slice(self, packet):
        self.stats['ns4'] += 1
        cprint(">> Packet arrived to the NS 4", "blue", attrs=['bold'])

    def configure_linux(self, policy):
        """Configure TC queuing discipline for a network slice"""
        # Delete existing qdisc if any
        subprocess.run(
            ["tc", "qdisc", "del", "dev", self.interface, "root"],
            stderr=subprocess.DEVNULL
        )

        # Create priority queue with 3 bands
        subprocess.run([
            "tc", "qdisc", "add", "dev", self.interface,
            "root", "handle", "1:", "prio", "bands", "3"
        ])

        # Add filter for TOS value
        subprocess.run([
            "tc", "filter", "add", "dev", self.interface,
            "parent", "1:", "protocol", "ip",
            "prio", "1", "u32",
            "match", "ip", "tos", hex(self.tos), "0xff",
            "action", "skbedit", "priority", str(self.slice_id)
        ])

        # Add bandwidth limiting
        subprocess.run([
            "tc", "qdisc", "add", "dev", self.interface,
            "parent", f"1:{self.slice_id}", "tbf",
            "rate", policy.bandwidth,
            "burst", "15k", "latency", "50ms"
        ])
