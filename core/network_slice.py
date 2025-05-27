import subprocess

from scapy.packet import Packet
from termcolor import cprint

from scapy.all import Packet, sendp
import subprocess
from typing import Optional, Dict, Any

from config import HANDLE
from core.policy import Policy
from utils import log


class NetworkSlice:
    def __init__(self, name: str, dscp: int, interface, policy: Policy, packet_handler=None, packet_handler_args=None,
                 args=None):
        self.name = name
        self.dscp = dscp
        self.policy = policy
        self.handler = packet_handler
        self.handler_args = {} if packet_handler_args is None else packet_handler_args
        self.args = args
        self.interface = interface
        self.packet_counter = 0
        self.byte_counter = 0
        self.current_packet: Optional[Packet] = None

        # TC-specific attributes
        self.tc_handle = f"1:"  # Default root qdisc handle
        self.tc_classid = f"{self.tc_handle}{policy.classid}"
        self.tc_qdisc = f"1{self.policy.classid}:"
        self.tc_flowid = f"{self.policy.classid}:1"

    def configure(self) -> None:
        """Configure TC queuing discipline for this slice"""

        log('yellow', f"Configuring slice {self.name}...")
        # Create root HTB qdisc if not exists
        cmd = f"tc qdisc show dev {self.interface} | grep htb"
        if subprocess.call(cmd, shell=True) != 0:
            subprocess.run([
                "tc", "qdisc", "add", "dev", self.interface,
                "root", "handle", self.tc_handle, "htb"
            ], check=True)

        # Create class for this slice
        subprocess.run([
            "tc", "class", "add", "dev", self.interface,
            "parent", self.tc_handle, "classid", self.tc_classid,
            "htb", "rate", self.policy.rate, "ceil", self.policy.ceil, "burst", self.policy.burst
        ], check=True)

        # Add leaf qdisc
        subprocess.run([
            "tc", "qdisc", "add", "dev", self.interface,
            "parent", self.tc_classid, "handle", self.tc_qdisc,
            "pfifo", "limit", str(self.policy.qsize)
        ], check=True)

        # Add DSCP filter
        subprocess.run([
            "tc", "filter", "add", "dev", self.interface,
            "protocol", "ip", "parent", "1:",
            "prio", "1", "u32",
            "match", "ip", "tos", hex(self.dscp), "0xff",
            "flowid", self.tc_classid
        ], check=True)

    def process_packet(self, packet: Packet) -> None:
        """
        Process and forward a packet through this slice
        Args:
            packet: Scapy Packet object to process
        """
        self.current_packet = packet
        self.packet_counter += 1
        self.byte_counter += len(packet)

        # Apply slice-specific processing
        if self.handler is not None:
            self.handler(self.current_packet, **self.handler_args)

        # Mark packet with slice's DSCP
        if packet.haslayer("IP"):
            packet["IP"].tos = self.dscp

        # Forward packet
        sendp(packet, iface=self.interface, verbose=False)
        self.current_packet = None

    def get_stats(self) -> Dict[str, int]:
        """Return current slice statistics"""
        return {
            "packets": self.packet_counter,
            "bytes": self.byte_counter,
            "dscp": self.dscp
        }

    def __del__(self):
        """Clean up TC rules when slice is destroyed"""
        if hasattr(self, "qdisc_handle"):
            subprocess.run([
                "tc", "qdisc", "del", "dev", self.interface,
                "handle", self.tc_qdisc.split(":")[0]
            ], check=False)


class NetworkSlice2:
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
