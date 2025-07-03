import threading

import torch
from scapy.packet import Packet
from scapy.packet import Packet
from termcolor import cprint
from termcolor import cprint
from typing import Dict
from typing import Dict, List

from core.network_slice import NetworkSlice
from core.network_slice import NetworkSlice
from utils import log


def gpu_frontend(func):
    """
    Decorator that turns classify_packet into GPU‐batching.
    It buffers incoming packets in self._buffer and, once either
      • len(self._buffer) == self.batch_size, or
      • self.time_limit seconds have elapsed since the first packet in the current batch,
    it will flush the buffer by calling self._flush_buffer(), which invokes the original
    per‐packet logic (_classify_single) on each packet in GPU.
    """

    def wrapper(self, packet: Packet):
        with self._lock:
            self._buffer.append(packet)
            if len(self._buffer) == 1 and self.time_limit > 0:
                self._timer = threading.Timer(self.time_limit, self._flush_buffer)
                self._timer.start()

            # 3) If we've reached batch_size, cancel any pending timer and flush immediately:
            if len(self._buffer) >= self.batch_size:
                if self._timer:
                    self._timer.cancel()
                    self._timer = None
                # Flush right away
                self._flush_buffer()

    return wrapper


class PacketClassifier:
    def __init__(self, slices: Dict[str, NetworkSlice], args, batch_size: int = 1, time_limit: float = 0.0):
        """
        :param batch_size: how many packets to buffer before forcing a GPU flush
                           (default: 1 → no buffering; packets are processed immediately)
        :param time_limit: if >0, the maximum seconds to wait after the first packet
                           in a batch before forcing a GPU flush. (default: 0 → ignore)
        """
        self.args = args
        self.slices: Dict[str, NetworkSlice] = slices

        # GPU‐batching parameters
        self.batch_size = batch_size
        self.time_limit = time_limit

        # Internal buffering state:
        self._buffer: List[Packet] = []
        self._lock = threading.Lock()
        self._timer: threading.Timer = None
        log('blue', f"Packet Classifier started ...")

    @gpu_frontend
    def classify_packet(self, packet: Packet):
        print(f"Classifying packet {packet}")
        pass

    def _flush_buffer(self):
        with self._lock:
            packets_to_process = self._buffer.copy()
            print(f"packets_to_process={packets_to_process}")
            self._buffer.clear()
            if self._timer:
                self._timer = None

        if not packets_to_process:
            return

        # ── GPU‐Accelerated Classification Pipeline ────────────────────────────────────

        tos_list = [pkt["IP"].tos for pkt in packets_to_process]
        tos_tensor = torch.tensor(tos_list, dtype=torch.uint8, device="cuda")
        dscp_tensor = tos_tensor >> 2
        # URLLC: dscp == 46 | eMBB: dscp == 10 | mMTC: dscp == 0 | others = unclassified
        mask_urllc = (dscp_tensor == 46)
        mask_embb  = (dscp_tensor == 10)
        mask_mmtc  = (dscp_tensor == 0)

        idx_urllc = torch.nonzero(mask_urllc, as_tuple=True)[0]
        idx_embb  = torch.nonzero(mask_embb,  as_tuple=True)[0]
        idx_mmtc  = torch.nonzero(mask_mmtc,  as_tuple=True)[0]
        idx_other = torch.nonzero(~(mask_urllc | mask_embb | mask_mmtc), as_tuple=True)[0]

        # 5) For each slice, gather the corresponding Packet objects into a Python list
        def gather_subbatch(indices_tensor):
            if indices_tensor.numel() == 0:
                return []
            idx_list = indices_tensor.to("cpu").tolist()
            return [packets_to_process[i] for i in idx_list]

        sub_urllc = gather_subbatch(idx_urllc)
        sub_embb  = gather_subbatch(idx_embb)
        sub_mmtc  = gather_subbatch(idx_mmtc)
        sub_other = gather_subbatch(idx_other)
        # ── Return to CPU for dispatching sub‐batchs to slices ────────────────────────────────────
        if sub_urllc:
            ns: NetworkSlice = self.slices["urllc"]
            try:
                cprint(f">> [GPU] URLLC batch of {len(sub_urllc)} packets", "blue", attrs=["bold"])
                ns.process_packet_batch_gpu(sub_urllc)
            except AttributeError:
                cprint(f">> [CPU fallback] URLLC batch of {len(sub_urllc)} packets", "light_blue", attrs=["bold"])
                for pkt in sub_urllc:
                    ns.process_packet(pkt)
        if sub_embb:
            ns: NetworkSlice = self.slices["embb"]
            try:
                cprint(f">> [GPU] eMBB batch of {len(sub_embb)} packets", "green", attrs=["bold"])
                ns.process_packet_batch_gpu(sub_embb)
            except AttributeError:
                cprint(f">> [CPU fallback] eMBB batch of {len(sub_embb)} packets", "light_green", attrs=["bold"])
                for pkt in sub_embb:
                    ns.process_packet(pkt)
        if sub_mmtc:
            ns: NetworkSlice = self.slices["mmtc"]
            try:
                cprint(f">> [GPU] mMTC batch of {len(sub_mmtc)} packets", "yellow", attrs=["bold"])
                ns.process_packet_batch_gpu(sub_mmtc)
            except AttributeError:
                cprint(f">> [CPU fallback] mMTC batch of {len(sub_mmtc)} packets", "light_yellow", attrs=["bold"])
                for pkt in sub_mmtc:
                    ns.process_packet(pkt)
        if sub_other:
            for pkt in sub_other:
                dscp = pkt["IP"].tos >> 2
                cprint(f">> Packet[DSCP={dscp} | {pkt['IP'].tos}] is not classified!", "grey")

    def _classify_single(self, packet: Packet):
        """
        The original per‐packet logic for DSCP‐based slicing. Identical to your original code.
        """
        if not packet.haslayer("IP"):
            print("Warning: Non-IP packet cannot be sliced")
            return

        # Extract DSCP (top 6 bits of TOS)
        dscp = packet["IP"].tos >> 2

        if dscp == 46:
            ns: NetworkSlice = self.slices["urllc"]
            ns.process_packet(packet)
            cprint(f">> Packet send to [{dscp} | {packet['IP'].tos}] URLLC Slice", "blue", attrs=["bold"])
        elif dscp == 10:
            ns: NetworkSlice = self.slices["embb"]
            ns.process_packet(packet)
            cprint(f">> Packet send to [{dscp} | {packet['IP'].tos}] eMBB Slice", "green", attrs=["bold"])
        elif dscp == 0:
            ns: NetworkSlice = self.slices["mmtc"]
            ns.process_packet(packet)
            cprint(f">> Packet send to [{dscp} | {packet['IP'].tos}] mMTC Slice", "yellow", attrs=["bold"])
        else:
            cprint(f">> Packet[DSCP={dscp} | {packet['IP'].tos}] is not classified! ", "grey")


class PacketClassifier0:
    def __init__(self, slices, args):
        self.args = args
        self.slices: Dict[str: NetworkSlice] = slices

    """
    @run_gpu
    for every 1ms, collect all packets and process them in GPU
    return processed packets batch 
    forward packets
    """

    def classify_packet(self, packet: Packet):
        """
        Route a packet to the appropriate slice based on DSCP/TOS value
        """
        if not packet.haslayer("IP"):
            print("Warning: Non-IP packet cannot be sliced")
            return

        # dscp = packet["IP"].tos & 0xFC
        dscp = packet["IP"].tos >> 2
        # if dscp == 0x2E:
        if dscp == 46:
            ns: NetworkSlice = self.slices["urllc"]
            ns.process_packet(packet)
            cprint(f">> Packet send to [{dscp} | {packet['IP'].tos}] URLLC Slice", "blue", attrs=["bold"])
        # elif dscp == 0x0A:
        elif dscp == 10:
            ns: NetworkSlice = self.slices["embb"]
            ns.process_packet(packet)
            cprint(f">> Packet send to [{dscp} | {packet['IP'].tos}] eMBB Slice", "green", attrs=["bold"])
        # elif dscp == 0x00:
        elif dscp == 0:
            ns: NetworkSlice = self.slices["mmtc"]
            ns.process_packet(packet)
            cprint(f">> Packet send to [{dscp} | {packet['IP'].tos}] mMTC Slice", "yellow", attrs=["bold"])
        else:
            cprint(f">> Packet[DSCP={dscp} | {packet['IP'].tos}] is not classified! ", "grey")
