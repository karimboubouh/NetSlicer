import time

from termcolor import colored

import config
from core.network_slice import NetworkSlice
from core.policy import Policy


def setup_slices(interface):
    # === URLLC ==============================================================>
    ns_urllc = NetworkSlice(
        "urllc",
        0x2E,  # DSCP 46 (Expedited Forwarding for URLLC)
        interface=interface,
        policy=Policy(
            classid=1,
            rate="10mbit",  # Guaranteed minimum bandwidth
            ceil="20mbit",  # Can burst up to 2x rate
            burst="15k",  # Buffer for ~10 packets (1500B each)
            prio=0,  # Highest priority (0-7, 0=highest)
            mtu=1500  # Standard Ethernet MTU
        ),
        args=config.args
    )

    # === eMBB ===============================================================>

    ns_embb = NetworkSlice(
        "embb",
        0x0A,  # DSCP AF11 (Assured Forwarding class 1, low drop)
        interface=interface,
        policy=Policy(
            classid=2,  # Different class ID
            rate="100mbit",  # Baseline guaranteed bandwidth
            ceil="1gbit",  # Can burst up to 1Gbps if available
            burst="50k",  # Larger burst buffer for throughput
            prio=1  # Slightly lower priority than URLLC
        ),
        args=config.args
    )

    # === mMTC ===============================================================>

    ns_mmtc = NetworkSlice(
        "mmtc",
        0x00,  # DSCP BE (Best Effort)
        interface=interface,
        policy=Policy(
            classid=3,  # Separate class ID
            rate="1mbit",  # Low baseline rate (IoT devices)
            ceil="10mbit",  # Can borrow unused bandwidth
            burst="5k",  # Small bursts (IoT sends tiny packets)
            prio=2  # Lowest priority
        ),
        args=config.args
    )

    return ns_urllc, ns_embb, ns_mmtc


def urllc_packet_handler(packet, max_latency=10):
    packet.urllc_timestamp = time.time()
    if len(packet) > 1500:
        print(colored(f"URLLC packet too large! Size: {len(packet)}B", color="red", attrs=["bold"]))
