import config
from core.classifier import PacketClassifier
from core.parser import parse_args
from termcolor import cprint
from core.scanner import Scanner
from core.slices_setup import setup_slices
from core.sniffer import Sniffer
from utils import log
from utils.helpers import reset_environment, setup_environment

"""
TOS: the differentiated services
-> forward IP packets
    -> Check remote connections
-> Use VPN
    -> What is the capacity of the VPN server
-> Do the performance trial
    -> locally
    -> With Xavier
-> memory size: Buffer size :: assume a list of fixed size and can support a small fixed number of packets

iperf3: small packets / find the max capacity for max packets per seconds.
do simple IP forwarding of packets

-> check  Packet Filter (PF) firewall (pfctl -f)

"""


def net_slicer():
    # === Configuration =========================
    parse_args()
    assert config.args is not None
    config.args.display_metrics = True
    config.args.display_packets = True
    # === Environment setup =====================
    setup_environment(config.args)
    # === Scan for network interfaces ===========
    scanner = Scanner()
    # scanner.interface = "eth0"
    # scanner.filters = "ip or tcp or udp or icmp"
    scanner.select_interface()
    scanner.packet_filter()  # Berkeley Packet Filter
    # === Network Slices =========================
    ns_urllc, ns_embb, ns_mmtc = setup_slices(scanner.interface)
    slices = {"urllc": ns_urllc, "embb": ns_embb, "mmtc": ns_mmtc}
    # === Classifier Sniffer =====================
    classifier = PacketClassifier(slices=slices, args=config.args)
    # === Packet Sniffer ========================
    sniffer = Sniffer(args=config.args, scanner=scanner, classifier=classifier)
    sniffer.start_sniffing()
    # === Plot results ==========================
    # === Reset Environment =====================
    reset_environment()


if __name__ == "__main__":
    try:
        net_slicer()
    except KeyboardInterrupt:
        log("red", "NetSlicer DONE by KeyboardInterrupt!")
