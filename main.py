import config
from core.classifier import PacketClassifier
from core.network_slice import NetworkSlice
from core.parser import parse_args
from core.scanner import Scanner
from core.sniffer import Sniffer
from utils import log
from utils.helpers import setup_environment, reset_environment

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
    # setup_environment(config.args)
    # === Scan for network interfaces ===========
    scanner = Scanner()
    scanner.interface = "en0"
    scanner.filters = "ip or tcp or udp or icmp"
    # scanner.select_interface()
    # scanner.packet_filter()  # Berkeley Packet Filter
    # === Network Slices =========================
    slices = {
        'urllc': NetworkSlice("urllc", 1, policy=None, args=config.args),
        'eMBB': NetworkSlice("embb", 2, policy=None, args=config.args),
        'mMTC': NetworkSlice("mMTC", 3, policy=None, args=config.args),
    }
    print(slices)

    exit(0)
    # === Classifier Sniffer =====================
    classifier = PacketClassifier(slices=slices, args=config.args)
    # === Packet Sniffer ========================
    sniffer = Sniffer(args=config.args, scanner=scanner, classifier=classifier)
    sniffer.start_sniffing()
    # === Plot results ==========================
    # === Reset Environment =====================
    reset_environment()


if __name__ == '__main__':
    try:
        net_slicer()
    except KeyboardInterrupt:
        log('red', "NetSlicer DONE by KeyboardInterrupt!")
