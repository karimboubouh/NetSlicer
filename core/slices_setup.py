from scapy.fields import ShortField
from scapy.packet import Packet


class SliceLayer(Packet):
    name = "Slice"
    fields_desc = [ShortField("SID", 0)]
