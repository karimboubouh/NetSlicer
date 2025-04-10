from termcolor import cprint

def display_packet(packet):
    cprint(f"ProtocolTTTTT: {packet.protocol} | Source: {packet.src} -> Destination: {packet.dest}", 'green')
    if hasattr(packet, 'data'):
        print(f"Data: {packet.data[:100]}")  # Display first 100 bytes
