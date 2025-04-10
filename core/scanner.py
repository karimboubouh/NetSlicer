import socket

import psutil
import questionary
from questionary import Choice

from utils.helpers import log


class Scanner:
    def __init__(self):
        self.interface = None
        self.filters = None

    @staticmethod
    def _get_interfaces():
        log('blue', "Scanning for available network interfaces...")
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()  # Retrieve interface statistics
        inter_list = []
        for iface, addrs in interfaces.items():
            ip4 = None
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip4 = addr.address
                    break
            # Get the interface status (Up/Down)
            iface_stat = stats.get(iface)
            status = "Up" if iface_stat and iface_stat.isup else "Down"
            # Build the title string including IPv4 (if available) and status
            if ip4:
                title = f"{iface} {status} inet {ip4}"
            else:
                title = f"{iface} {status}"
            inter_list.append(Choice(title=title, value=iface))
        return inter_list

    def select_interface(self):
        # Create an instance to obtain the list of interfaces.
        selected = questionary.select(
            "Select a network interface:",
            choices=self._get_interfaces(),
            style=questionary.Style([
                ('qmark', 'fg:#ff9d00 bold'),
                ('question', 'bold'),
                ('answer', 'fg:#00ff00 bold'),
                ('pointer', 'fg:#673ab7 bold'),
                ('highlighted', 'fg:#673ab7 bold'),
            ])
        ).ask()
        print(selected)
        self.interface = selected
        return selected

    def packet_filter(self):
        protocols = [
            Choice("IP", checked=True),
            Choice("TCP", checked=True),
            Choice("UDP", checked=True),
            Choice("ICMP", checked=True)
        ]
        style = questionary.Style([
            ('qmark', 'fg:#ff9d00 bold'),
            ('question', 'bold'),
            ('answer', 'fg:#00ff00 bold'),
            ('pointer', 'fg:#673ab7 bold'),
            ('highlighted', 'fg:#673ab7 bold'),
            ('selected', 'fg:#673ab7  bg:#ffffff bold'),  # Custom style for selected items
        ])
        selected_protocols = questionary.checkbox(
            "Select the internet protocols you want to keep (all are selected by default):",
            choices=protocols,
            validate=lambda answer: "You must select at least one protocol" if len(answer) == 0 else True,
            style=style
        ).ask()
        # Optional BPF filter
        bpf_filter = questionary.text(
            "BPF filter (optional):",
            style=style
        ).ask()

        selected = selected_protocols + ([bpf_filter] if bpf_filter else [])
        filters = list(dict.fromkeys(
            item.lower() for item in selected if item.strip() and not any(char.isspace() for char in item)
        ))
        self.filters = " or ".join(filters)
        print(self.filters)
        return self.filters


# Example usage:
if __name__ == "__main__":
    scanner = Scanner()
    interface = scanner.select_interface()
    print(f"Selected interface: {interface}")
    filtered = scanner.packet_filter()
    print(f"Filtered packets: {filtered}")
