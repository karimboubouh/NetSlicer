import time

class PacketMetrics:
    def __init__(self):
        self.packet_count = 0
        self.total_data = 0
        self.start_time = time.time()

    def update(self, packet_size):
        self.packet_count += 1
        self.total_data += packet_size

    def pps(self):
        """Packets per second"""
        elapsed = time.time() - self.start_time
        return round(self.packet_count / elapsed, 2) if elapsed > 0 else 0

    def throughput(self):
        """Throughput"""
        elapsed = time.time() - self.start_time
        return round((self.total_data / 1024) / elapsed, 2) if elapsed > 0 else 0
