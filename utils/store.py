from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS


def store_init():
    influx_client = InfluxDBClient(
        url="http://localhost:8086",
        token="YOUR_TOKEN",
        org="YOUR_ORG"
    )
    write_api = influx_client.write_api(write_options=SYNCHRONOUS)

    return write_api


def store_packet(write_api, packet):
    point = Point("network_packets") \
        .tag("source", packet.ip_src) \
        .tag("destination", packet.ip_dst) \
        .tag("protocol", packet.protocol) \
        .field("size", packet.size) \
        .field("data_size", packet.data_size)

    return write_api.write(bucket="YOUR_BUCKET", record=point)
