import dpkt
import datetime
import socket
import sys
import argparse
from itertools import groupby


class Packet:
    def __init__(self, ip, ts):
        self.conn_type = ip.data.__class__.__name__
        self.src_ip = socket.inet_ntoa(ip.src)
        self.src_port = ip.data.sport
        self.dst_ip = socket.inet_ntoa(ip.dst)
        self.dst_port = ip.data.dport
        self.length = len(ip.data.data)
        self.timestamp = ts

    def __eq__(self, other):
        return (
            (self.src_ip == other.src_ip or self.src_ip == other.dst_ip or self.dst_ip == other.src_ip)
            and (self.src_port == other.src_port or self.src_port == other.dst_port or self.dst_port == other.src_port)
            and (self.dst_ip == other.dst_ip or self.dst_ip == other.src_ip or self.src_ip == other.dst_ip)
            and (self.dst_port == other.dst_port or self.dst_port == other.src_port or self.src_port == other.dst_port)
            and self.conn_type == other.conn_type
                )

    def __str__(self):
        return f"{self.src_ip} {self.src_port} -> {self.dst_ip} {self.dst_port}; {self.conn_type} {self.length}"

    def __repr__(self):
        return f"{self.src_ip} {self.src_port} -> {self.dst_ip} {self.dst_port}; {self.conn_type} {self.length}"

    def __hash__(self):
        return hash((self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.conn_type))

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--read',)
args = parser.parse_args()

if args.read:

    try:
        file_name = sys.argv[1]
    except:
        print('![Usage] python main.py [filename]')
        sys.exit(1)

    packets = []
    with open(file_name, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buffer in pcap:

            eth = dpkt.ethernet.Ethernet(buffer)
            ip = eth.data

            if isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP):
                packets.append(Packet(ip, timestamp))


flows = [list(g) for _, g in groupby(packets, key=lambda x: x)]
count = 1
for flow in flows:
    sent_packets = 0
    received_packets = 0
    sent_bytes = 0
    received_bytes = 0
    times = []

    for packet in flow:
        if packet.src_ip == flow[0].src_ip:
            sent_bytes += packet.length
            sent_packets += 1
        else:
            received_bytes += packet.length
            received_packets += 1

        times.append(packet.timestamp)

    times = sorted(times)
    if len(times) > 1:
        time = f"({datetime.datetime.fromtimestamp(min(times))}, {datetime.datetime.fromtimestamp(max(times))})"
    else:
        time = f"({datetime.datetime.fromtimestamp(times[0])})"

    print("### flow number", count)
    print("{}, {} -> {}, {}; {}: UNKNOWN; sent packets: {}, received packets: {}, sent bytes: {} received bytes: {}, timestamp: {}".format(flow[0].src_ip,flow[0].src_port,flow[0].dst_ip,flow[0].dst_port,flow[0].conn_type,sent_packets,received_packets,sent_bytes,received_bytes,time))
    print()
    count += 1
