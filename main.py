import os
import re
import sys
from build import Build
import argparse


class DNS:
    def __init__(self, dpi_engine):
        self.dns_label = 'DNS'
        dpi_engine.register_udp_first_packet_callback(rb'^.{4}\x00[\x01-\x0f]\x00.{5}',self.callback_function)

    def callback_function(self, flow, application_packet):
        flow.set_protocol(self.dns_label)

class HTTP:
    def __init__(self, dpi_engine):
        self.http_label = 'HTTP'
        dpi_engine.register_tcp_first_packet_callback(rb'^(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE) .{0,5000}HTTP\/1\.(0|1)(|\x0d)\x0a',self.callback_function)

    def callback_function(self, flow, application_packet):
        flow.set_protocol(self.http_label)

class NTP:
    def __init__(self, dpi_engine):
        self.ntp_label = 'NTP'
        dpi_engine.register_udp_first_packet_callback(rb'^.{12}\x00{4}',self.callback_function)

    def callback_function(self, flow, application_packet):
        flow_dst_port = flow.get_fivetuple()[4]
        expected_dst_port = 123
        if (application_packet.packet_data[0] & 56 >> 3) < 4:
            if flow_dst_port == expected_dst_port:
                flow.set_protocol(self.ntp_label)

class QUIC:
    def __init__(self, dpi_engine):
        self.quic_label = 'QUIC'
        dpi_engine.register_udp_first_packet_callback(rb'^[\xc0-\xff]\x00{3}\x01',self.callback_function)

    def callback_function(self, flow, application_packet):
        application_packet_data = application_packet.packet_data
        if len(application_packet_data) < 1200:
            return
        if not (application_packet_data[0] >> 7):
            return
        if not (application_packet_data[0] >> 6):
            return
        flow.set_protocol(self.quic_label)

class STUN:
    def __init__(self, dpi_engine):
        self.stun_label = 'STUN'
        dpi_engine.register_udp_first_packet_callback(rb"^.{4}\x21\x12\xa4\x42",self.callback_function)

    def callback_function(self, flow, application_packet):
        flow.set_protocol(self.stun_label)

class TLS:
    def __init__(self, dpi_engine):
        self.tls_label = 'TLS'
        dpi_engine.register_tcp_first_packet_callback(rb'^\x16\x03[\x00-\x03].{2}\x01',self.callback_function)

    def callback_function(self, flow, application_packet):
        flow.set_protocol(self.tls_label)

def get_args(args):
    parser = argparse.ArgumentParser(description="DPI is a program that can be used to analyze packet streams.\n\r"
        "use -h or --help to see the help", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-r', '--read', type=str, required=True, help='read a pcap file', dest='read_file', metavar='File Path')
    args = parser.parse_args()
    args.file_r = os.path.join('packets', args.file_r)
    return args

class DPI:

    def __init__(self):
        self.udp_first_packet_patterns_callback_dict = {}
        self.tcp_first_packet_patterns_callback_dict = {}
        self.protocols_list = [DNS,NTP,TLS,HTTP,STUN,QUIC]
        self.modules_objects = dict()

        for module_name in self.protocols_list:
            module_name(self)

    def register_udp_first_packet_callback(self, pattern, callback):
        self.udp_first_packet_patterns_callback_dict[pattern] = callback

    def register_tcp_first_packet_callback(self, pattern, callback):
        self.tcp_first_packet_patterns_callback_dict[pattern] = callback

    def feed_udp_first_packet(self, flow, application_packet):
        for pattern in self.udp_first_packet_patterns_callback_dict:
            if not re.search(pattern, application_packet.packet_data, re.DOTALL):
                continue
            self.udp_first_packet_patterns_callback_dict[pattern](flow,application_packet,)

    def feed_tcp_first_packet(self, flow, application_packet):
        for pattern in self.tcp_first_packet_patterns_callback_dict:
            if not re.search(pattern, application_packet.packet_data, re.DOTALL):
                continue
            self.tcp_first_packet_patterns_callback_dict[pattern](flow,application_packet,)

    def inspect_packet(self, fivetuple_key, flow, application_packet):
        if flow.get_total_packets_number() > 1:
            return

        if fivetuple_key[2]:
            self.feed_tcp_first_packet(flow,application_packet,)
        else:
            self.feed_udp_first_packet(flow,application_packet,)


if __name__ == "__main__":
    dpi_eng = DPI()
    dpi_builder = Build(dpi_eng)
    args = get_args(sys.argv[1:])
    dpi_builder.launcher(os.path.abspath(args.file_r))
    dpi_builder.session_print()
