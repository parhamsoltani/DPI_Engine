import socket
import datetime
import dpkt
from main.debug.debugger import Debugger


class Packet():
    def __init__(self, is_packet_from_client, packet_timestamp, packet_data):
        self.is_packet_from_client = is_packet_from_client
        self.packet_timestamp = packet_timestamp
        self.packet_data = packet_data

class StateDetection():

    def __init__(self):
        unknown_label = "UNKNOWN"
        self.protocol = unknown_label

    def set_protocol(self, protocol_label):
        self.protocol = protocol_label

class FiveTuple():

    def __init__(self, fivetuple):
        self.ip_source = fivetuple[0]
        self.ip_destination = fivetuple[1]
        self.payload = fivetuple[2]
        self.port_source = fivetuple[3]
        self.port_destination = fivetuple[4]

    def get_fivetuple(self):
        return (self.ip_source, self.ip_destination, self.payload, self.port_source, self.port_destination)

    def get_reversed_fivetuple(self):
        return (self.ip_destination, self.ip_source, self.payload, self.port_destination, self.port_source)


class FlowStats():

    def __init__(self):
        self.sent_packets_number = 0
        self.recieved_packets_number = 0
        self.sent_bytes_number = 0
        self.recieved_bytes_number = 0
        self.flow_start_time = 0
        self.flow_last_time = 0

    def get_total_packets_number(self):
        return self.sent_packets_number + self.recieved_packets_number

    def get_total_bytes_number(self):
        return self.sent_bytes_number + self.recieved_bytes_number

    def get_flow_duration_time(self):
        return self.flow_last_time - self.flow_start_time

    def update_stats(self, packet):
        self.flow_last_time = packet.packet_timestamp
        if self.get_total_packets_number() == 0:
            self.flow_start_time = packet.packet_timestamp
        if packet.is_packet_from_client:
            self.sent_packets_number += 1
            self.sent_bytes_number += len(packet.packet_data)
        else:
            self.recieved_packets_number += 1
            self.recieved_bytes_number += len(packet.packet_data)


class Flow(FlowStats, FiveTuple, StateDetection):

    def __init__(self, fivetuple):
        FlowStats.__init__(self)
        FiveTuple.__init__(self, fivetuple)
        StateDetection.__init__(self)

    index = -1

    def get_state(self):
        payload = 'TCP' if self.payload else 'UDP'
        src_ip_str = socket.inet_ntoa(self.ip_source)
        dst_ip_str = socket.inet_ntoa(self.ip_destination)

        fivetuple = (src_ip_str, dst_ip_str, payload,*self.get_fivetuple()[3:])
        Flow.index += 1
        return (f'### flow number {Flow.index}' + ' ' * 3 +
                f'### five tuple: {fivetuple}' + '\n'
                f'{src_ip_str}, {self.port_source} --> {dst_ip_str}, {self.port_destination}: {payload}: {self.protocol}; '
                f'sent packets: {self.sent_packets_number}, received packets: {self.recieved_packets_number}, sent bytes: {self.sent_bytes_number}, received bytes: {self.recieved_bytes_number}, timestamp: ({datetime.datetime.fromtimestamp(self.flow_start_time)}, {datetime.datetime.fromtimestamp(self.flow_last_time)})' + '\n' * 2
                )

class Build:
    def __init__(self, dpi_engine):
        self.flows_dict = {}
        self.dpi_engine = dpi_engine

    def process_packet(self, packet_payload, timestamp):

        ethernet = dpkt.ethernet.Ethernet(packet_payload)
        if not isinstance(ethernet, dpkt.ethernet.Ethernet):
            return
        ip_packet = ethernet.data

        if not isinstance(ip_packet, dpkt.ip.IP):
            return
        ip_payload = ip_packet.data

        if not isinstance(ip_payload, dpkt.udp.UDP) and not isinstance(ip_payload, dpkt.tcp.TCP):
            return

        if not ip_payload.data:
            return

        fivetuple_key = (ip_packet.src,ip_packet.dst,(ip_packet.p == 6),ip_packet.data.sport,ip_packet.data.dport)
        reversed_fivetuple_key = (ip_packet.dst, ip_packet.src,(ip_packet.p == 6),ip_packet.data.dport,ip_packet.data.sport)

        Debugger.catch_debugger(src=fivetuple_key[0], dst=fivetuple_key[1],sport=fivetuple_key[3], dport=fivetuple_key[4])
        find_flow_fivetuple_key = fivetuple_key
        is_packet_from_client = True

        if fivetuple_key in self.flows_dict:
            flow = self.flows_dict[fivetuple_key]
        elif reversed_fivetuple_key in self.flows_dict:
            flow = self.flows_dict[reversed_fivetuple_key]
            is_packet_from_client = not is_packet_from_client
            find_flow_fivetuple_key = reversed_fivetuple_key
        else:
            flow = Flow(fivetuple_key)


        application_data = ip_packet.data.data
        application_packet = Packet(is_packet_from_client, timestamp, application_data)
        flow.update_stats(application_packet)
        self.flows_dict.update({find_flow_fivetuple_key: flow})
        self.dpi_engine.inspect_packet(fivetuple_key, flow, application_packet)

    def session_print(self):
        for flow_key in self.flows_dict:
            print(self.flows_dict[flow_key].get_state())

    def launcher(self, pcap_file_name):
        with open(pcap_file_name, 'rb') as file:
            pcap = dpkt.pcap.Reader(file)
            for timestamp, buffer in pcap:
                self.process_packet(buffer, timestamp)
