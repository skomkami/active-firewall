from abc import ABC, abstractmethod

from datetime import datetime
import socket, sys
from struct import *
from collections import OrderedDict
from config.config import DBConnectionConf
from database.detections_repo import DetectionRepo
from model.packet import Packet
from utils.log import log_to_file


class AbstractAnalysePackets(ABC):
    def __init__(self, db_config: DBConnectionConf):
        try:
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except socket.error as msg:
            # TODO lepsza obsługa błędów
            log_to_file('[*]Socket can\'t be created! Error Code : ' + str(msg[0]) + ' Error Message ' + msg[1])
            sys.exit()
        except AttributeError:
            log_to_file('[*]Socket can\'t be created! Because of Attribute error')
            sys.exit()
        self.db_config = db_config
        self.stats = None

    def parse_flags(self, dec):
        parsed_flags = []
        flags_dict = OrderedDict(
            [("128", "CWR"), ("64", "ECE"), ("32", "URG"), ("16", "ACK"), ("8", "PSH"), ("4", "RST"), ("2", "SYN"),
             ("1", "FIN")])
        for i in flags_dict.keys():
            if (dec >= int(i)):
                dec = dec - int(i)
                parsed_flags.append(flags_dict[i])
        return parsed_flags

    # @abstractmethod
    def init(self):
        return

    @abstractmethod
    def process_packet(self, packet: Packet):
        return None

    @abstractmethod
    def module_name(self):
        return None

    def run(self):
        self.repo = DetectionRepo(self.db_config)
        self.init()
        log_to_file(self.module_name() + " started")
        while True:
            try:
                # https://en.wikipedia.org/wiki/File:Ethernet_Type_II_Frame_format.svg
                # wielkość buffera
                packet = self.socket.recv(65565)
                eth_length = 14
                eth_header_bytes = packet[:eth_length]
                # 6s - 6 bytes
                # H - unsigned short (2 bytes)
                eth_header = unpack('! 6s 6s H', eth_header_bytes)
                # ether_type in network byte order
                (dest_mac, src_mac, ether_type) = eth_header
            except:
                log_to_file("Error in analyser")
                pass

            # ipV4 https://en.wikipedia.org/wiki/EtherType
            if ether_type == 2048:
                ip_header_packed = packet[eth_length:20 + eth_length]
                # https://nmap.org/book/tcpip-ref.html
                ip_header = unpack('!BBHHHBBH4s4s', ip_header_packed)

                # version and IHL (header length) are on one byte
                version_and_ihl = ip_header[0]
                version = version_and_ihl >> 4
                ihl = version_and_ihl & 0xF
                total_length = ip_header[2]
                ipheader_length = ihl * 4
                protocol = ip_header[6]
                src_addr = socket.inet_ntoa(ip_header[8])
                dest_addr = socket.inet_ntoa(ip_header[9])

                # TCP protocol
                if protocol == 6:
                    t = ipheader_length + eth_length
                    tcp_header_packed = packet[t:t + 20]

                    # https://www.gatevidyalay.com/wp-content/uploads/2018/09/TCP-Header-Format.png
                    tcp_header = unpack('!HHLLBBHHH', tcp_header_packed)

                    src_port = tcp_header[0]
                    dest_port = tcp_header[1]
                    seq_no = tcp_header[2]
                    ack_no = tcp_header[3]
                    tcp_flags = self.parse_flags(tcp_header[5])

                    packet = Packet(
                        arrival_time=datetime.now(),
                        from_ip=src_addr,
                        to_ip=dest_addr,
                        from_mac=src_mac,
                        to_mac=dest_mac,
                        from_port=src_port,
                        to_port=dest_port,
                        seq_no=seq_no,
                        ack_no=ack_no,
                        size=total_length,
                        flags=tcp_flags
                    )
                    self.process_packet(packet)
