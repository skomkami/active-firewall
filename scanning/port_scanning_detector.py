from datetime import datetime
from struct import *
from config.config import DBConnectionConf
from database.detections_repo import debug
from model.detection import Detection, ModuleName
from analysepackets.abstract_analyse_packets import AbstractAnalysePackets
from model.packet import Packet

class PortScanningDetector(AbstractAnalysePackets):
    def __init__(self, dbConfig: DBConnectionConf):
        super().__init__(dbConfig)
        self.halfscandb = {}

    def module_name(self):
        return "Port Scanning"

    def process_packet(self, packet: Packet):
        p_direction = packet.from_ip+"->"+packet.to_ip
        p_reverse_direction = packet.to_ip+"->"+packet.from_ip
        if("SYN" in packet.flags and packet.seq_no>0 and packet.ack_no==0 and len(packet.flags)==1):
            self.halfscandb[p_direction+"_"+str(packet.seq_no)] = p_direction+"_SYN_ACK_"+str(packet.seq_no)+"_"+str(packet.ack_no)
        elif("RST" in packet.flags and "ACK" in packet.flags and len(packet.flags)==2):
            tmp = p_reverse_direction+"_"+str(packet.ack_no-1)
            if tmp in self.halfscandb:
                del self.halfscandb[p_reverse_direction+"_"+str(packet.ack_no-1)]
                detection = Detection(
                    detection_time=datetime.now(),
                    attacker_ip_address=packet.to_ip,
                    module_name=ModuleName.PORTSCANNING_MODULE,
                    note="Attacked port: {}".format(str(packet.to_port))
                )
                self.repo.add(detection)
