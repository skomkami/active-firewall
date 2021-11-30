from datetime import datetime
from config.config import DBConnectionConf, DoSModuleConf
from database.detections_repo import debug
from model.detection import Detection, ModuleName
from analysepackets.abstract_analyse_packets import AbstractAnalysePackets
from model.packet import Packet

class DosAttackDetector(AbstractAnalysePackets):
    def __init__(self, dbConfig: DBConnectionConf, dosModuleConf: DoSModuleConf):
        super().__init__(dbConfig)
        self.config = dosModuleConf
        self.packetsDb = {}

    def module_name(self):
        return "Dos attack"

    def process_packet(self, packet: Packet):
        self.packetsDb.setdefault(packet.from_ip, 0)
        self.packetsDb[packet.from_ip] += packet.size
        if self.packetsDb[packet.from_ip] >= self.config.maxDataKB*1024:
            detection = Detection(
                detection_time=datetime.now(),
                attacker_ip_address=packet.to_ip,
                module_name=ModuleName.PORTSCANNING_MODULE,
                note="Attacked port: {}".format(str(packet.to_port))
            )
            self.repo.add(detection)

