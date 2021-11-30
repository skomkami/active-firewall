from dataclasses import dataclass
from datetime import datetime, timedelta
from config.config import DBConnectionConf, DoSModuleConf, Periodicity, PeriodicityUnit
from database.detections_repo import debug
from model.detection import Detection, ModuleName
from analysepackets.abstract_analyse_packets import AbstractAnalysePackets
from model.packet import Packet

@dataclass
class RulesAccumulator:
    no_counter: int
    size_counter:int
    since: datetime

    def reset(self, date: datetime):
        self.no_counter = 0
        self.size_counter = 0
        self.since = date
    
    def init(date: datetime):
        new_acc = RulesAccumulator(no_counter=0, size_counter=0, since=date)
        new_acc.since = date
        return new_acc
    
    def plus(self, packet: Packet):
        self.no_counter += 1
        self.size_counter += packet.size
    
    # resets counters when time expires
    def check_validity(self, dosModuleConf: DoSModuleConf) -> bool:
        now = datetime.now()
        counter_valid_to = self.since + timedelta(seconds = seconds_of(dosModuleConf.periodicity))
        if now > counter_valid_to:
            self.reset(now)
    
    # returns false when rules are not exceeded and true when exceeded (dos detected)
    def check_rules(self, dosModuleConf: DoSModuleConf) -> bool:
        if self.no_counter >= dosModuleConf.maxPackets or self.size_counter >= dosModuleConf.maxDataKB * 1000:
            return True
        else:
            return False

def seconds_of(periodicity: Periodicity):
    unit_to_seconds = 1
    if periodicity['unit'] == PeriodicityUnit.Minute: unit_to_seconds = 60
    elif periodicity['unit'] == PeriodicityUnit.Hour: unit_to_seconds = 60 * 60
    else: unit_to_seconds = 60 * 60 * 24
    return unit_to_seconds * periodicity['multiplier']

class DosAttackDetector(AbstractAnalysePackets):
    def __init__(self, dbConfig: DBConnectionConf, dosModuleConf: DoSModuleConf):
        super().__init__(dbConfig)
        self.config = dosModuleConf
        self.packetsDb = {}

    def module_name(self):
        return "Dos attack"

    def process_packet(self, packet: Packet):
        try:
            self.packetsDb.setdefault(packet.from_ip, RulesAccumulator.init(datetime.now()))
            self.packetsDb[packet.from_ip].plus(packet)
            self.packetsDb[packet.from_ip].check_validity(self.config)
            if self.packetsDb[packet.from_ip].check_rules(self.config):
                detection = Detection(
                    detection_time=datetime.now(),
                    attacker_ip_address=packet.to_ip,
                    module_name=ModuleName.DOS_MODULE,
                    note="Attacked port: {}".format(str(packet.to_port))
                )
                self.repo.add(detection)
        except Exception as msg:
            debug("error in dos scan: " + str(msg))

