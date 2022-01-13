from __future__ import annotations
from datetime import datetime
from struct import *
from config.config import DBConnectionConf, PortScannerModuleConf
from database.port_scanning_repo import PortScanningRepo
from model.detection import Detection, ModuleName
from analysepackets.abstract_analyse_packets import AbstractAnalysePackets
from model.packet import Packet
from model.persistent_stats import PortScanningModuleStats
from model.running_stats import ModuleStats, RunningStatsAccumulator
from dataclasses import dataclass
from datetime import datetime
from functools import reduce

from utils.utils import debug


@dataclass
class PortScanningStats(ModuleStats):
    scan_tries: int

    def plus(self, other: PortScanningStats) -> PortScanningStats:
        self.scan_tries += other.scan_tries
        return self


@dataclass
class PortScanningRunningStats(RunningStatsAccumulator):
    def empty_stats(self) -> PortScanningStats:
        return PortScanningStats()

    @staticmethod
    def init(date: datetime):
        new_acc = PortScanningRunningStats(since=date, statsDb={})
        return new_acc

    # returns false when rules are not exceeded and true when exceeded (PortScanning detected)
    def check_rules(self, address: str, PortScanningModuleConf: PortScannerModuleConf) -> bool:
        # if self.no_counter >= PortScanningModuleConf.maxPackets or self.size_counter >= PortScanningModuleConf.maxDataKB * 1000:
        #     return True
        # else:
        return False

    def calc_mean(self) -> PortScanningModuleStats:
        total = len(self.statsDb)
        if(total > 0):
            stats_sum = reduce(lambda a, b: a.plus(b), self.statsDb.values())
            mean_stats = PortScanningModuleStats(
                id=None,
                time_window_start=self.since,
                time_window_end=datetime.now(),
                mean_scans_per_addr=stats_sum/total
            )
            return mean_stats
        else:
            return PortScanningRunningStats(
                id=None,
                time_window_start=self.since,
                time_window_end=datetime.now(),
                mean_scans_per_addr=0
            )

class PortScanningDetector(AbstractAnalysePackets):
    def __init__(self, dbConfig: DBConnectionConf, lanIp: str = ""):
        super().__init__(dbConfig)
        self.halfscandb = {}
        self.lanIp = lanIp
        self.stats_repo = None
        self.stats = PortScanningRunningStats.init(datetime.now())

    def init(self):
        self.port_scanning_repo = PortScanningRepo(self.dbConfig)

    def module_name(self):
        return "Port Scanning"

    def process_packet(self, packet: Packet):
        try:
            if packet.from_ip == self.lanIp:
                return
            p_direction = packet.from_ip+"->"+packet.to_ip
            p_reverse_direction = packet.to_ip+"->"+packet.from_ip
            if("SYN" in packet.flags and packet.seq_no>0 and packet.ack_no==0 and len(packet.flags)==1):
                self.halfscandb[p_direction+"_"+str(packet.seq_no)] = p_direction+"_SYN_ACK_"+str(packet.seq_no)+"_"+str(packet.ack_no)
                debug('received syn')
            elif("RST" in packet.flags and "ACK" in packet.flags and len(packet.flags)==2):
                tmp = p_reverse_direction+"_"+str(packet.ack_no-1)
                if tmp in self.halfscandb:
                    del self.halfscandb[p_reverse_direction+"_"+str(packet.ack_no-1)]
                # detection = Detection(
                #     detection_time=datetime.now(),
                #     attacker_ip_address=packet.to_ip,
                #     module_name=ModuleName.PORTSCANNING_MODULE,
                #     note="Attacked port: {}".format(str(packet.to_port))
                # )
                # self.repo.add(detection)

                debug("detected port scanning")
                packet_stats = PortScanningStats(1)
                self.stats.plus(packet.to_ip, packet_stats)

                valid = self.stats.check_validity(self.config.periodicity)
                if not valid:
                    mean = self.stats.calc_mean()
                    self.stats_repo.add(mean)
                    self.stats.reset(datetime.now())
        except Exception as msg:
            debug("error in port scanning scan: " + str(msg))


        
