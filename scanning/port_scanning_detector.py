from __future__ import annotations
from datetime import datetime
from struct import *
from config.config import DBConnectionConf, PortScannerModuleConf, Periodicity
from database.port_scanning_repo import PortScanningRepo
from model.detection import Detection, ModuleName
from analysepackets.abstract_analyse_packets import AbstractAnalysePackets
from model.packet import Packet
from model.persistent_stats import PortScanningPersistentStats
from model.running_stats import ModuleStats, RunningStatsAccumulator
from dataclasses import dataclass
from datetime import datetime
from functools import reduce
from model.timewindow import TimeWindow

from utils.log import log_to_file


@dataclass
class PortScanningStats(ModuleStats):
    scan_tries: int = 0

    def plus(self, other: PortScanningStats) -> PortScanningStats:
        self.scan_tries += other.scan_tries
        return self


@dataclass
class PortScanningRunningStats(RunningStatsAccumulator):
    def empty_stats(self) -> PortScanningStats:
        return PortScanningStats()

    @staticmethod
    def init(date: datetime, periodicity: Periodicity):
        new_acc = PortScanningRunningStats(since=date, stats_db={}, periodicity=periodicity)
        return new_acc

    # returns false when rules are not exceeded and true when exceeded (PortScanning detected)
    def check_rules(self, address: str, PortScanningModuleConf: PortScannerModuleConf) -> bool:
        # if self.no_counter >= PortScanningModuleConf.maxPackets or self.size_counter >= PortScanningModuleConf.maxDataKB * 1000:
        #     return True
        # else:
        return False

    def calc_mean(self) -> PortScanningPersistentStats:
        total = len(self.stats_db)
        if total > 0:
            stats_sum = reduce(lambda a, b: a.plus(b), self.stats_db.values())
            mean_stats = PortScanningPersistentStats(
                id=None,
                time_window=TimeWindow(self.since, self.until()),
                mean_scans_per_addr=stats_sum.scan_tries / total
            )
            return mean_stats
        else:
            return PortScanningPersistentStats(
                id=None,
                time_window=TimeWindow(self.since, self.until()),
                mean_scans_per_addr=0
            )


class PortScanningDetector(AbstractAnalysePackets):
    def __init__(self, db_config: DBConnectionConf, port_scanning_module_conf: PortScannerModuleConf, lanIp: str = ""):
        super().__init__(db_config)
        self.config = port_scanning_module_conf
        self.halfscandb = {}
        self.lanIp = lanIp
        self.stats_repo = None
        self.stats = PortScanningRunningStats.init(datetime.now(), port_scanning_module_conf.periodicity)

    def init(self):
        self.stats_repo = PortScanningRepo(self.db_config)

    def module_name(self):
        return "Port Scanning"

    def process_packet(self, packet: Packet):
        try:
            p_direction = packet.from_ip + "->" + packet.to_ip
            p_reverse_direction = packet.to_ip + "->" + packet.from_ip
            if "SYN" in packet.flags and packet.seq_no > 0 and packet.ack_no == 0 and len(packet.flags) == 1:
                self.halfscandb[p_direction + "_" + str(packet.seq_no)] = p_direction + "_SYN_ACK_" + str(
                    packet.seq_no) + "_" + str(packet.ack_no)
            elif "RST" in packet.flags and "ACK" in packet.flags and len(packet.flags) == 2:
                tmp = p_reverse_direction + "_" + str(packet.ack_no - 1)
                if tmp in self.halfscandb:
                    del self.halfscandb[p_reverse_direction + "_" + str(packet.ack_no - 1)]
                    # detection = Detection(
                    #     detection_time=datetime.now(),
                    #     attacker_ip_address=packet.to_ip,
                    #     module_name=ModuleName.PORTSCANNING_MODULE,
                    #     note="Attacked port: {}".format(str(packet.to_port))
                    # )
                    # self.repo.add(detection)

                    valid = self.stats.check_validity()
                    if not valid:
                        mean = self.stats.calc_mean()
                        empty_windows = self.stats.forward(datetime.now())
                        up_to_now_stats = list(
                            map(
                                lambda tw: PortScanningPersistentStats(id=None, time_window=tw),
                                empty_windows
                            )
                        )
                        
                        up_to_now_stats.insert(0, mean)
                        self.stats_repo.add_many(up_to_now_stats)

                    packet_stats = PortScanningStats(scan_tries=1)
                    self.stats.plus(packet.to_ip, packet_stats)

        except Exception as msg:
            log_to_file("error in port scanning scan: " + str(msg))
