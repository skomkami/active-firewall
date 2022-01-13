from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import reduce

from analysepackets.abstract_analyse_packets import AbstractAnalysePackets
from config.config import DBConnectionConf, DoSModuleConf
from database.dos_repo import DosRepo
from model.detection import Detection, ModuleName
from model.packet import Packet
from model.persistent_stats import DosModuleStats
from model.running_stats import RunningStatsAccumulator, ModuleStats
from utils.utils import debug


@dataclass
class DosRunningStats(ModuleStats):
    packets_no: int = 0
    packets_size: int = 0

    def plus(self, other: DosRunningStats) -> DosRunningStats:
        self.packets_no += 1
        self.packets_size += other.packets_size
        return self

    def reset(self) -> DosRunningStats:
        self.packets_no = 0
        self.packets_size = 0


@dataclass
class DosRunningStats(RunningStatsAccumulator):
    def empty_stats(self):
        DosRunningStats()

    # returns false when rules are not exceeded and true when exceeded (dos detected)
    def check_rules(self, address: str, dosModuleConf: DoSModuleConf) -> bool:
        if self.no_counter >= dosModuleConf.maxPackets or self.size_counter >= dosModuleConf.maxDataKB * 1000:
            return True
        else:
            return False

    def calc_mean(self) -> DosModuleStats:
        total = len(self.statsDb)
        stats_sum = reduce(lambda a, b: a.plus(b), self.statsDb.values())
        mean_stats = DosModuleStats(
            id=None,
            time_window_start=self.since,
            mean_packets_per_addr=stats_sum.packets_no/total,
            mean_packets_size_per_addr=stats_sum.packets_size/total
        )
        return mean_stats


class DosAttackDetector(AbstractAnalysePackets):
    def __init__(self, db_config: DBConnectionConf, dos_module_conf: DoSModuleConf):
        super().__init__(db_config)
        self.statsRepo = None
        self.config = dos_module_conf
        self.stats = DosRunningStats.init(datetime.now)

    def init(self):
        self.statsRepo = DosRepo(self.dbConfig)

    def module_name(self):
        return "Dos attack"

    def process_packet(self, packet: Packet):
        try:
            packet_stats = DosRunningStats(1, packet.size)
            self.stats.plus(packet.from_ip, packet_stats)

            valid = self.stats.check_validity(self.config.periodicity)
            if not valid:
                mean = self.stats.calc_mean()
                self.statsRepo.add(mean)
                self.stats.reset(datetime.now())

            if self.stats.check_rules(packet.from_ip, self.config):
                detection = Detection(
                    detection_time=datetime.now(),
                    attacker_ip_address=packet.to_ip,
                    module_name=ModuleName.DOS_MODULE,
                    note="Attacked port: {}".format(str(packet.to_port))
                )
                self.repo.add(detection)
        except Exception as msg:
            debug("error in dos scan: " + str(msg))
