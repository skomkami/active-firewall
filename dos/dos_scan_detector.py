from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import reduce

from analysepackets.abstract_analyse_packets import AbstractAnalysePackets
from config.config import DBConnectionConf, DoSModuleConf, Periodicity
from database.dos_repo import DosRepo
from model.detection import Detection, ModuleName
from model.packet import Packet
from model.persistent_stats import DosPersistentStats
from model.running_stats import RunningStatsAccumulator, ModuleStats
from utils.utils import debug


@dataclass
class DosStats(ModuleStats):
    packets_no: int = 0
    packets_size: int = 0

    def plus(self, other: DosStats) -> DosStats:
        self.packets_no += 1
        self.packets_size += other.packets_size
        return self


@dataclass
class DosRunningStats(RunningStatsAccumulator):
    def empty_stats(self) -> DosStats:
        return DosStats()

    @staticmethod
    def init(date: datetime, periodicity: Periodicity):
        new_acc = DosRunningStats(since=date, statsDb={}, periodicity=periodicity)
        return new_acc

    # returns false when rules are not exceeded and true when exceeded (dos detected)
    def check_rules(self, address: str, dosModuleConf: DoSModuleConf) -> bool:
        # if self.no_counter >= dosModuleConf.maxPackets or self.size_counter >= dosModuleConf.maxDataKB * 1000:
        #     return True
        # else:
        return False

    def calc_mean(self) -> DosPersistentStats:
        total = len(self.statsDb)
        stats_sum = reduce(lambda a, b: a.plus(b), self.statsDb.values())
        mean_stats = DosPersistentStats(
            id=None,
            time_window_start=self.since,
            time_window_end=datetime.now(),
            mean_packets_per_addr=stats_sum.packets_no/total,
            mean_packets_size_per_addr=stats_sum.packets_size/total
        )
        return mean_stats


class DosAttackDetector(AbstractAnalysePackets):
    def __init__(self, db_config: DBConnectionConf, dos_module_conf: DoSModuleConf):
        super().__init__(db_config)
        self.stats_repo = None
        self.config = dos_module_conf
        self.stats = DosRunningStats.init(datetime.now(), dos_module_conf.periodicity)

    def init(self):
        self.stats_repo = DosRepo(self.db_config)

    def module_name(self):
        return "Dos attack"

    def process_packet(self, packet: Packet):
        try:
            valid = self.stats.check_validity()
            if not valid:
                mean = self.stats.calc_mean()
                empty_windows = self.stats.forward(datetime.now())
                empty_stats = list(
                    map(
                        lambda tw: DosPersistentStats(id=None, time_window=tw),
                        empty_windows
                    )
                )
                self.stats_repo.add_many([mean].extend(empty_stats))

            packet_stats = DosStats(1, packet.size)
            self.stats.plus(packet.from_ip, packet_stats)

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
