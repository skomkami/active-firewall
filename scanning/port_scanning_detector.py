from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import reduce

from analysepackets.abstract_analyse_packets import AbstractAnalysePackets
from anomaly_detection.detect import AnomalyDetector
from config.config import DBConnectionConf, PortScannerModuleConf, AnomalyDetectorConf, Periodicity
from database.blocked_hosts_repo import BlockedHostRepo
from database.port_scanning_repo import PortScanningRepo
from ip_access_manager.manager import IPAccessManager
from model.packet import Packet
from model.persistent_stats import PortScanningPersistentStats
from model.running_stats import ModuleStats, RunningStatsAccumulator
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
    def __init__(self, db_config: DBConnectionConf, port_scanning_module_conf: PortScannerModuleConf):
        super().__init__(db_config)
        self.config = port_scanning_module_conf
        self.halfscandb = {}
        self.synackdb = {}
        self.stats_repo = None
        self.stats = PortScanningRunningStats.init(datetime.now(), port_scanning_module_conf.periodicity)
        self.ip_manager = IPAccessManager()
        self.anomaly_detector = AnomalyDetector(AnomalyDetectorConf())
        self.blocks_repo = BlockedHostRepo(db_config)

    def init(self):
        self.stats_repo = PortScanningRepo(self.db_config)

    def module_name(self):
        return "Port Scanning"

    def on_scan_detected(self, scan_from_ip: str):
        stats_valid = self.stats.check_validity()
        if not stats_valid:
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


        self.anomaly_detector.update_counter()
        anomaly_detector_valid = self.anomaly_detector.check_validity()
        if not anomaly_detector_valid:
            self.anomaly_detector.reset_counter() 

            # TODO 1. pobierz ostatnie X średnich z bazy danych
            limit = self.anomaly_detector.maxCounter
            time_series_training_data = self.stats_repo.get_all(self, limit=limit, order='DESC')

            # TODO 2. podmień w obiekcie anomaly_detector
            self.anomaly_detector.update_time_series(time_series_training_data)

        # TODO 3. wyznacz anomalię dla tego skanu
        # ...

        packet_stats = PortScanningStats(scan_tries=1)
        self.stats.plus(scan_from_ip, packet_stats)

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
                    del self.halfscandb[tmp]
                    self.on_scan_detected(packet.to_ip)
            elif "SYN" in packet.flags and "ACK" in packet.flags and len(packet.flags) == 2:
                tmp = p_reverse_direction + "_" + str(packet.ack_no)
                self.synackdb[tmp] = p_direction + "_SYN_ACK_" + str(packet.seq_no) + "_" + str(packet.ack_no)
                del self.halfscandb[tmp]
            elif "RST" in packet.flags and len(packet.flags) == 1:
                tmp = p_direction + "_" + str(packet.ack_no - 1)
                if tmp in self.synackdb:
                    del self.synackdb[tmp]
                    self.on_scan_detected(packet.from_ip)
            elif "ACK" in packet.flags and len(packet.flags) == 1:
                tmp = p_direction + "_" + str(packet.ack_no - 1)
                if tmp in self.synackdb:
                    del self.synackdb[tmp]

        except Exception as msg:
            log_to_file("error in port scanning scan: " + str(msg))
