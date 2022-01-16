from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import reduce

from analysepackets.abstract_analyse_packets import AbstractAnalysePackets
from anomaly_detection.detect import AnomalyDetector
from config.config import DBConnectionConf, DoSModuleConf, Periodicity, AnomalyDetectorConf
from database.blocked_hosts_repo import BlockedHostRepo
from database.detections_repo import DetectionRepo
from database.dos_repo import DosRepo
from ip_access_manager.manager import IPAccessManager
from model.blocked_host import BlockedHost
from model.detection import Detection, ModuleName
from model.packet import Packet
from model.persistent_stats import DosPersistentStats
from model.running_stats import RunningStatsAccumulator, ModuleStats
from model.timewindow import TimeWindow
from utils.log import log_to_file


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
        new_acc = DosRunningStats(since=date, stats_db={}, periodicity=periodicity)
        return new_acc

    def calc_mean(self) -> DosPersistentStats:
        total = len(self.stats_db)
        time_window = TimeWindow(start=self.since, end=self.until())
        if total > 0:
            stats_sum = reduce(lambda a, b: a.plus(b), self.stats_db.values())
            mean_stats = DosPersistentStats(
                id=None,
                time_window=time_window,
                mean_packets_per_addr=stats_sum.packets_no / total,
                mean_packets_size_per_addr=stats_sum.packets_size / total
            )
            return mean_stats
        else:
            return DosPersistentStats(
                id=None,
                time_window=time_window
            )


class DosAttackDetector(AbstractAnalysePackets):
    """
    This detector counts number and size of packets in chosen time windows and then decides whether current host stats
    are treated as suspicious traffic.
    """

    def __init__(self, db_config: DBConnectionConf, dos_module_conf: DoSModuleConf, anomaly_config: AnomalyDetectorConf):
        super().__init__(db_config)
        self.stats_repo = None
        self.detections_repo = None
        self.blocks_repo = None
        self.config = dos_module_conf
        self.stats = DosRunningStats.init(datetime.now(), dos_module_conf.periodicity)
        self.anomaly_detector = AnomalyDetector(anomaly_config)
        self.ip_manager = IPAccessManager()

    def init(self):
        self.stats_repo = DosRepo(self.db_config)
        self.blocks_repo = BlockedHostRepo(self.db_config)
        self.detections_repo = DetectionRepo(self.db_config)

    def module_name(self):
        return "Dos attack"

    def process_packet(self, packet: Packet):
        if packet.from_ip in ['localhost', '127.0.0.1']:
            return
        try:
            now = datetime.now()
            valid = self.stats.check_validity(now)
            if not valid:
                mean = self.stats.calc_mean()
                empty_windows = self.stats.forward(now)
                up_to_now_stats = list(
                    map(
                        lambda tw: DosPersistentStats(id=None, time_window=tw),
                        empty_windows
                    )
                )
                up_to_now_stats.insert(0, mean)
                self.stats_repo.add_many(up_to_now_stats)

            packet_stats = DosStats(1, packet.size)
            self.stats.plus(packet.from_ip, packet_stats)

            self.anomaly_detector.update_counter()
            anomaly_detector_valid = self.anomaly_detector.check_validity()
            if not anomaly_detector_valid:
                self.anomaly_detector.reset_counter()

                # get last X means from database
                limit = self.anomaly_detector.maxCounter
                time_series_training_data = self.stats_repo.get_all(limit=limit, order='DESC')

                # update time series in anomaly detector object
                self.anomaly_detector.update_time_series(time_series_training_data)

            nr_of_packets = self.stats.stats_db[packet.from_ip].scan_tries
            anomaly = self.anomaly_detector.detect_anomalies(datetime.now(), nr_of_packets)
            if anomaly:
                detection = Detection(now, packet.from_ip, ModuleName.DOS_MODULE)
                self.detections_repo.add(detection)
                block_host = BlockedHost(packet.from_ip, now)
                self.blocks_repo.add(block_host)
                self.ip_manager.block_access_from_ip(packet.from_ip)

        except Exception as msg:
            log_to_file("error in dos scan: " + str(msg))
