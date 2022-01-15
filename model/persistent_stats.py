from dataclasses import dataclass

from model.timewindow import TimeWindow


@dataclass
class PersistentStats:
    id: int
    time_window: TimeWindow


@dataclass
class DosPersistentStats(PersistentStats):
    mean_packets_per_addr: float = 0
    mean_packets_size_per_addr: float = 0


@dataclass
class BruteForcePersistentStats(PersistentStats):
    mean_attempts_per_addr: float = 0


@dataclass
class PortScanningPersistentStats(PersistentStats):
    mean_scans_per_addr: float = 0
