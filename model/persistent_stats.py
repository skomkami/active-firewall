from dataclasses import dataclass
from datetime import datetime


@dataclass
class PersistentStats:
    id: int
    time_window_start: datetime
    time_window_end: datetime


@dataclass
class DosModuleStats(PersistentStats):
    mean_packets_per_addr: float
    mean_packets_size_per_addr: float


@dataclass
class BruteForceModuleStats(PersistentStats):
    mean_tries_per_addr: float


@dataclass
class PortScanningModuleStats(PersistentStats):
    mean_scans_per_addr: float
