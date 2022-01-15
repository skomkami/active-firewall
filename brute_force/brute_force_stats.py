from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import reduce

from config.config import Periodicity
from model.running_stats import RunningStatsAccumulator, ModuleStats
from model.timewindow import TimeWindow
from model.persistent_stats import BruteForcePersistentStats
from config.config import ServiceConfig

def logg(txt: str):
    with open('brute_force/logs.txt', 'a') as f:
        print(txt, file=f)

@dataclass
class BruteForceStats(ModuleStats):
    login_attempts: int = 0

    def plus(self, other: BruteForceStats) -> BruteForceStats:
        self.login_attempts += other.login_attempts
        return self
    
    
@dataclass
class BruteForceRunningStats(RunningStatsAccumulator):
    def empty_stats(self) -> BruteForceStats:
        return BruteForceStats()

    @staticmethod
    def init(date: datetime, periodicity: Periodicity):
        new_acc = BruteForceRunningStats(since=date, stats_db={}, periodicity=periodicity)
        return new_acc

    def check_rules(self, address: str, config: ServiceConfig) -> bool:
        stats_for_address = self.stats_db[address]
        return stats_for_address.login_attempts > config.attemptLimit

    def calc_mean(self) -> BruteForcePersistentStats:
        total = len(self.stats_db)
        time_window = TimeWindow(start=self.since, end=self.until())
        if total > 0:
            stats_sum = reduce(lambda a, b: a.plus(b), self.stats_db.values())
            mean_stats = BruteForcePersistentStats(
                id=None,
                time_window=time_window,
                mean_attempts_per_addr=stats_sum.login_attempts/total
            )
            return mean_stats
        else:
            return BruteForcePersistentStats(
                id=None,
                time_window=time_window
            )
        