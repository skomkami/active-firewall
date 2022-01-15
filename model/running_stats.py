from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List

from config.config import Periodicity
from model.timewindow import TimeWindow
from utils.log import log_to_file


class ModuleStats(ABC):
    def plus(self, other: ModuleStats) -> ModuleStats:
        raise NotImplementedError


@dataclass
class RunningStatsAccumulator(ABC):
    since: datetime
    # address:str -> ModuleStats TODO typing
    stats_db: dict
    periodicity: Periodicity

    @abstractmethod
    def empty_stats(self) -> ModuleStats:
        raise NotImplementedError

    def reset(self, date: datetime):
        self.stats_db = {}
        self.since = date

    def until(self) -> datetime:
        return self.since + timedelta(seconds=self.periodicity.seconds()) - timedelta(microseconds=1)

    def plus(self, address: str, other: ModuleStats):
        self.stats_db.setdefault(address, self.empty_stats()).plus(other)

    def check_validity(self) -> bool:
        now = datetime.now()
        # debug("now: " + str(now) + ', valid to: ' + str(counter_valid_to))
        if now > self.until():
            return False
        return True

    def forward(self, to_date: datetime) -> List[TimeWindow]:
        """Adjust window to to_date and return empty TimeWindow-s between."""
        empty_windows: List[TimeWindow] = []
        self.since += timedelta(seconds=self.periodicity.seconds())
        while self.until() < to_date:
            new_window = TimeWindow(self.since, self.until())
            empty_windows.append(new_window)
            self.since += timedelta(seconds=self.periodicity.seconds())
        self.reset(self.since)

        return empty_windows
