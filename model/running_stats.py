from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from config.config import Periodicity, PeriodicityUnit
from utils.utils import debug


def seconds_of(periodicity: Periodicity):
    unit_to_seconds = 1
    if periodicity['unit'] == PeriodicityUnit.Minute:
        unit_to_seconds = 60
    elif periodicity['unit'] == PeriodicityUnit.Hour:
        unit_to_seconds = 60 * 60
    else:
        unit_to_seconds = 60 * 60 * 24
    return unit_to_seconds * periodicity['multiplier']


class ModuleStats(ABC):
    def plus(self, other: ModuleStats) -> ModuleStats:
        raise NotImplementedError

    def reset(self) -> ModuleStats:
        raise NotImplementedError


@dataclass
class RunningStatsAccumulator(ABC):
    since: datetime
    # address:str -> ModuleStats TODO typing
    statsDb: dict

    @abstractmethod
    def empty_stats(self) -> ModuleStats:
        raise NotImplementedError

    def reset(self, date: datetime):
        self.statsDb = {}
        self.since = date


    def plus(self, address: str, other: ModuleStats):
        self.statsDb.setdefault(address, self.empty_stats()).plus(other)

    def check_validity(self, periodicity: Periodicity) -> bool:
        now = datetime.now()
        counter_valid_to = self.since + timedelta(seconds=seconds_of(periodicity))
        if now > counter_valid_to:
            return False
        return True
