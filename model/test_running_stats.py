import unittest

from config.config import Periodicity, PeriodicityUnit
from scanning.port_scanning_detector import PortScanningRunningStats, PortScanningStats
from datetime import datetime, timedelta

periodicity = Periodicity()
periodicity.unit = PeriodicityUnit.Second
periodicity.multiplier = 10


class TestStats(unittest.TestCase):
    def setUp(self):
        date = datetime(year=2022, month=1, day=10, hour=0, minute=0, second=0)
        self.stats = PortScanningRunningStats.init(date, periodicity)
        increment = PortScanningStats(4)
        ip = '192.168.1.1'
        self.stats.plus(ip, increment)


class RunningStatsUnitTest(TestStats):

    def test_plus(self):
        ip = '192.168.1.1'
        increment = PortScanningStats(2)
        self.stats.plus(ip, increment)
        assert self.stats.stats_db[ip].scan_tries == 6

    def test_check_validity_false(self):
        date = datetime(year=2022, month=1, day=10, hour=0, minute=0, second=20)
        valid = self.stats.check_validity(date)
        assert not valid

    def test_check_validity_true(self):
        date = datetime(year=2022, month=1, day=10, hour=0, minute=0, second=9)
        valid = self.stats.check_validity(date)
        assert valid

    def test_forward(self):
        date = datetime(year=2022, month=1, day=10, hour=0, minute=2, second=22, microsecond=49)
        empty_windows = self.stats.forward(date)
        new_since = self.stats.since
        assert len(empty_windows) == 13
        assert new_since == datetime(year=2022, month=1, day=10, hour=0, minute=2, second=20)

    def test_mean(self):
        ip = '192.168.1.1'
        increment = PortScanningStats(2)
        self.stats.plus(ip, increment)
        ip2 = '40.12.12.1'
        increment2 = PortScanningStats(3)
        self.stats.plus(ip2, increment2)
        mean = self.stats.calc_mean()
        assert mean.mean_scans_per_addr == 4.5


if __name__ == '__main__':
    unittest.main()
