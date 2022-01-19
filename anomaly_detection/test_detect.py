from unittest import TestCase
from datetime import datetime
import pandas as pd

from anomaly_detection.detect import AnomalyDetector
from config.config import AnomalyDetectorConf
from model.persistent_stats import PersistentStats, PortScanningPersistentStats
from model.timewindow import TimeWindow


class TestAnomalyDetector(TestCase):

    def setUp(self) -> None:
        conf = AnomalyDetectorConf()
        self.anomaly_detector = AnomalyDetector(conf)

        # read test data from .csv file
        self.stats = []
        f = open("test_detect_data.csv", "r")
        lines = f.readlines()
        for i in range(1, len(lines)):
            # create TimeWindow object
            start = datetime.strptime(lines[i - 1].split(',')[0], "%Y-%m-%d %H:%M:%S")
            end = datetime.strptime(lines[i].split(',')[0], "%Y-%m-%d %H:%M:%S")
            time_window = TimeWindow(start, end)

            # create PortScanningPersistentStats object
            id = i
            mean_scans_per_addr = float(lines[i].split(',')[1][:-1])
            self.stats.append(PortScanningPersistentStats(id, time_window, mean_scans_per_addr))
        f.close()

    def test_update_counter(self):
        counter_before_update = self.anomaly_detector.counter

        no_of_updates = 5
        for i in range(no_of_updates):
            self.anomaly_detector.update_counter()

        counter_after_update = self.anomaly_detector.counter
        assert counter_before_update + no_of_updates == counter_after_update

    def test_reset_counter(self):
        no_of_updates = 5
        for i in range(no_of_updates):
            self.anomaly_detector.update_counter()
        assert self.anomaly_detector.counter == no_of_updates

        self.anomaly_detector.reset_counter()
        assert self.anomaly_detector.counter == 0

    def test_check_validity_true(self):
        self.anomaly_detector.update_time_series(self.stats)
        assert self.anomaly_detector.check_validity()

    def test_check_validity_false_max_counter_exceedence(self):
        self.anomaly_detector.update_time_series(self.stats)
        assert self.anomaly_detector.check_validity()

        no_of_updates_to_exceed_max_counter = self.anomaly_detector.maxCounter + 1
        for i in range(no_of_updates_to_exceed_max_counter):
            self.anomaly_detector.update_counter()

        assert not self.anomaly_detector.check_validity()

    def test_check_validity_false_none_time_series(self):
        self.assertEqual(self.anomaly_detector.check_validity(), False)

    def test_update_time_series(self):
        self.anomaly_detector.update_time_series(self.stats)

        df = pd.read_csv('test_detect_data.csv', parse_dates=[0], index_col=0, date_parser=lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S'), dtype=float)
        df.index.name = None
        df = df.rename(columns={'9034': 'Total'})
        assert self.anomaly_detector.time_series.equals(df) == True

    def test_detect_anomalies_true(self):
        self.anomaly_detector.update_time_series(self.stats)

        nr_of_packets_anomaly = 30000
        datetime = '2022-01-19 12:05:23'
        is_anomaly = self.anomaly_detector.detect_anomalies(datetime, nr_of_packets_anomaly)

        assert is_anomaly

    def test_detect_anomalies_false(self):
        self.anomaly_detector.update_time_series(self.stats)

        nr_of_packets_non_anomaly = 11000
        datetime = '2022-01-19 12:05:23'
        is_anomaly = self.anomaly_detector.detect_anomalies(datetime, nr_of_packets_non_anomaly)

        assert not is_anomaly

    def test_detect_anomalies_false_empty_time_series(self):
        self.anomaly_detector.update_time_series(self.stats)

        nr_of_packets_anomaly = 30000
        datetime = '2022-01-19 12:05:23'
        is_anomaly = self.anomaly_detector.detect_anomalies(datetime, nr_of_packets_anomaly)
        assert is_anomaly

        self.anomaly_detector.time_series = pd.DataFrame()
        is_anomaly = self.anomaly_detector.detect_anomalies(datetime, nr_of_packets_anomaly)
        assert not is_anomaly
