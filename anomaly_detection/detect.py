from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

from config.config import AnomalyDetectorConf
from model.persistent_stats import DosPersistentStats, BruteForcePersistentStats, PortScanningPersistentStats

from utils.log import log_to_file


class AnomalyDetector:

    def __init__(self, anomaly_detector_config: AnomalyDetectorConf):
        self.counter = 0
        self.maxCounter = anomaly_detector_config.maxCounter
        self.outliers_fraction = anomaly_detector_config.outliersFraction
        self.time_series = None

    def update_counter(self):
        self.counter += 1

    def reset_counter(self):
        self.counter = 0

    def check_validity(self) -> bool:
        return not (self.counter >= self.maxCounter or self.time_series is None)

    def update_time_series(self, entities: list()):

        # convert data queried from database to DataFrame object indexed with Timestamps
        timestamps = []
        values = []
        for e in entities:
            if isinstance(e, DosPersistentStats):
                values.append(e.mean_packets_per_addr)
            elif isinstance(e, BruteForcePersistentStats):
                values.append(e.mean_attempts_per_addr)
            elif isinstance(e, PortScanningPersistentStats):
                values.append(e.mean_scans_per_addr)
            else:
                continue
            timestamps.append(e.time_window.end)
        self.time_series = pd.DataFrame(values, index=timestamps, columns=['Total'])

    def detect_anomalies(self, now: datetime, stats: int) -> bool:

        df = self.time_series.copy()
        df = df.append(pd.DataFrame({'Total': stats}, index=[now]))

        # scale values
        scaler = StandardScaler()
        np_scaled = scaler.fit_transform(df.values.reshape(-1, 1))
        data = pd.DataFrame(np_scaled)

        # train isolation forest
        model = IsolationForest(contamination=self.outliers_fraction)
        model.fit(data)

        # get anomalies
        df['anomaly'] = model.predict(data)
        df_with_anomaly = df.loc[df['anomaly'] == -1, ['Total']]

        if df_with_anomaly.index[-1] == now:
            if df.iloc[-1]['Total'] > df.iloc[-2]['Total']:
                return True
        else:
            return False
