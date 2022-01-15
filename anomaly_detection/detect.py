from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

from config.config import AnomalyDetectorConf


class AnomalyDetector():

    def __init__(self, anomaly_detector_config: AnomalyDetectorConf):
        self.counter = 0
        self.maxCounter = anomaly_detector_config.maxCounter
        self.outliers_fraction = anomaly_detector_config.outliers_fraction
        self.time_series = None

    def update_counter(self):
        self.counter += 1

    def reset_counter(self):
        self.counter = 0

    def check_validity(self) -> bool:
        if self.counter >= self.maxCounter or self.time_series == None:
            return False
        else:
            return True

    def update_time_series(self, entities: list()):

        # convert data queried from database to DataFrame object indexed with Timestamps
        timestamps = []
        values = []
        for e in entities:
            timestamps.append(e.time_window.end)
            values.append(e.mean_scans_per_addr)
        self.time_series = pd.DataFrame(values, index = timestamps, columns =['Total'])

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


# =========== TESTY ============
# def get_mocked_stats_db() -> dict:
#     return {
#         "16.32.312.13": 12900,
#         "28.213.123.2": 30000,
#         "32.132.123.23": 13000,
#     }

# def parser(s):
#     return datetime.strptime(s, '%Y-%m-%d')

# def get_mocked_persistent_stats_for_period() -> pd.DataFrame:
#     catfish_sales = pd.read_csv('catfish.csv', parse_dates=[0], index_col=0, date_parser=parser)
#     catfish_sales = catfish_sales.asfreq(pd.infer_freq(catfish_sales.index))
#     return catfish_sales
            

# if __name__ == "__main__":

#     # TODO: jako idx przekazujemy timestamp dla tego okna czasowego, w którym badamy anomalie
#     timestamp = pd.ts = pd.Timestamp(year = 2013,  month = 1, day = 1,
#            hour = 0, second = 0, tz = 'US/Central')

#     # TODO: przekazujemy słownik słownik hostów i odebranych pakietów dla nich
#     stats_db = get_mocked_stats_db()

#     anomaly_detector = AnomalyDetector()
#     anomaly_detector.stats_for_period = get_mocked_persistent_stats_for_period()
#     anomaly_detector.outliers_fraction = float(0.02)


#     hosts_to_block = anomaly_detector.detect_anomalies(timestamp, stats_db)
#     for host in hosts_to_block:
#         print("Block", host)
