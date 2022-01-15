import numpy as np
import pandas as pd

from datetime import datetime
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest


# ===== do testów =====
def get_mocked_stats_db() -> dict:
    return {
        "16.32.312.13": 12900,
        "28.213.123.2": 30000,
        "32.132.123.23": 13000,
    }

def parser(s):
    return datetime.strptime(s, '%Y-%m-%d')

def get_mocked_persistent_stats_for_period() -> pd.DataFrame:
    catfish_sales = pd.read_csv('catfish.csv', parse_dates=[0], index_col=0, date_parser=parser)
    catfish_sales = catfish_sales.asfreq(pd.infer_freq(catfish_sales.index))
    return catfish_sales


# ===== właściwy kod =====
def detect_anomalies(timestamp: pd.Timestamp, stats_db: dict(), stats_for_period: pd.DataFrame, outliers_fraction = float(.02)) -> pd.DataFrame:
    
    hosts_to_block = []
    for host_address in stats_db:

        df = stats_for_period.copy()
        df = df.append(pd.DataFrame({'Total': stats_db[host_address]}, index=[timestamp]))

        # scale values
        scaler = StandardScaler()
        np_scaled = scaler.fit_transform(df.values.reshape(-1, 1))
        data = pd.DataFrame(np_scaled)

        # train isolation forest
        model = IsolationForest(contamination=outliers_fraction)
        model.fit(data) 

        # get anomalies
        df['anomaly'] = model.predict(data)
        df_with_anomaly = df.loc[df['anomaly'] == -1, ['Total']]

        if not df_with_anomaly.empty: 
            if df_with_anomaly.index[-1] == timestamp:
                hosts_to_block.append(host_address)

    return hosts_to_block
            

if __name__ == "__main__":

    # TODO: jako idx przekazujemy timestamp dla tego okna czasowego, w którym badamy anomalie
    timestamp = pd.ts = pd.Timestamp(year = 2013,  month = 1, day = 1,
           hour = 0, second = 0, tz = 'US/Central')

    # TODO: przekazujemy słownik słownik hostów i odebranych pakietów dla nich
    stats_db = get_mocked_stats_db()

    # TODO: tutaj przekazujemy zaczytane z bazy danych średnie dla okien czasowych mieszczących się w danym okresie
    stats_for_period = get_mocked_persistent_stats_for_period()

    # TODO: to chyba ustalamy w configu, tbh nie wiem jak to dobrze ustalać, do przemyślenia
    outliers_fraction = float(0.02)

    hosts_to_block = detect_anomalies(timestamp, stats_db, stats_for_period, outliers_fraction)
    for host in hosts_to_block:
        print("Block", host)


    