from typing import Tuple

from database.repo import Repo
from model.persistent_stats import PortScanningPersistentStats


class PortScanningRepo(Repo):

    def build_insert_query(self, entity: PortScanningPersistentStats) -> str:
        command = "INSERT INTO port_scanning_module_stats (time_window_start, time_window_end, mean_scans_per_addr) VALUES ('{}','{}', '{}')".format(
            entity.time_window_start, entity.time_window_end, entity.mean_scans_per_addr
        )
        return command

    def build_get_all_query(self, limit=10, offset=0) -> str:
        command = "SELECT id, time_window_start, time_window_end, mean_scans_per_addr FROM port_scanning_module_stats ORDER BY time_window_start LIMIT {} OFFSET {}".format(
            limit, offset)
        return command

    def entity_from_tuple(self, tuple: Tuple) -> PortScanningPersistentStats:
        (id, time_window_start, time_window_end, mean_scans_per_addr) = tuple
        return PortScanningPersistentStats(id, time_window_start, time_window_end, mean_scans_per_addr)
