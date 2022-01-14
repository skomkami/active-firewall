from typing import Tuple

from database.repo import Repo
from model.persistent_stats import DosPersistentStats
from model.timewindow import TimeWindow


class DosRepo(Repo):

    def build_insert_query(self, entity: DosPersistentStats) -> str:
        command = "INSERT INTO dos_module_stats (time_window_start, time_window_end, mean_packets_per_addr, mean_packets_size_per_addr) VALUES ('{}','{}', '{}', '{}')".format(
            entity.time_window.start, entity.time_window.end, entity.mean_packets_per_addr, entity.mean_packets_size_per_addr
        )
        return command

    def build_get_all_query(self, limit=10, offset=0, where_clause='id IS NOT NULL', order='ASC') -> str:
        command = "SELECT id, time_window_start, time_window_end, mean_packets_per_addr, mean_packets_size_per_addr FROM dos_module_stats WHERE {} ORDER BY detection_time {} LIMIT {} OFFSET {}".format(
            where_clause, order, limit, offset)
        return command

    def entity_from_tuple(self, tuple: Tuple) -> DosPersistentStats:
        (id, time_window_start, time_window_end, mean_packets_per_addr, mean_packets_size_per_addr) = tuple
        return DosPersistentStats(id, TimeWindow(time_window_start, time_window_end), mean_packets_per_addr, mean_packets_size_per_addr)
