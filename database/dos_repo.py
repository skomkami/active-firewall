from typing import Tuple

from database.repo import Repo
from model.persistent_stats import DosModuleStats


class DosRepo(Repo):

    def build_insert_query(self, entity: DosModuleStats) -> str:
        command = "INSERT INTO dos_module_stats (time_window_start, time_window_end, mean_packets_per_addr, mean_packets_size_per_addr) VALUES ('{}','{}', '{}', '{}')".format(
            entity.time_window_start, entity.time_window_end, entity.mean_packets_per_addr, entity.mean_packets_size_per_addr
        )
        return command

    def build_get_all_query(self, limit=10, offset=0) -> str:
        command = "SELECT id, time_window_start, time_window_end, mean_packets_per_addr, mean_packets_size_per_addr FROM dos_module_stats ORDER BY detection_time LIMIT {} OFFSET {}".format(
            limit, offset)
        return command

    def entity_from_tuple(self, tuple: Tuple) -> DosModuleStats:
        (id, time_window_start, time_window_end, mean_packets_per_addr, mean_packets_size_per_addr) = tuple
        return DosModuleStats(id, time_window_start, time_window_end, mean_packets_per_addr, mean_packets_size_per_addr)
