from typing import Tuple

from database.repo import Repo
from model.persistent_stats import BruteForcePersistentStats
from model.timewindow import TimeWindow


class BruteForceRepo(Repo):

    def build_insert_query(self, entity: BruteForcePersistentStats) -> str:
        command = "INSERT INTO brute_force_module_stats (time_window_start, time_window_end, mean_attempts_per_addr) VALUES ('{}','{}', '{}')".format(
            entity.time_window.start, entity.time_window.end, entity.mean_attempts_per_addr
        )
        return command

    def build_get_all_query(self, limit=10, offset=0, where_clause='id IS NOT NULL', order='ASC') -> str:
        command = "SELECT id, time_window_start, time_window_end, mean_attempts_per_addr FROM brute_force_module_stats WHERE {} ORDER BY time_window_start {} LIMIT {} OFFSET {}".format(
            where_clause, order, limit, offset)
        return command

    def entity_from_tuple(self, tuple: Tuple) -> BruteForcePersistentStats:
        (id, time_window_start, time_window_end, mean_attempts_per_addr) = tuple
        return BruteForcePersistentStats(id, TimeWindow(time_window_start, time_window_end), mean_attempts_per_addr)
