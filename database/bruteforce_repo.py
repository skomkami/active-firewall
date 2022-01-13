from typing import Tuple

from database.repo import Repo
from model.persistent_stats import BruteForcePersistentStats


class BruteForceRepo(Repo):

    def build_insert_query(self, entity: BruteForcePersistentStats) -> str:
        command = "INSERT INTO brute_force_module_stats (time_window_start, time_window_end, mean_tries_per_addr) VALUES ('{}','{}', '{}')".format(
            entity.time_window_start, entity.time_window_end, entity.mean_tries_per_addr
        )
        return command

    def build_get_all_query(self, limit=10, offset=0) -> str:
        command = "SELECT id, time_window_start, time_window_end, mean_tries_per_addr FROM brute_force_module_stats ORDER BY time_window_start LIMIT {} OFFSET {}".format(
            limit, offset)
        return command

    def entity_from_tuple(self, tuple: Tuple) -> BruteForcePersistentStats:
        (id, time_window_start, time_window_end, mean_tries_per_addr) = tuple
        return BruteForcePersistentStats(id, time_window_start, time_window_end, mean_tries_per_addr)
