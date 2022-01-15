from config.config import DBConnectionConf
from database.repo import Repo
from model.blocked_host import BlockedHost, BlockState
from typing import Tuple


class BlockedHostRepo(Repo):

    def __init__(self, db_connection_conf: DBConnectionConf) -> None:
        super().__init__(db_connection_conf)
        self.db_fields = "ip_address,state_since,state,note"

    def build_insert_query(self, entity: BlockedHost) -> str:
        command = "INSERT INTO blocked_hosts ({}) VALUES ('{}','{}', '{}', '{}')".format(
            self.db_fields, entity.ip_address, str(entity.state_since), entity.state.name, entity.note
        )
        return command

    def build_get_all_query(self, limit=10, offset=0) -> str:
        command = "SELECT {},block_id FROM blocked_hosts ORDER BY state_since DESC LIMIT {} OFFSET {}".format(
            self.db_fields, limit, offset)
        return command

    def entity_from_tuple(self, tuple: Tuple) -> BlockedHost:
        (ip_address, state_since, block_state, note, block_id) = tuple
        return BlockedHost(ip_address, state_since, BlockState(block_state), note, block_id)

    def get_block_for(self, ip: str):
        command = "SELECT {},block_id FROM blocked_hosts WHERE ip_address = {}".format(self.db_fields, ip)
        cur = self.conn.cursor()
        cur.execute(command)
        content = cur.fetchone()
        cur.close()
        self.conn.commit()
        if len(content) > 0:
            return self.entity_from_tuple(content[0])
        else:
            return None

    def update_field_for_ip(self, ip: str, field: str, value: str):
        command = "UPDATE blocked_hosts SET {}={} WHERE ip_address = {}".format(field, value, ip)
        cur = self.conn.cursor()
        cur.execute(command)
        cur.close()
        self.conn.commit()
