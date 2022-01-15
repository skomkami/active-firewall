from logging import logThreads
from typing import Tuple, List

import psycopg2

from config.config import DBConnectionConf
from utils.log import log_to_file
from abc import abstractmethod
import sys

class Repo:
    def __init__(self, dbConnectionConf: DBConnectionConf) -> None:
        self.conn = None
        self.config = dbConnectionConf
        try:
            self.conn = psycopg2.connect(
                dbname=self.config.dbname,
                user=self.config.user,
                password=self.config.password,
                host=self.config.host,
                port=self.config.port
            )
        except (Exception, psycopg2.DatabaseError) as error:
            log_to_file(str(error))
        # except:
        #     log_to_file("something bad happended. " + sys.exc_info()[0])

    def __exit__(self, exc_type, exc_value, traceback):
        if self.conn is not None:
            self.conn.close()

    @abstractmethod
    def build_insert_query(self, entity) -> str:
        raise NotImplementedError

    def add(self, entity):
        if entity.attacker_ip_address in (self.config.host, self.config.host_ip):
            return
        command = self.build_insert_query(entity)
        cur = self.conn.cursor()
        cur.execute(command)
        cur.close()
        self.conn.commit()

    def add_many(self, entities: List[object]):
        commands = list(map(lambda ent: self.build_insert_query(ent), entities))
        cur = self.conn.cursor()
        for command in commands:
            cur.execute(command)
        cur.close()
        self.conn.commit()

    def entity_from_tuple(self, tuple: Tuple) -> object:
        raise NotImplementedError

    @abstractmethod
    def build_get_all_query(self, limit=10, offset=0, where_clause='detection_id IS NOT NULL', order='ASC') -> str:
        raise NotImplementedError

    def get_all(self, limit=10, offset=0, where_clause='detection_id IS NOT NULL', order='ASC'):
        command = self.build_get_all_query(limit, offset, where_clause, order)
        cur = self.conn.cursor()
        cur.execute(command)
        content = cur.fetchall()
        cur.close()
        self.conn.commit()
        entities = list(map(self.entity_from_tuple, content))
        return entities
