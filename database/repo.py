from typing import Tuple

import psycopg2

from config.config import DBConnectionConf
from utils.utils import debug
from abc import abstractmethod


class Repo:
    def __init__(self, dbConnectionConf: DBConnectionConf) -> None:
        self.conn = None
        try:
            self.conn = psycopg2.connect(
                dbname=dbConnectionConf.dbname,
                user=dbConnectionConf.user,
                password=dbConnectionConf.password,
                host=dbConnectionConf.host,
                port=dbConnectionConf.port
            )

        except (Exception, psycopg2.DatabaseError) as error:
            debug(str(error))

    def __exit__(self, exc_type, exc_value, traceback):
        if self.conn is not None:
            self.conn.close()

    @abstractmethod
    def build_insert_query(self, entity) -> str:
        raise NotImplementedError

    def add(self, entity):
        command = self.build_insert_query(entity)
        cur = self.conn.cursor()
        cur.execute(command)
        cur.close()
        self.conn.commit()

    def entity_from_tuple(self, tuple: Tuple) -> object:
        raise NotImplementedError

    @abstractmethod
    def build_get_all_query(self, limit=10, offset=0) -> str:
        raise NotImplementedError

    def get_all(self, limit=10, offset=0):
        command = self.build_get_all_query(limit, offset)
        cur = self.conn.cursor()
        cur.execute(command)
        content = cur.fetchall()
        cur.close()
        self.conn.commit()
        entities = list(map(self.entity_from_tuple, content))
        return entities
