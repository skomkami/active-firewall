from abc import abstractmethod
from typing import Tuple, List

import psycopg2

from config.config import DBConnectionConf
from utils.log import log_to_file


class Repo:
    """
    Base class for all repositories. Its purpose is to reduce boilerplate code.
    """
    
    def __init__(self, db_connection_conf: DBConnectionConf) -> None:
        self.conn = None
        try:
            self.conn = psycopg2.connect(
                dbname=db_connection_conf.dbname,
                user=db_connection_conf.user,
                password=db_connection_conf.password,
                host=db_connection_conf.host,
                port=db_connection_conf.port
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
