import psycopg2

from config.config import DBConnectionConf

def debug(str1: str):
  fileName = "test.txt"
  with open(fileName, 'a') as file:
      file.write(str1)
      file.write('\n')

class DetectionRepo:
  def __init__(self, dbConnectionConf: DBConnectionConf) -> None:
    self.conn = None
    try:
      self.conn = psycopg2.connect(
        dbname = dbConnectionConf.dbname,
        user = dbConnectionConf.user,
        password = dbConnectionConf.password,
        host = "localhost",
        port = dbConnectionConf.port
      )

    except (Exception, psycopg2.DatabaseError) as error:
      debug(str(error))

  def __exit__(self, exc_type, exc_value, traceback):
    if self.conn is not None:
        self.conn.close()

  def add(self, detectionInfo: str):
    command = "INSERT INTO detections (info) VALUES ({})".format(detectionInfo)
    cur = self.conn.cursor()
    cur.execute(command)
    cur.close()
    self.conn.commit()

  def get_all(self, limit = 10, offset = 0):
    command = "SELECT * FROM detections LIMIT {} OFFSET {}".format(limit, offset)
    cur = self.conn.cursor()
    cur.execute(command)
    content = cur.fetchall()
    cur.close()
    self.conn.commit()
    return content