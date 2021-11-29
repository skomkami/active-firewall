import psycopg2

from config.config import DBConnectionConf
from model.detection import Detection

def debug(str: str):
  fileName = "test.txt"
  with open(fileName, 'a') as file:
      file.write(str)
      file.write('\n')

class DetectionRepo:
  def __init__(self, dbConnectionConf: DBConnectionConf) -> None:
    self.conn = None
    try:
      self.conn = psycopg2.connect(
        dbname = dbConnectionConf.dbname,
        user = dbConnectionConf.user,
        password = dbConnectionConf.password,
        host = dbConnectionConf.host,
        port = dbConnectionConf.port
      )

    except (Exception, psycopg2.DatabaseError) as error:
      debug(str(error))

  def __exit__(self, exc_type, exc_value, traceback):
    if self.conn is not None:
        self.conn.close()

  def add(self, detection: Detection):
    command = "INSERT INTO detections (detection_time,attacker_ip_address,module_name,note) VALUES ('{}','{}', '{}', '{}')".format(
      str(detection.detection_time), detection.attacker_ip_address, detection.module_name.name, detection.note
    )
    cur = self.conn.cursor()
    cur.execute(command)
    cur.close()
    self.conn.commit()

  def get_all(self, limit = 10, offset = 0):
    command = "SELECT * FROM detections LIMIT {} OFFSET {} ORDERY BY detection_time".format(limit, offset)
    cur = self.conn.cursor()
    cur.execute(command)
    content = cur.fetchall()
    cur.close()
    self.conn.commit()
    return content