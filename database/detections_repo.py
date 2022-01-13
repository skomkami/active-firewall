from database.repo import Repo
from model.detection import Detection, ModuleName
from typing import Tuple


class DetectionRepo(Repo):

    def build_insert_query(self, entity) -> str:
        command = "INSERT INTO detections (detection_time,attacker_ip_address,module_name,note) VALUES ('{}','{}', '{}', '{}')".format(
            str(entity.detection_time), entity.attacker_ip_address, entity.module_name.name, entity.note
        )
        return command

    def build_get_all_query(self, limit=10, offset=0) -> str:
        command = "SELECT detection_time, attacker_ip_address, module_name, note, detection_id FROM detections ORDER BY detection_time LIMIT {} OFFSET {}".format(
            limit, offset)
        return command

    def entity_from_tuple(self, tuple: Tuple) -> Detection:
        (detection_time, attacker_ip_address, module_name, note, id) = tuple
        return Detection(detection_time, attacker_ip_address, ModuleName(module_name), note, id)
