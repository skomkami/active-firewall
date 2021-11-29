from dataclasses import dataclass
from datetime import datetime
from enum import Enum

class ModuleName(Enum):
  DOS_MODULE = "DOS_MODULE"
  BRUTEFORCE_MODULE = "BRUTEFORCE_MODULE"
  PORTSCANNING_MODULE = "PORTSCANNING_MODULE"

@dataclass
class Detection:
  detection_time: datetime
  attacker_ip_address: str
  module_name: ModuleName
  note: str
  detection_id: int = None