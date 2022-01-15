from dataclasses import dataclass
from datetime import datetime
from enum import Enum

class ModuleName(Enum):
  DOS_MODULE = "DOS_MODULE"
  PORTSCANNING_MODULE = "PORTSCANNING_MODULE"
  APACHE2_LOGIN_DETECTOR = "APACHE2_LOGIN_DETECTOR"
  SSH_LOGIN_DETECTOR = "SSH_LOGIN_DETECTOR"
  IMAP_POP3_LOGIN_DETECTOR = "IMAP_POP3_LOGIN_DETECTOR"


@dataclass
class Detection:
  detection_time: datetime
  attacker_ip_address: str
  module_name: ModuleName
  note: str
  detection_id: int = None