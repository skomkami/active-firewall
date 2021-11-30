from dataclasses import dataclass
from datetime import datetime
from typing import Tuple

@dataclass
class Packet:
  arrival_time: datetime
  from_ip: str
  to_ip: str
  from_mac: str
  to_mac: str
  from_port: int
  to_port: int
  seq_no: int
  ack_no: int
  size: int
  flags: Tuple