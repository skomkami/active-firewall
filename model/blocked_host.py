from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class BlockState(Enum):
    BLOCKED = "BLOCKED"
    UNBLOCKED = "UNBLOCKED"


@dataclass
class BlockedHost:
    ip_address: str
    state_since: datetime
    state: BlockState = BlockState.BLOCKED
    note: str = None
    block_id: int = None
