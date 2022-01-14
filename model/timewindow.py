from dataclasses import dataclass
from datetime import datetime


@dataclass
class TimeWindow:
    start: datetime
    end: datetime
