import abc
from typing import Optional

from attr import dataclass


@dataclass
class DataModel(metaclass=abc.ABCMeta):
    id: str
    description: Optional[str] = None
    enabled: bool = False






