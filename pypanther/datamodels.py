import abc
from typing import Optional

from attr import dataclass


@dataclass
class PantherDataModel(metaclass=abc.ABCMeta):
    Name: str
    Description: Optional[str] = None
    Enabled: bool = False



