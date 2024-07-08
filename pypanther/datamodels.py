import abc
import dataclasses
from typing import Optional, Any

from .schema import SplitTransform, EKSAudit


@dataclasses.dataclass
class DataModelMapping:
    field: Any = None
    transform: [SplitTransform] = None


class DataModel(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def _description(cls) -> Optional[str]:
        pass

    @abc.abstractmethod
    def _enabled(cls) -> bool:
        pass


class Kubernetes(DataModel):
    def _description(cls) -> Optional[str]:
        return "Kubernetes Data Model"

    def _enabled(cls) -> bool:
        return True

    annotations = DataModelMapping(field=EKSAudit.annotations)
