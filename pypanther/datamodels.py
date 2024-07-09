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
    def _description(self) -> Optional[str]:
        pass

    @abc.abstractmethod
    def _enabled(self) -> bool:
        pass


class Kubernetes(DataModel):

    def _description(self) -> Optional[str]:
        return "Kubernetes Data Model"

    def _enabled(self) -> bool:
        return True

    labels = DataModelMapping(field=EKSAudit.annotations)

def generate_yaml_for_datamodel_subclasses():
    subclasses_yaml = []
    for cls in DataModel.__subclasses__():
        cls_instance = cls()
        data_model_dict = {
            "ID": cls.__name__,
            "Description": cls_instance._description() if cls_instance._description() else "No Description",
            "Enabled": cls_instance._enabled(),
            "DataModelMappings": {}
        }
        attributes = [attr for attr in dir(cls_instance) if not callable(getattr(cls_instance, attr)) and not attr.startswith('__')]
        for attr in attributes:
            if hasattr(cls_instance, attr):
                data_model_dict["DataModelMappings"][attr] = getattr(cls_instance, attr)
        if hasattr(cls_instance, 'labels'):
            data_model_dict["DataModelMappings"]["LogType"] = "EKSAudit"  # Assuming fixed value for demonstration
            data_model_dict["DataModelMappings"]["Field"] = cls_instance.labels.field if cls_instance.labels.field else "No Field"
        subclasses_yaml.append(yaml.dump(data_model_dict, sort_keys=False))
    return subclasses_yaml