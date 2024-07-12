from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardOCSFNetworkActivity(PantherDataModel):
    id_: str = "Standard.OCSF.NetworkActivity"
    display_name: str = "OCSF Network Activity"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.OCSF_NetworkActivity]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="destination_ip", path="$.dst_endpoint.ip"),
        PantherDataModelMapping(name="destination_port", path="$.dst_endpoint.port"),
        PantherDataModelMapping(name="source_ip", path="$.src_endpoint.ip"),
        PantherDataModelMapping(name="source_port", path="$.src_endpoint.port"),
        PantherDataModelMapping(name="log_status", path="status_code"),
    ]
