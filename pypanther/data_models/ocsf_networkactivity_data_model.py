from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardOCSFNetworkActivity(PantherDataModel):
    DataModelID: str = "Standard.OCSF.NetworkActivity"
    DisplayName: str = "OCSF Network Activity"
    Enabled: bool = True
    LogTypes: List[str] = [PantherLogType.OCSF_NetworkActivity]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="destination_ip", Path="$.dst_endpoint.ip"),
        PantherDataModelMapping(Name="destination_port", Path="$.dst_endpoint.port"),
        PantherDataModelMapping(Name="source_ip", Path="$.src_endpoint.ip"),
        PantherDataModelMapping(Name="source_port", Path="$.src_endpoint.port"),
        PantherDataModelMapping(Name="log_status", Path="status_code"),
    ]
