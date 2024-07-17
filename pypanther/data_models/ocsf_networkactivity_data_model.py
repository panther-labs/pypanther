from pypanther.base import DataModel, DataModelMapping, LogType


class StandardOCSFNetworkActivity(DataModel):
    id: str = "Standard.OCSF.NetworkActivity"
    display_name: str = "OCSF Network Activity"
    enabled: bool = True
    log_types: list[str] = [LogType.OCSF_NETWORK_ACTIVITY]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="destination_ip", path="$.dst_endpoint.ip"),
        DataModelMapping(name="destination_port", path="$.dst_endpoint.port"),
        DataModelMapping(name="source_ip", path="$.src_endpoint.ip"),
        DataModelMapping(name="source_port", path="$.src_endpoint.port"),
        DataModelMapping(name="log_status", path="status_code"),
    ]
