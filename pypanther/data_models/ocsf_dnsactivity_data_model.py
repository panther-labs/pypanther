from pypanther.base import DataModel, DataModelMapping, LogType


class StandardOCSFDnsActivity(DataModel):
    id_: str = "Standard.OCSF.DnsActivity"
    display_name: str = "OCSF DNS Activity"
    enabled: bool = True
    log_types: list[str] = [LogType.OCSF_DnsActivity]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="source_ip", path="$.src_endpoint.ip"),
        DataModelMapping(name="source_port", path="$.src_endpoint.port"),
        DataModelMapping(name="dns_query", path="$.query.hostname"),
    ]
