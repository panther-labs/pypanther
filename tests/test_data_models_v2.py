from pypanther import LogType, Rule, Severity
from pypanther.data_models_v2 import DataModel, FieldMapping, new_string


def test_data_model():
    class DNS(DataModel):
        source_ip: str = new_string([
            FieldMapping(log_type=LogType.AWS_VPC_DNS, field_path="srcAddr"),
            FieldMapping(log_type=LogType.OCSF_DNS_ACTIVITY, field_path="src_endpoint.ip"),
        ])
        dns_query: str = new_string([
            FieldMapping(log_type=LogType.AWS_VPC_DNS, field_path="queryName"),
            FieldMapping(log_type=LogType.OCSF_DNS_ACTIVITY, field_path="query.hostname"),
        ])

    class A(Rule):
        tags = ["test"]
        default_severity = Severity.INFO

        def rule(self, event: DNS):
            return event.source_ip == ""
