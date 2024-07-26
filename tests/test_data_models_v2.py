from pypanther import LogType
from pypanther.data_models_v2 import DataModel, new_string, FieldMapping


class DNS(DataModel):
    source_ip = new_string(
        description="The IP address of the host",
        mappings=[FieldMapping(log_type=LogType.AWS_VPC_DNS, field_path="srcAddr")]
    )


def rule(event: DNS):
    return event.source_ip == "127.0.0.1"


def test_rule():
    log = {
        "srcAddr": "127.0.0.1",
        "dstAddr": "8.8.8.8",
        "query_name": "www.evil.com",
        "native_log_field": "value",
        "p_log_type": "AWS.VPCDns"
    }

    assert rule(DNS(log))
