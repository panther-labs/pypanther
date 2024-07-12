from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import PantherLogType


class StandardAmazonEKSAudit(PantherDataModel):
    id_: str = "Standard.Amazon.EKS.Audit"
    display_name: str = "AWS EKS Audit"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.Amazon_EKS_Audit]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(name="annotations", path="$.annotations"),
        PantherDataModelMapping(name="apiGroup", path="$.objectRef.apiGroup"),
        PantherDataModelMapping(name="apiVersion", path="$.objectRef.apiVersion"),
        PantherDataModelMapping(name="namespace", path="$.objectRef.namespace"),
        PantherDataModelMapping(name="resource", path="$.objectRef.resource"),
        PantherDataModelMapping(name="name", path="$.objectRef.name"),
        PantherDataModelMapping(name="requestURI", path="$.requestURI"),
        PantherDataModelMapping(name="responseStatus", path="$.responseStatus"),
        PantherDataModelMapping(name="sourceIPs", path="$.sourceIPs"),
        PantherDataModelMapping(name="username", path="$.user.username"),
        PantherDataModelMapping(name="userAgent", path="$.userAgent"),
        PantherDataModelMapping(name="verb", path="$.verb"),
        PantherDataModelMapping(name="requestObject", path="$.requestObject"),
        PantherDataModelMapping(name="responseObject", path="$.responseObject"),
    ]
