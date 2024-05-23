from typing import List

from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.log_types import LogType


class StandardAmazonEKSAudit(PantherDataModel):
    DataModelID: str = "Standard.Amazon.EKS.Audit"
    DisplayName: str = "AWS EKS Audit"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.Amazon_EKS_Audit]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(Name="annotations", Path="$.annotations"),
        PantherDataModelMapping(Name="apiGroup", Path="$.objectRef.apiGroup"),
        PantherDataModelMapping(Name="apiVersion", Path="$.objectRef.apiVersion"),
        PantherDataModelMapping(Name="namespace", Path="$.objectRef.namespace"),
        PantherDataModelMapping(Name="resource", Path="$.objectRef.resource"),
        PantherDataModelMapping(Name="name", Path="$.objectRef.name"),
        PantherDataModelMapping(Name="requestURI", Path="$.requestURI"),
        PantherDataModelMapping(Name="responseStatus", Path="$.responseStatus"),
        PantherDataModelMapping(Name="sourceIPs", Path="$.sourceIPs"),
        PantherDataModelMapping(Name="username", Path="$.user.username"),
        PantherDataModelMapping(Name="userAgent", Path="$.userAgent"),
        PantherDataModelMapping(Name="verb", Path="$.verb"),
        PantherDataModelMapping(Name="requestObject", Path="$.requestObject"),
        PantherDataModelMapping(Name="responseObject", Path="$.responseObject"),
    ]
