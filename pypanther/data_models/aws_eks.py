from pypanther.base import DataModel, DataModelMapping, LogType


class StandardAmazonEKSAudit(DataModel):
    id: str = "Standard.Amazon.EKS.Audit"
    display_name: str = "AWS EKS Audit"
    enabled: bool = True
    log_types: list[str] = [LogType.AMAZON_EKS_AUDIT]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="annotations", path="$.annotations"),
        DataModelMapping(name="apiGroup", path="$.objectRef.apiGroup"),
        DataModelMapping(name="apiVersion", path="$.objectRef.apiVersion"),
        DataModelMapping(name="namespace", path="$.objectRef.namespace"),
        DataModelMapping(name="resource", path="$.objectRef.resource"),
        DataModelMapping(name="name", path="$.objectRef.name"),
        DataModelMapping(name="requestURI", path="$.requestURI"),
        DataModelMapping(name="responseStatus", path="$.responseStatus"),
        DataModelMapping(name="sourceIPs", path="$.sourceIPs"),
        DataModelMapping(name="username", path="$.user.username"),
        DataModelMapping(name="userAgent", path="$.userAgent"),
        DataModelMapping(name="verb", path="$.verb"),
        DataModelMapping(name="requestObject", path="$.requestObject"),
        DataModelMapping(name="responseObject", path="$.responseObject"),
    ]
