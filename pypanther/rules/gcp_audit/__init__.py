from pypanther.rules.gcp_audit.gcp_access_attempts_violating_vpc_service_controls import (
    GCPAccessAttemptsViolatingVPCServiceControls as GCPAccessAttemptsViolatingVPCServiceControls,
)
from pypanther.rules.gcp_audit.gcp_bigquery_large_scan import GCPBigQueryLargeScan as GCPBigQueryLargeScan
from pypanther.rules.gcp_audit.gcp_cloud_run_service_created import (
    GCPCloudRunServiceCreated as GCPCloudRunServiceCreated,
)
from pypanther.rules.gcp_audit.gcp_cloud_run_set_iam_policy import GCPCloudRunSetIAMPolicy as GCPCloudRunSetIAMPolicy
from pypanther.rules.gcp_audit.gcp_cloud_storage_buckets_modified_or_deleted import (
    GCPCloudStorageBucketsModifiedOrDeleted as GCPCloudStorageBucketsModifiedOrDeleted,
)
from pypanther.rules.gcp_audit.gcp_cloudbuild_potential_privilege_escalation import (
    GCPCloudBuildPotentialPrivilegeEscalation as GCPCloudBuildPotentialPrivilegeEscalation,
)
from pypanther.rules.gcp_audit.gcp_cloudfunctions_functions_create import (
    GCPCloudfunctionsFunctionsCreate as GCPCloudfunctionsFunctionsCreate,
)
from pypanther.rules.gcp_audit.gcp_cloudfunctions_functions_update import (
    GCPCloudfunctionsFunctionsUpdate as GCPCloudfunctionsFunctionsUpdate,
)
from pypanther.rules.gcp_audit.gcp_computeinstances_create_privilege_escalation import (
    GCPcomputeinstancescreatePrivilegeEscalation as GCPcomputeinstancescreatePrivilegeEscalation,
)
from pypanther.rules.gcp_audit.gcp_destructive_queries import GCPDestructiveQueries as GCPDestructiveQueries
from pypanther.rules.gcp_audit.gcp_dns_zone_modified_or_deleted import (
    GCPDNSZoneModifiedorDeleted as GCPDNSZoneModifiedorDeleted,
)
from pypanther.rules.gcp_audit.gcp_firewall_rule_created import GCPFirewallRuleCreated as GCPFirewallRuleCreated
from pypanther.rules.gcp_audit.gcp_firewall_rule_deleted import GCPFirewallRuleDeleted as GCPFirewallRuleDeleted
from pypanther.rules.gcp_audit.gcp_firewall_rule_modified import GCPFirewallRuleModified as GCPFirewallRuleModified
from pypanther.rules.gcp_audit.gcp_gcs_iam_changes import GCPGCSIAMChanges as GCPGCSIAMChanges
from pypanther.rules.gcp_audit.gcp_gcs_public import GCPGCSPublic as GCPGCSPublic
from pypanther.rules.gcp_audit.gcp_iam_corp_email import GCPIAMCorporateEmail as GCPIAMCorporateEmail
from pypanther.rules.gcp_audit.gcp_iam_custom_role_changes import GCPIAMCustomRoleChanges as GCPIAMCustomRoleChanges
from pypanther.rules.gcp_audit.gcp_iam_org_folder_changes import GCPIAMOrgFolderIAMChanges as GCPIAMOrgFolderIAMChanges
from pypanther.rules.gcp_audit.gcp_iam_roles_update_privilege_escalation import (
    GCPiamrolesupdatePrivilegeEscalation as GCPiamrolesupdatePrivilegeEscalation,
)
from pypanther.rules.gcp_audit.gcp_iam_service_account_key_create import (
    GCPiamserviceAccountKeyscreate as GCPiamserviceAccountKeyscreate,
)
from pypanther.rules.gcp_audit.gcp_iam_service_accounts_get_access_token_privilege_escalation import (
    GCPIAMserviceAccountsgetAccessTokenPrivilegeEscalation as GCPIAMserviceAccountsgetAccessTokenPrivilegeEscalation,
)
from pypanther.rules.gcp_audit.gcp_iam_service_accounts_sign_blob import (
    GCPIAMserviceAccountssignBlob as GCPIAMserviceAccountssignBlob,
)
from pypanther.rules.gcp_audit.gcp_iam_serviceaccounts_signjwt import (
    GCPIAMserviceAccountssignJwtPrivilegeEscalation as GCPIAMserviceAccountssignJwtPrivilegeEscalation,
)
from pypanther.rules.gcp_audit.gcp_inbound_sso_profile_created_or_updated import (
    GCPInboundSSOProfileCreated as GCPInboundSSOProfileCreated,
)
from pypanther.rules.gcp_audit.gcp_log_bucket_or_sink_deleted import (
    GCPLogBucketOrSinkDeleted as GCPLogBucketOrSinkDeleted,
)
from pypanther.rules.gcp_audit.gcp_logging_settings_modified import (
    GCPLoggingSettingsModified as GCPLoggingSettingsModified,
)
from pypanther.rules.gcp_audit.gcp_logging_sink_modified import GCPLoggingSinkModified as GCPLoggingSinkModified
from pypanther.rules.gcp_audit.gcp_permissions_granted_to_create_or_manage_service_account_key import (
    GCPPermissionsGrantedtoCreateorManageServiceAccountKey as GCPPermissionsGrantedtoCreateorManageServiceAccountKey,
)
from pypanther.rules.gcp_audit.gcp_privilege_escalation_by_deployments_create import (
    GCPPrivilegeEscalationByDeploymentsCreate as GCPPrivilegeEscalationByDeploymentsCreate,
)
from pypanther.rules.gcp_audit.gcp_service_account_access_denied import (
    GCPServiceAccountAccessDenied as GCPServiceAccountAccessDenied,
)
from pypanther.rules.gcp_audit.gcp_service_account_or_keys_created import (
    GCPServiceAccountorKeysCreated as GCPServiceAccountorKeysCreated,
)
from pypanther.rules.gcp_audit.gcp_serviceusage_apikeys_create_privilege_escalation import (
    GCPserviceusageapiKeyscreatePrivilegeEscalation as GCPserviceusageapiKeyscreatePrivilegeEscalation,
)
from pypanther.rules.gcp_audit.gcp_sql_config_changes import GCPSQLConfigChanges as GCPSQLConfigChanges
from pypanther.rules.gcp_audit.gcp_storage_hmac_keys_create import GCPStorageHmacKeysCreate as GCPStorageHmacKeysCreate
from pypanther.rules.gcp_audit.gcp_unused_regions import GCPUnusedRegions as GCPUnusedRegions
from pypanther.rules.gcp_audit.gcp_user_added_to_iap_protected_service import (
    GCPUserAddedtoIAPProtectedService as GCPUserAddedtoIAPProtectedService,
)
from pypanther.rules.gcp_audit.gcp_user_added_to_privileged_group import (
    GCPUserAddedToPrivilegedGroup as GCPUserAddedToPrivilegedGroup,
)
from pypanther.rules.gcp_audit.gcp_vpc_flow_logs_disabled import GCPVPCFlowLogsDisabled as GCPVPCFlowLogsDisabled
from pypanther.rules.gcp_audit.gcp_workforce_pool_created_or_updated import (
    GCPWorkforcePoolCreatedorUpdated as GCPWorkforcePoolCreatedorUpdated,
)
from pypanther.rules.gcp_audit.gcp_workload_identity_pool_created_or_updated import (
    GCPWorkloadIdentityPoolCreatedorUpdated as GCPWorkloadIdentityPoolCreatedorUpdated,
)
