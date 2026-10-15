"""Rule catalog. Each rule is an Azure Resource Graph query that returns the resources that violate it.

Every query must return the columns: id, name, type, subscriptionId.
`applies_to` lists the resource types the rule evaluates. It gives the scorer the number of resources that
could have violated the rule, so one finding in a large tenant is not diluted by unrelated resources.
New rules (for example the Azure review checklists) are added to RULES and need no other change.
"""
from dataclasses import dataclass

PILLARS = (
    "Reliability",
    "Security",
    "Cost Optimization",
    "Operational Excellence",
    "Performance Efficiency",
)
SEVERITIES = ("critical", "high", "medium", "low")

RESOURCE_GROUP_TYPE = "microsoft.resources/subscriptions/resourcegroups"


@dataclass(frozen=True)
class Rule:
    id: str
    pillar: str
    severity: str
    title: str
    recommendation: str
    applies_to: tuple
    query: str
    source: str = "builtin"


# "*" in applies_to means every resource in the subscription.
ALL_RESOURCES = "*"


RULES = (
    Rule(
        id="SEC-STG-001",
        pillar="Security",
        severity="high",
        title="Storage account allows public blob access",
        recommendation="Disable 'Allow Blob anonymous access' on the storage account.",
        applies_to=("microsoft.storage/storageaccounts",),
        query="""
resources
| where type =~ 'microsoft.storage/storageaccounts'
| where isnull(properties.allowBlobPublicAccess) or tobool(properties.allowBlobPublicAccess) == true
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="SEC-STG-002",
        pillar="Security",
        severity="medium",
        title="Storage account accepts TLS older than 1.2",
        recommendation="Set the minimum TLS version of the storage account to TLS 1.2.",
        applies_to=("microsoft.storage/storageaccounts",),
        query="""
resources
| where type =~ 'microsoft.storage/storageaccounts'
| where tostring(properties.minimumTlsVersion) in~ ('TLS1_0', 'TLS1_1')
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="SEC-SQL-001",
        pillar="Security",
        severity="high",
        title="SQL server allows public network access",
        recommendation="Disable public network access and use private endpoints or firewall rules.",
        applies_to=("microsoft.sql/servers",),
        query="""
resources
| where type =~ 'microsoft.sql/servers'
| where tostring(properties.publicNetworkAccess) =~ 'Enabled'
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="REL-VM-001",
        pillar="Reliability",
        severity="medium",
        title="Virtual machine is not in an availability zone or availability set",
        recommendation="Deploy the virtual machine across availability zones or into an availability set.",
        applies_to=("microsoft.compute/virtualmachines",),
        query="""
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where (isnull(zones) or array_length(zones) == 0) and isnull(properties.availabilitySet)
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="COST-IP-001",
        pillar="Cost Optimization",
        severity="medium",
        title="Public IP address is not attached to any resource",
        recommendation="Delete the public IP address if it is no longer needed.",
        applies_to=("microsoft.network/publicipaddresses",),
        query="""
resources
| where type =~ 'microsoft.network/publicipaddresses'
| where isnull(properties.ipConfiguration) and isnull(properties.natGateway)
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="COST-DISK-001",
        pillar="Cost Optimization",
        severity="medium",
        title="Managed disk is not attached to a virtual machine",
        recommendation="Delete or snapshot and delete the unattached managed disk.",
        applies_to=("microsoft.compute/disks",),
        query="""
resources
| where type =~ 'microsoft.compute/disks'
| where isempty(managedBy) and tostring(properties.diskState) =~ 'Unattached'
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="OPS-TAG-001",
        pillar="Operational Excellence",
        severity="low",
        title="Resource group has no tags",
        recommendation="Add tags such as owner, environment and cost center to the resource group.",
        applies_to=(RESOURCE_GROUP_TYPE,),
        query="""
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions/resourcegroups'
| where isnull(tags) or array_length(bag_keys(tags)) == 0
| project id, name, type, subscriptionId
""",
    ),
)

INVENTORY_QUERY = """
resources
| summarize count() by type
| order by count_ desc
"""

# Resource groups live in a different table, same output shape as INVENTORY_QUERY.
RESOURCE_GROUP_INVENTORY_QUERY = """
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions/resourcegroups'
| summarize count_ = count()
| extend type = 'microsoft.resources/subscriptions/resourcegroups'
"""


def pillars_with_rules():
    return {rule.pillar for rule in RULES}


# Additional built-in checks, inspired by the discovery, governance and FinOps checks of the CAF-WAF toolkit.
RULES = RULES + (
    Rule(
        id="SEC-STG-003",
        pillar="Security",
        severity="high",
        title="Storage account allows unencrypted HTTP traffic",
        recommendation="Enable 'Secure transfer required' on the storage account.",
        applies_to=("microsoft.storage/storageaccounts",),
        query="""
resources
| where type =~ 'microsoft.storage/storageaccounts'
| where tobool(properties.supportsHttpsTrafficOnly) == false
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="SEC-STG-004",
        pillar="Security",
        severity="medium",
        title="Storage account firewall allows all networks by default",
        recommendation="Set the default network action to Deny and allow only required networks or private endpoints.",
        applies_to=("microsoft.storage/storageaccounts",),
        query="""
resources
| where type =~ 'microsoft.storage/storageaccounts'
| where tostring(properties.networkAcls.defaultAction) =~ 'Allow'
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="SEC-KV-001",
        pillar="Security",
        severity="medium",
        title="Key Vault has purge protection disabled",
        recommendation="Enable purge protection so deleted keys, secrets and certificates cannot be purged early.",
        applies_to=("microsoft.keyvault/vaults",),
        query="""
resources
| where type =~ 'microsoft.keyvault/vaults'
| where isnull(properties.enablePurgeProtection) or tobool(properties.enablePurgeProtection) == false
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="SEC-KV-002",
        pillar="Security",
        severity="medium",
        title="Key Vault is reachable from the public internet",
        recommendation="Restrict network access with the vault firewall or private endpoints.",
        applies_to=("microsoft.keyvault/vaults",),
        query="""
resources
| where type =~ 'microsoft.keyvault/vaults'
| where isnull(properties.publicNetworkAccess) or tostring(properties.publicNetworkAccess) =~ 'Enabled'
| where tostring(properties.networkAcls.defaultAction) !~ 'Deny'
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="SEC-WEB-001",
        pillar="Security",
        severity="high",
        title="App Service accepts HTTP traffic",
        recommendation="Enable 'HTTPS Only' so requests are redirected to HTTPS.",
        applies_to=("microsoft.web/sites",),
        query="""
resources
| where type =~ 'microsoft.web/sites'
| where tobool(properties.httpsOnly) == false
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="REL-NET-001",
        pillar="Reliability",
        severity="medium",
        title="Virtual network has no DDoS protection plan",
        recommendation="Associate a DDoS protection plan with virtual networks that host public-facing workloads.",
        applies_to=("microsoft.network/virtualnetworks",),
        query="""
resources
| where type =~ 'microsoft.network/virtualnetworks'
| where tobool(properties.enableDdosProtection) != true
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="REL-BKP-001",
        pillar="Reliability",
        severity="high",
        title="Virtual machine is not protected by Azure Backup",
        recommendation="Enable Azure Backup for the virtual machine.",
        applies_to=("microsoft.compute/virtualmachines",),
        query="""
resources
| where type =~ 'microsoft.compute/virtualmachines'
| extend vmId = tolower(id)
| join kind=leftouter (
    recoveryservicesresources
    | where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems'
    | extend vmId = tolower(tostring(properties.sourceResourceId)), protectedByBackup = true
    | project vmId, protectedByBackup
  ) on vmId
| where isnull(protectedByBackup)
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="REL-BKP-002",
        pillar="Reliability",
        severity="high",
        title="The last backup of a protected item failed",
        recommendation="Investigate the failed backup job and make sure the item is protected again.",
        applies_to=("microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems",),
        query="""
recoveryservicesresources
| where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems'
| where tostring(properties.lastBackupStatus) =~ 'Failed'
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="COST-NIC-001",
        pillar="Cost Optimization",
        severity="low",
        title="Network interface is not attached to anything",
        recommendation="Delete the network interface if it is no longer needed.",
        applies_to=("microsoft.network/networkinterfaces",),
        query="""
resources
| where type =~ 'microsoft.network/networkinterfaces'
| where isnull(properties.virtualMachine) and isnull(properties.privateEndpoint)
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="COST-NSG-001",
        pillar="Cost Optimization",
        severity="low",
        title="Network security group is not associated with any subnet or network interface",
        recommendation="Delete the network security group or associate it with a subnet or network interface.",
        applies_to=("microsoft.network/networksecuritygroups",),
        query="""
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| where isnull(properties.networkInterfaces) and isnull(properties.subnets)
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="COST-VM-001",
        pillar="Cost Optimization",
        severity="low",
        title="Virtual machine is deallocated but still has disks and IP addresses",
        recommendation="Delete the virtual machine and its resources if it is no longer needed.",
        applies_to=("microsoft.compute/virtualmachines",),
        query="""
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where tostring(properties.extended.instanceView.powerState.code) =~ 'PowerState/deallocated'
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="COST-VM-002",
        pillar="Cost Optimization",
        severity="medium",
        title="Virtual machine is stopped but not deallocated, so compute is still billed",
        recommendation="Deallocate the virtual machine from Azure so compute charges stop.",
        applies_to=("microsoft.compute/virtualmachines",),
        query="""
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where tostring(properties.extended.instanceView.powerState.code) =~ 'PowerState/stopped'
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="COST-AGW-001",
        pillar="Cost Optimization",
        severity="medium",
        title="Application Gateway has no backend targets",
        recommendation="Delete the Application Gateway or add backend targets. It is billed while it exists.",
        applies_to=("microsoft.network/applicationgateways",),
        query="""
resources
| where type =~ 'microsoft.network/applicationgateways'
| where isnull(properties.backendAddressPools) or array_length(properties.backendAddressPools) == 0
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="COST-LB-001",
        pillar="Cost Optimization",
        severity="medium",
        title="Load balancer has no backend pool",
        recommendation="Delete the load balancer or add a backend pool.",
        applies_to=("microsoft.network/loadbalancers",),
        query="""
resources
| where type =~ 'microsoft.network/loadbalancers'
| where isnull(properties.backendAddressPools) or array_length(properties.backendAddressPools) == 0
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="COST-SQL-001",
        pillar="Cost Optimization",
        severity="medium",
        title="SQL elastic pool contains no databases",
        recommendation="Delete the empty elastic pool. It is billed while it exists.",
        applies_to=("microsoft.sql/servers/elasticpools",),
        query="""
resources
| where type =~ 'microsoft.sql/servers/elasticpools'
| extend poolId = tolower(id)
| join kind=leftouter (
    resources
    | where type =~ 'microsoft.sql/servers/databases'
    | extend poolId = tolower(tostring(properties.elasticPoolId)), hasDatabases = true
    | where isnotempty(poolId)
    | distinct poolId, hasDatabases
  ) on poolId
| where isnull(hasDatabases)
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="COST-AHB-001",
        pillar="Cost Optimization",
        severity="low",
        title="Windows virtual machine does not use Azure Hybrid Benefit",
        recommendation="Apply Azure Hybrid Benefit if you own Windows Server licenses with Software Assurance.",
        applies_to=("microsoft.compute/virtualmachines",),
        query="""
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where tostring(properties.storageProfile.osDisk.osType) =~ 'Windows'
| where tostring(properties.licenseType) !in~ ('Windows_Server', 'Windows_Client')
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="COST-AHB-002",
        pillar="Cost Optimization",
        severity="low",
        title="SQL Server virtual machine pays the license as you go",
        recommendation="Apply Azure Hybrid Benefit if you own SQL Server licenses with Software Assurance.",
        applies_to=("microsoft.sqlvirtualmachine/sqlvirtualmachines",),
        query="""
resources
| where type =~ 'microsoft.sqlvirtualmachine/sqlvirtualmachines'
| where tostring(properties.sqlServerLicenseType) =~ 'PAYG'
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="OPS-TAG-002",
        pillar="Operational Excellence",
        severity="low",
        title="Resource has no tags",
        recommendation="Add tags such as owner, environment and cost center so costs and ownership can be tracked.",
        applies_to=(ALL_RESOURCES,),
        query="""
resources
| where isnull(tags) or array_length(bag_keys(tags)) == 0
| where type !in~ ('microsoft.insights/workbooks', 'microsoft.alertsmanagement/smartdetectoralertrules')
| project id, name, type, subscriptionId
""",
    ),
)
