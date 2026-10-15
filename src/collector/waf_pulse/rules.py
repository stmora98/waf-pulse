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
