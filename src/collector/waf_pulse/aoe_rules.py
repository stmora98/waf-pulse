"""Rules inspired by the Azure Optimization Engine's custom recommendations: scale sets, networking, availability sets and
platform limits. They only need Reader, like the rest of the catalog."""
from .rule_model import Rule

SUBSCRIPTION_TYPE = "microsoft.resources/subscriptions"

# Subnets Azure reserves for a service: they are empty or tight on purpose.
RESERVED_SUBNETS = "'GatewaySubnet', 'AzureFirewallSubnet', 'AzureFirewallManagementSubnet', 'AzureBastionSubnet', 'RouteServerSubnet'"

SUBNETS = f"""
resources
| where type =~ 'microsoft.network/virtualnetworks'
| mv-expand subnet = properties.subnets
| where tostring(subnet.name) !in~ ({RESERVED_SUBNETS})
| extend prefix = tostring(coalesce(subnet.properties.addressPrefix, subnet.properties.addressPrefixes[0]))
| extend mask = toint(split(prefix, '/')[1])
| extend capacity = pow(2, 32 - mask) - 5
| extend used = coalesce(array_length(subnet.properties.ipConfigurations), 0) + coalesce(array_length(subnet.properties.privateEndpoints), 0)
"""

EMPTY_SUBNETS = f"""
resources
| where type =~ 'microsoft.network/virtualnetworks'
| mv-expand subnet = properties.subnets
| where tostring(subnet.name) !in~ ({RESERVED_SUBNETS})
| where coalesce(array_length(subnet.properties.ipConfigurations), 0) == 0
| where coalesce(array_length(subnet.properties.privateEndpoints), 0) == 0
| where coalesce(array_length(subnet.properties.delegations), 0) == 0
| where coalesce(array_length(subnet.properties.resourceNavigationLinks), 0) == 0
| where coalesce(array_length(subnet.properties.serviceAssociationLinks), 0) == 0
| where isnull(subnet.properties.natGateway)
"""

RULES_EXTRA = (
    Rule(
        id="REL-VMSS-001",
        pillar="Reliability",
        severity="medium",
        title="Virtual machine scale set is not spread across availability zones",
        recommendation="Deploy the scale set across at least two availability zones where the region has them.",
        applies_to=("microsoft.compute/virtualmachinescalesets",),
        query="""
resources
| where type =~ 'microsoft.compute/virtualmachinescalesets'
| where isnull(zones) or array_length(zones) < 2
| where toint(sku.capacity) > 0
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="COST-VMSS-001",
        pillar="Cost Optimization",
        severity="low",
        title="Virtual machine scale set has no instances",
        recommendation="Delete the scale set if it is no longer used. Its disks, load balancer and public IP keep costing.",
        applies_to=("microsoft.compute/virtualmachinescalesets",),
        query="""
resources
| where type =~ 'microsoft.compute/virtualmachinescalesets'
| where toint(sku.capacity) == 0
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="REL-AVS-001",
        pillar="Reliability",
        severity="low",
        title="Availability set has fewer than two virtual machines",
        recommendation="An availability set only protects when it holds two or more machines. Add the missing ones or remove the set.",
        applies_to=("microsoft.compute/availabilitysets",),
        query="""
resources
| where type =~ 'microsoft.compute/availabilitysets'
| where coalesce(array_length(properties.virtualMachines), 0) < 2
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="OPS-NET-001",
        pillar="Operational Excellence",
        severity="low",
        title="Virtual network has empty subnets",
        recommendation="Delete the subnets nothing uses, or document what they are reserved for.",
        applies_to=("microsoft.network/virtualnetworks",),
        query=EMPTY_SUBNETS + """
| summarize subnets = make_list(tostring(subnet.name)) by id, name, type, subscriptionId
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="OPS-NET-002",
        pillar="Operational Excellence",
        severity="medium",
        title="Subnet is running out of IP addresses",
        recommendation="Add an address range to the subnet or move workloads out. A full subnet blocks scaling and deployments.",
        applies_to=("microsoft.network/virtualnetworks",),
        query=SUBNETS + """
| where mask <= 28 and used > 0.8 * capacity
| summarize subnets = make_list(tostring(subnet.name)) by id, name, type, subscriptionId
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="OPS-NET-003",
        pillar="Operational Excellence",
        severity="low",
        title="Subnet reserves far more IP addresses than it uses",
        recommendation="Resize the subnet when the address space is scarce: a large range that is almost empty is hard to reclaim later.",
        applies_to=("microsoft.network/virtualnetworks",),
        query=SUBNETS + """
| where mask <= 22 and used < 0.05 * capacity
| summarize subnets = make_list(tostring(subnet.name)) by id, name, type, subscriptionId
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="OPS-NSG-001",
        pillar="Operational Excellence",
        severity="low",
        title="Network security group has rules that point at an empty subnet",
        recommendation="Remove the rules that refer to subnets nothing uses, so the group only holds rules that matter.",
        applies_to=("microsoft.network/networksecuritygroups",),
        query="""
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rule = properties.securityRules
| extend prefixes = array_concat(pack_array(tostring(rule.properties.sourceAddressPrefix), tostring(rule.properties.destinationAddressPrefix)),
    iff(isnull(rule.properties.sourceAddressPrefixes), dynamic([]), rule.properties.sourceAddressPrefixes),
    iff(isnull(rule.properties.destinationAddressPrefixes), dynamic([]), rule.properties.destinationAddressPrefixes))
| mv-expand prefix = prefixes to typeof(string)
| where prefix contains '/'
| join kind=inner (
    resources
    | where type =~ 'microsoft.network/virtualnetworks'
    | mv-expand subnet = properties.subnets
    | where coalesce(array_length(subnet.properties.ipConfigurations), 0) == 0 and coalesce(array_length(subnet.properties.privateEndpoints), 0) == 0
    | where coalesce(array_length(subnet.properties.delegations), 0) == 0
    | project prefix = tostring(coalesce(subnet.properties.addressPrefix, subnet.properties.addressPrefixes[0]))
  ) on prefix
| summarize by id, name, type, subscriptionId
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="OPS-LIM-001",
        pillar="Operational Excellence",
        severity="medium",
        title="Subscription is close to the limit of 4,000 role assignments",
        recommendation="Assign roles to groups instead of users and remove the assignments of deleted identities before the limit blocks new ones.",
        applies_to=(SUBSCRIPTION_TYPE,),
        query="""
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| summarize assignments = count() by subscriptionId
| where assignments >= 3200
| extend id = strcat('/subscriptions/', subscriptionId), name = subscriptionId, type = 'microsoft.resources/subscriptions'
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="OPS-LIM-002",
        pillar="Operational Excellence",
        severity="low",
        title="Subscription is close to the limit of 980 resource groups",
        recommendation="Delete the empty resource groups or split the workloads across subscriptions before the limit blocks new groups.",
        applies_to=(SUBSCRIPTION_TYPE,),
        query="""
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions/resourcegroups'
| summarize groups = count() by subscriptionId
| where groups >= 800
| extend id = strcat('/subscriptions/', subscriptionId), name = subscriptionId, type = 'microsoft.resources/subscriptions'
| project id, name, type, subscriptionId
""",
    ),
)
