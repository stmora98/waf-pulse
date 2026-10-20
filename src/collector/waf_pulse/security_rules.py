"""Network exposure rules (Resource Graph, Reader is enough): management and database ports open to the internet, and virtual
machines that have a public IP address. A rule that allows a port from the internet is judged by its own priority only: the
deny rules around it are not evaluated, so a finding says "this rule allows it", not "it is reachable"."""
from .rule_model import Rule

MANAGEMENT_PORTS = (22, 23, 3389, 5985, 5986)
DATABASE_PORTS = (1433, 1521, 3306, 5432, 6379, 27017, 9200, 445)

# every inbound allow rule from the internet with one row per destination port range
INTERNET_INBOUND = """
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rule = properties.securityRules
| where tostring(rule.properties.access) =~ 'Allow' and tostring(rule.properties.direction) =~ 'Inbound'
| extend sources = array_concat(pack_array(tostring(rule.properties.sourceAddressPrefix)),
    iff(isnull(rule.properties.sourceAddressPrefixes), dynamic([]), rule.properties.sourceAddressPrefixes))
| mv-expand source = sources to typeof(string)
| where source in~ ('*', 'internet', 'any', '0.0.0.0/0', '0.0.0.0', '/0')
| extend ranges = array_concat(pack_array(tostring(rule.properties.destinationPortRange)),
    iff(isnull(rule.properties.destinationPortRanges), dynamic([]), rule.properties.destinationPortRanges))
| mv-expand range = ranges to typeof(string)
| extend everything = range in ('*', ''), low = toint(iff(range contains '-', split(range, '-')[0], range)), high = toint(iff(range contains '-', split(range, '-')[1], range))
"""


def _ports(ports):
    return " or ".join(f"(low <= {port} and high >= {port})" for port in ports)


RULES_SECURITY = (
    Rule(
        id="SEC-NSG-001",
        pillar="Security",
        severity="critical",
        title="Network security group allows management ports (SSH, RDP, WinRM) from the internet",
        recommendation="Remove the rule or limit its source to known addresses, and use Azure Bastion or just-in-time access to reach the machines.",
        applies_to=("microsoft.network/networksecuritygroups",),
        query=INTERNET_INBOUND + f"""
| where not(everything) and ({_ports(MANAGEMENT_PORTS)})
| summarize by id, name, type, subscriptionId
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="SEC-NSG-002",
        pillar="Security",
        severity="high",
        title="Network security group allows database or file sharing ports from the internet",
        recommendation="Remove the rule or limit its source, and reach databases through private endpoints or a VPN.",
        applies_to=("microsoft.network/networksecuritygroups",),
        query=INTERNET_INBOUND + f"""
| where not(everything) and ({_ports(DATABASE_PORTS)})
| summarize by id, name, type, subscriptionId
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="SEC-NSG-003",
        pillar="Security",
        severity="critical",
        title="Network security group allows every port from the internet",
        recommendation="Replace the rule with the specific ports the workload needs, from the sources that need them.",
        applies_to=("microsoft.network/networksecuritygroups",),
        query=INTERNET_INBOUND + """
| where everything
| summarize by id, name, type, subscriptionId
| project id, name, type, subscriptionId
""",
    ),
    Rule(
        id="SEC-VM-004",
        pillar="Security",
        severity="medium",
        title="Virtual machine has a public IP address",
        recommendation="Remove the public IP address and reach the machine through Azure Bastion, a VPN or a load balancer.",
        applies_to=("microsoft.compute/virtualmachines",),
        query="""
resources
| where type =~ 'microsoft.network/networkinterfaces'
| mv-expand ipc = properties.ipConfigurations
| where isnotempty(tostring(ipc.properties.publicIPAddress.id))
| extend vmId = tostring(properties.virtualMachine.id)
| where isnotempty(vmId)
| summarize by vmId, subscriptionId
| extend id = vmId, name = tostring(split(vmId, '/')[-1]), type = 'microsoft.compute/virtualmachines'
| project id, name, type, subscriptionId
""",
    ),
)
