# WAF Pulse

Continuous Azure Well-Architected Framework (WAF) and Cloud Adoption Framework (CAF) assessment for your entire Microsoft Entra tenant. A scheduled collector reads your Azure estate, stores the results, and a dashboard shows them scored against the five WAF pillars.

Each company deploys its **own isolated copy** into its **own subscription** with one click, using its **own service principal**. Nothing is shared and nothing leaves your tenant.

> **Status: early preview.** The first vertical slice is in place: the collector inventories every subscription in the tenant and checks 7 Well-Architected rules, and the dashboard shows scores per pillar and the findings. More rules and checks are added over time. Packages are published to GitHub Releases by the [Release workflow](.github/workflows/release.yml).

## Deploy to Azure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fstmora98%2Fwaf-pulse%2Fmain%2Finfra%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fstmora98%2Fwaf-pulse%2Fmain%2Finfra%2FcreateUiDefinition.json)

The button opens the Azure portal with a form where you choose:

| Field | Description |
|---|---|
| Subscription, resource group, region | Where the resources are created. You can create a new resource group in the form. |
| Tool name | 2 to 10 lowercase letters or digits used in every resource name. |
| Tenant ID, client ID, client secret | Your service principal (see [step 2](#2-create-the-service-principal)). The secret is stored in Key Vault. |
| Subscription filter | Optional. Empty scans the entire tenant. |
| Refresh mode | Daily, weekly, near real time or manual. |
| App Service plan SKU | `B1` (default, low cost) or `P1v3`. |

## What gets deployed

| Resource | Purpose |
|---|---|
| App Service (Linux, Python 3.12) | Dashboard, runs from a package on GitHub Releases. |
| Azure Functions (Flex Consumption) with Durable Functions | Collector: timer (daily or weekly), manual refresh, and near real time polling. |
| Cosmos DB for NoSQL (serverless) | Findings, run summaries and score history. |
| Storage account | Raw snapshots, generated dashboards, Functions deployment package. |
| Key Vault | Service principal secret. |
| User-assigned managed identity | Access to Cosmos DB, Storage and Key Vault without keys. |
| Log Analytics and Application Insights | Logs and tracing. |

Estimated cost is about **$20 per month** with the defaults (App Service B1 is about $13). Functions cost depends on how long each collection runs.

## 1. Prerequisites

- An Azure subscription where you can create resources and role assignments (`Owner`, or `Contributor` plus `User Access Administrator`, on the resource group).
- Permission to create an app registration in Microsoft Entra ID.
- To grant tenant-wide read access: a user who can [elevate access](https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin) (Global Administrator).
- These resource providers registered in the subscription. New subscriptions often lack `Microsoft.ContainerInstance` (used by the deployment script) and `Microsoft.AlertsManagement` (used by Application Insights):

  ```bash
  for ns in Microsoft.Web Microsoft.DocumentDB Microsoft.KeyVault Microsoft.Storage \
            Microsoft.OperationalInsights Microsoft.Insights Microsoft.ManagedIdentity \
            Microsoft.ContainerInstance Microsoft.AlertsManagement; do
    az provider register --namespace $ns
  done
  ```

## 2. Create the service principal

The collector authenticates with a service principal that you create and own. The template never creates it.

### Azure CLI

```bash
az login --tenant <tenant-id>

# Reader on the whole tenant (root management group)
az ad sp create-for-rbac \
  --name waf-pulse-collector \
  --role Reader \
  --scopes /providers/Microsoft.Management/managementGroups/<tenant-id> \
  --years 1
```

The command prints `appId` (client ID), `password` (client secret) and `tenant`. Save the secret now, it cannot be shown again.

Granting a role at the root management group requires elevated access. Turn on **Microsoft Entra ID > Properties > Access management for Azure resources** first. If you prefer not to, assign `Reader` on each subscription instead by passing several `--scopes /subscriptions/<id>`.

### Permissions, one by one

The collector only **reads**. It never gets a write permission, an Owner/Contributor role, or access to a secret value. Everything below is
granted to the service principal (or its app registration) that you create here. Each optional item is independent: leave it out and only the
part that needs it shows as **Not available** in the **Data source coverage** table of the overview, with the exact permission that is missing.

| Level | What to grant | What you get |
|---|---|---|
| **Minimum** | `Reader` on the tenant root management group | Inventory, findings from the built-in rules and the review checklists, Advisor, Defender recommendations and Secure Score, governance and landing zone, right-sizing with Azure Monitor metrics, security signals (alerts, vulnerable software, exposure, compliance, changes) and access and policy |
| **Recommended** | Minimum + `Cost Management Reader` | + the Cost page, cost of each resource in right-sizing, spend of the filtered resources |
| **Full** | Recommended + `Key Vault Reader` + the Microsoft Graph application permissions below | + expiring Key Vault objects, app credentials, guests, Defender XDR incidents, Conditional Access, privileged roles, MFA registration, users at risk and Entra recommendations |

#### Azure roles

Assign them to the service principal at the tenant root management group (or on each subscription).

| Azure role | Required | Scope | What the collector reads with it | Without it |
|---|---|---|---|---|
| `Reader` | **Yes** | Tenant root management group, or every subscription you want assessed | Resource Graph tables `resources` (including virtual networks, peerings, firewalls, gateways, security groups, private endpoints and flow logs, for the Network page), `resourcecontainers` (subscriptions and management groups), `advisorresources`, `securityresources` (Defender assessments, Secure Score, alerts, software inventory, regulatory compliance, pricing tiers), `policyresources` (assignments, compliance, exemptions), `authorizationresources` (role assignments and definitions), `patchassessmentresources`, `resourcechanges`; Azure Monitor metrics (`Microsoft.Insights/metrics/read`); the VM size catalog (`Microsoft.Compute/skus/read`); compute and network quota usage (`Microsoft.Compute/locations/usages/read`, `Microsoft.Network/locations/usages/read`); diagnostic settings; storage account lifecycle policies; Defender plan tiers (`Microsoft.Security/pricings/read`); the list of subscriptions | Nothing is assessed. With subscription scopes instead of the root group the management group tree and the landing zone view stay empty, and role assignments and policy at group scope are not seen |
| `Cost Management Reader` | No | Same scope as `Reader` | Cost Management queries (billed and amortized cost, by service, group, region, type and resource) and budgets (`Microsoft.Consumption`) | The Cost page has no data, right-sizing has no cost column, the filtered spend panel is empty. Everything else works |
| `Key Vault Reader` | No | Subscriptions or the root group | The metadata (names and expiry dates) of secrets, keys and certificates of vaults that use Azure RBAC. Vaults that use access policies need the **List** permission for secrets, keys and certificates on the collector; a vault with a firewall must allow the collector | The Key Vault expirations panel and its findings are empty. Only metadata is read, never a value |
| `Security Reader` | **Not needed** | – | Everything WAF Pulse reads from Defender for Cloud is covered by `Reader` | – |

You do not need a custom role: Resource Graph returns a resource only if the caller has `*/read` on it, so `Reader` is already the smallest role that works.

Granting a role at the root management group needs [elevated access](https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin).

```bash
APP_ID=<client-id>
ROOT=/providers/Microsoft.Management/managementGroups/<tenant-id>
az role assignment create --assignee $APP_ID --role "Reader" --scope $ROOT                       # required
az role assignment create --assignee $APP_ID --role "Cost Management Reader" --scope $ROOT      # optional
az role assignment create --assignee $APP_ID --role "Key Vault Reader" --scope $ROOT            # optional
```

#### Microsoft Graph application permissions

Add them to the **app registration** of the service principal (App registration > API permissions > Add a permission > Microsoft Graph > **Application permissions**) and select **Grant admin consent**. Granting consent needs a Privileged Role Administrator or a Global Administrator. They are all read-only and each one is independent.

| Permission | ID | Required | Findings and views it feeds | License or condition |
|---|---|---|---|---|
| `Application.Read.All` | `9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30` | No | App registration secrets and certificates that expired, expire soon or live too long (SEC-APP-001, OPS-APP-002, SEC-APP-003) | None |
| `User.Read.All` | `df021288-bdef-4463-88db-98f22de89214` | No | Guest invitations never accepted (SEC-GUEST-001) | None |
| `SecurityIncident.Read.All` | `45cc0394-e837-488b-a098-1918f48d186c` | No | Open Defender XDR incidents (SEC-XDR-001) | Microsoft Defender XDR |
| `Policy.Read.All` | `246dd0d5-5bd0-4def-940b-0421030a5b68` | No | Identity tab: Conditional Access policies and security defaults (SEC-CA-001 to 004) | Entra ID P1 for Conditional Access |
| `RoleManagement.Read.Directory` | `483bed4a-2ad3-4361-a73b-c83ccdbdc53c` | No | Identity tab: privileged directory roles, Global Administrators, guests and service principals with a privileged role (SEC-ROLE-001 to 003) | None |
| `RoleEligibilitySchedule.Read.Directory` | `ff278e11-4a33-4d0c-83d2-d01dc58929a5` | No | Whether privileged roles are managed with PIM (SEC-ROLE-004) | Entra ID P2 or Entra ID Governance |
| `Reports.Read.All` and `AuditLog.Read.All` (both) | `230c1aed-a721-4c5d-9cb4-a90514e508ef`, `b0afded3-3588-46d8-8b3d-9842eff778da` | No | Identity tab: MFA registration, administrators and users without MFA (SEC-MFA-001, 002) | Entra ID P1 |
| `IdentityRiskyUser.Read.All` | `dc5007c0-2d7d-4c42-879c-2dab87571379` | No | Identity tab: users at risk (SEC-RISK-001 to 003) | Entra ID P2 |
| `DirectoryRecommendations.Read.All` | `ae73097b-cb2a-4447-b064-5d80f6093921` | No | Identity tab: Entra recommendations (SEC-ENTRA-001 to 003). Read from the Microsoft Graph **beta** endpoint, the only one that has them | None |

```bash
APP_ID=<client-id>
GRAPH=00000003-0000-0000-c000-000000000000
# Keep the lines you want. Each id comes from the table above.
az ad app permission add --id $APP_ID --api $GRAPH --api-permissions \
  9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role df021288-bdef-4463-88db-98f22de89214=Role 45cc0394-e837-488b-a098-1918f48d186c=Role \
  246dd0d5-5bd0-4def-940b-0421030a5b68=Role 483bed4a-2ad3-4361-a73b-c83ccdbdc53c=Role ff278e11-4a33-4d0c-83d2-d01dc58929a5=Role \
  230c1aed-a721-4c5d-9cb4-a90514e508ef=Role b0afded3-3588-46d8-8b3d-9842eff778da=Role dc5007c0-2d7d-4c42-879c-2dab87571379=Role \
  ae73097b-cb2a-4447-b064-5d80f6093921=Role
az ad app permission admin-consent --id $APP_ID
```

A permission or a license that is missing is not an error: the part shows as **Not available** and names what to grant. The permissions can be granted at any time; the next refresh picks them up.

#### Data that depends on a Defender plan or a service, not on a permission

Some views are empty because the tenant does not produce the data, even with every permission above.

| View | What the tenant needs |
|---|---|
| Security > Vulnerabilities: software with known vulnerabilities or past its end of support | Defender for Servers (software inventory and vulnerability assessment) |
| Security > Vulnerabilities: pending patches | Azure Update Manager with periodic assessment on the machines |
| Security > Alerts | The Defender plans you want alerts from |
| Security > Compliance | Defender CSPM or a Defender plan, with the regulatory standards you want added in Defender for Cloud |
| Defender coverage and Secure Score | Defender for Cloud enabled on the subscriptions |
| Right-sizing for virtual machines: memory | The VM host metric *Available Memory Bytes*, which Azure Monitor publishes for running machines |
| Advisor savings and commitments | Azure Advisor recommendations, which need a few days of usage |

#### Outbound access

The collector needs to reach `management.azure.com`, `graph.microsoft.com`, `vault.azure.net` (only for Key Vault expirations) and, for the sizes that fit, the public **Azure Retail Prices API** at `prices.azure.com` (no authentication; if it cannot be reached the sizes that fit are skipped and the rest works).

#### What the deployment itself needs and assigns

The person who deploys needs `Owner`, or `Contributor` plus `User Access Administrator`, on the resource group, because the template assigns roles to the managed identity of the dashboard and the collector: `Key Vault Secrets User`, `Storage Blob Data Owner`, `Storage Queue Data Contributor`, `Storage Table Data Contributor`, the Cosmos DB `Built-in Data Contributor` data role and `Website Contributor` on the Function App (for the deployment script). Those are on the deployed resources only; they give no access to the rest of the tenant.

### Secret expiry

Client secrets expire (`--years 1` above). When it expires, create a new secret and update the Key Vault secret `collector-client-secret`. No redeployment is needed.

## 3. Deploy

1. Select the **Deploy to Azure** button.
2. Fill in the form, using the tenant ID, client ID and secret from step 2, (and, only if you turn sign-in on, your object ID as an allowed user).
3. Select **Review + create**, then **Create**.
4. When the deployment finishes, open the **Outputs** tab, and copy `dashboardUrl`. If you turned sign-in on, run the command in `signInSetupCommand` (step 4).

## 4. Dashboard sign-in (optional, off by default)

Sign-in is built in but turned off for now: with the default **None**, anyone who has the dashboard URL can see the data. Keep the URL private, or turn sign-in on before sharing it.

To turn it on, choose **Microsoft Entra** in the form and list the object IDs of the users who may open the dashboard (your own: `az ad signed-in-user show --query id -o tsv`). The dashboard then reuses the service principal from step 2 as the sign-in app, so one command is left after the deployment (also in the **Outputs** tab as `signInSetupCommand`):

```bash
az ad app update --id <client-id> \
  --web-redirect-uris https://<dashboard-host>/.auth/login/aad/callback \
  --enable-id-token-issuance true
```

`--web-redirect-uris` replaces the existing list, so include any other redirect URI the app already has. Until you run it, the sign-in page reports a redirect URI mismatch.

- To change who has access later, edit **App Service > Authentication**, or redeploy with a new list.
- To turn it off again, redeploy with **None**, or disable authentication in the App Service.
- The `/api/health` path stays anonymous for the health probe. It returns no data.
## Dashboard pages

Modeled on the Azure Optimization Engine reports: an overview, one page per Well-Architected pillar and drill-through to each recommendation.

| Page | What it shows |
|---|---|
| **Overview** | Score and finding count per pillar, findings by pillar and severity, by source, resource types and resources with the most findings, and a table of what each data source could read. |
| **Resources** | The list behind every resource count: name, type, resource group, location, size or SKU and subscription, with the number of findings of each and an Open in Azure link. Filters work like the Azure portal: select **+ Add filter** and pick Subscription, Resource group, Resource type, Location, Findings or Name; each filter becomes a pill you can change (several values, **equals** or **does not equal**, with a search box and the number of resources behind every choice, counted with your other filters applied) or remove with the ×. A box next to the pills filters for any field. Filters are in the URL, so a filtered list can be shared. Select a resource to see its facts and all its findings. Up to 5000 resources are kept per run. |
| **Affected resources** | The resources behind a count. Cards, bars and panels that show a number of findings (a severity, a source, a pillar, the savings card, Key Vault, Entra, diagnostics) open it: one row per resource with its worst severity, its findings, its resource group and subscription. |
| **Filters** | The filter bar under the header works like the filters of the Azure portal: **+ Add filter**, pick a field (subscription, management group, resource group, resource type, location or a tag), choose *equals* or *does not equal* and the values, and add as many as you need; all of them have to hold. Every page follows them, except governance, history and suppressions (they say so): the findings and counts, the action items, the resources and right-sizing (with their CSV downloads) and the **scores**, which are calculated again for what is left with the same formula the collector uses. Filters on subscriptions and management groups (with every group below them) give the exact score of those subscriptions. Filters on a resource group, type, location or tag count the affected resources from the findings and estimate how many resources each rule evaluated there (the tenant figure scaled by the share of the resources of its types that stay), so those scores are an estimate; the cost page adds the 30-day spend of the filtered resources (from the per-resource costs of the most expensive resources, by type, group, region and subscription) above its tenant-wide trends, anomalies, rate options and budgets; subscription level and tenant level findings leave a filter on a resource. Secure Score, Defender plans, commitments and usage savings are reported per subscription, so only the subscription and management group filters narrow them. The filters are kept in a cookie of your browser. Tags (up to 8 per resource) come from the resource inventory. |
| **Fix first and score trend** | The overview and each pillar page rank the recommendations by how many points of score fixing them would give (the pillar scored again with the rule solved everywhere), then by how many of their resources face the internet, and draw the score of the last runs. The ranking follows the filters; the trend is the whole tenant's. |
| **Suppressions** | Accept or postpone a recommendation with **Suppress** (for one resource or for every one, for 30 days up to forever, with a reason). The dashboard hides it at once, the collector leaves it out of the scores at the next refresh, and **Restore** brings it back. |
| **Action items** | Every recommendation of the assessment in one place, grouped by problem, with pillar, source and severity filters and a search box. Select one to see what to do and every affected resource. The other pages do not repeat these lists. |
| **Security** (tabs) | Posture (score, Defender coverage, Secure Score and its controls, Entra and Key Vault), **Vulnerabilities** (machines with vulnerable or unsupported software, software on the most machines, pending patches), **Exposure** (internet inbound rules classified by port, machines with a public IP), **Alerts** (Defender alerts by severity and status with a link to each), **Identity** (Conditional Access checks, privileged directory roles, MFA registration, users at risk and Entra recommendations, from Microsoft Graph and tenant-wide), **Access and policy** (powerful Azure role assignments given directly to users or to applications, subscriptions with many owners, custom roles that allow everything, policy compliance by assignment, non-compliant resources and expired exemptions), **Compliance** (pass rate per regulatory standard and the failed controls) and **Changes** (security-relevant changes of the last 14 days, by whom). Every tab follows the filters. |
| **Reliability, Cost, Performance, Operations** | Score, severity counts, charts, and the insights that belong to it: Defender for Cloud coverage by plan and tier, the Secure Score controls, Entra and Key Vault for Security, diagnostic settings for Operations. **Cost** also holds the spend, laid out like the [FinOps hub dashboard](https://learn.microsoft.com/cloud-computing/finops/toolkit/hubs/finops-hubs-overview): summary cards, monthly trends by service, resource group, region and resource type, the most expensive resources, daily spend, anomalies and running total, cost by pricing model and commitment coverage, reservation and savings plan options, budgets and subscriptions. |
| **Right-sizing** | Charts of how many virtual machines, SQL databases, App Service plans and storage accounts are idle, underutilized, right-sized or saturated. Select a bar to list the resources with their size, average and maximum CPU, resource group and assessment. Each row also shows what the resource cost in the last 30 days and what Azure Advisor recommends (shut down, or move to a smaller size, with the monthly saving and the P95 CPU and memory); resources Advisor flags but that have no metrics, like a stopped virtual machine, are listed too. Cards add up the Advisor savings and the spend on idle and underutilized resources. For virtual machines it also reads memory in use, disk IOPS (as a share of what the size allows) and network traffic, so a machine with low CPU but busy memory is flagged as memory-bound instead of idle, and one short on memory is flagged as saturated. Selecting a resource opens its page with the daily utilization curve of the last 30 days (average and peak CPU, memory) against the thresholds. It also covers virtual machine scale sets, Premium SSD disks (share of their IOPS), AKS clusters (node CPU and memory), Cosmos DB accounts with provisioned throughput (normalized RU consumption), SQL managed instances and Redis caches. Virtual machines used only in office hours (from seven days of hourly CPU) are listed as auto-shutdown candidates with the estimated saving, and each machine shows what to weigh before a change (production tag, single instance or availability set or zone). For idle and underutilized virtual machines it also lists the smaller sizes that fit (same CPU architecture and GPUs, available to the subscription, holding the observed peak CPU and memory with headroom), ranked by saving, with a fit score (how close the peak, projected on that size, is to 70%) and the list price (pay as you go, Azure Retail Prices API; list prices, not your agreement's). Tick the rows you plan to change to add up their Advisor savings and cost, and download that selection as CSV. **Advisor savings over time** shows what each run saw and which recommendations were resolved or are new since the previous run. The **Thresholds** panel changes what counts as idle, underutilized or saturated (the dashboard applies it at once, the action items use it from the next refresh). Filter with **+ Add filter** (subscription, resource group, assessment, Advisor recommendation, name), order by assessment, cost, savings or average, and **Download CSV** (the Resources page has it too). |
| **Network** (Manage) | A topology of your virtual networks drawn from what the collector reads, and what to improve. **Topology** puts hubs (networks with a firewall or gateway, or with several peerings) on top and the networks that peer to them below, with the peering state (green connected, red dashed broken or on one side only), gateway transit, an on-premises node for VPN and ExpressRoute gateways, badges for the firewall, gateway, Bastion, application gateway and private endpoints, and the number of findings on each network; select one to see its subnets (range, how full, security group, route table, delegation), peerings and findings. **Virtual networks** lists them with address space, DNS, subnets without a security group and findings. **Security** shows the security groups that let the internet in (with the ports), firewalls and application gateways and their protection, public IPs (basic SKU, not attached) and the storage accounts, Key Vaults, SQL servers, Cosmos DB accounts and registries that accept public traffic and have no private endpoint. **Insights** groups the network findings by recommendation. All of it follows the filters and needs only Reader. |
| **Chargeback** | Who spent what, in amortized cost (commitments spread over their term). **Subscriptions and resource groups** shows each subscription and its resource groups for a month or for all six, with their share of the cost and a chart per month; open a group to see its most expensive resources of the last 30 days, with a link to each in Azure. **By tag** shows the cost of every value of a tag key (a cost center, an owner, an environment) and, above all, the share of the cost **without the tag**, which nobody can be charged for. The collector picks up to six tag keys from your resources, the ones with few distinct values (cost center, owner and similar keys first); set the function app setting `COST_TAG_KEYS` (for example `CostCenter,Owner`) to choose them. Both views follow the subscription, management group and resource group filters and download as CSV. Uses the same Cost Management Reader role as the Cost page; tag keys are read with Resource Graph (Reader). |
| **Action item detail** | Select any action item to see what to do, the documentation link, every affected resource and how many resources it affected in each earlier run. |
| **Governance** | The management group hierarchy drawn as a landing zone diagram (each group with its subscriptions), and an editable landing zone design that starts as the reference architecture (rename, retype, link, add levels and subscriptions, move and delete boxes), plus policy, access, locks, Defender, diagnostics, Key Vault and Entra. |
| **History** | Runs, score trend and what changed between two runs. |
### Landing zone design

The Governance page shows two diagrams. **Your management group hierarchy** is drawn from what the tenant has. **Landing zone design** starts as the Azure landing zone reference architecture and is yours to change completely.

Click any box of the design. A panel opens where you can:

- **Rename** the box.
- **Change its type** between management group and subscription, and back (a subscription is always a leaf, so empty a group before turning it into a subscription).
- **Link it** to one of your own management groups or subscriptions with a dropdown (or typing). A group box only takes management groups and a subscription box only takes subscriptions; each dropdown offers one kind and the dashboard refuses a name of the wrong kind or one that does not exist in your tenant. A linked subscription shows its real name.
- **Add boxes below it**, a management group (a new level, up to 8) or a subscription (up to 150 boxes in all).
- **Move it** left or right among its siblings, or **delete** it with what is below.

A check on a box means it was found in your tenant: by the link you chose, or automatically for boxes that came from the reference. The automatic search looks, in this order, at the name (in English, Spanish or Portuguese, without accents: `Plataforma`, `Conectividad`, `Zonas de aterrizaje`, `Dado de baja`, `Pruebas` ...), at the policy assignments made on the group (the reference architecture assigns well known ones: `Enforce-ALZ-Sandbox` marks the sandbox, `Enforce-ALZ-Decomm` the decommissioned group, `Deny-IP-Forwarding` and similar the landing zones, `Deploy-Private-DNS-Zones` the corp group, `Enable-DDoS-VNET` the connectivity group) and, for groups under a platform group, at what their subscriptions contain (firewalls, gateways and virtual hubs point to connectivity, domain services to identity, Log Analytics workspaces and Automation accounts to management). Hover a box to see how it was matched. **Back to the reference** discards your design.

Your design is kept in the dashboard's database, so it survives new runs and restarts. Without dashboard sign-in, anyone with the URL can change it; it only affects how this page is drawn. With sign-in on, only the users you allowed can.

To help the automatic search at deployment time, fill the **Landing zone mapping** field of the form (Advanced) or the `LANDING_ZONE_MAP` setting of the dashboard App Service with a JSON object that maps a role to the name or id of a management group, or to a list of them:

```json
{"connectivity": "mg-hub", "platform": ["Plataforma", "mg-plat-prod"], "sandbox": "Laboratorio"}
```

Roles: `platform`, `security`, `management`, `identity`, `connectivity`, `landingzones`, `corp`, `online`, `local`, `sandbox`, `decommissioned`. Names are compared without caring about case. Changing the setting restarts the dashboard and applies right away.

### Drill-down

Numbers are links, and a resource can be opened in the Azure portal from every list (the **Open in Azure** link; it needs the tenant id, which the template gives the dashboard as `AZURE_TENANT_ID`; older deployments can add that setting, and without it the portal opens the resource in your default directory). A count of resources, a type bar, a subscription, a severity card, the savings card, the Key Vault, Entra or diagnostics panels and the governance cards open the list of items behind them: the resources, the action items of that severity or source, or the plan and group details. Resource names open the resource page. Not everything has a list yet: policy and role assignment counts are totals only.

## Refresh modes

| Mode | Behavior |
|---|---|
| Daily | Full collection once a day (02:00 UTC). |
| Weekly | Full collection once a week (Monday 02:00 UTC). |
| Near real time | Full collection every 5 to 60 minutes (default 15). Incremental refresh from the Azure Resource Graph `resourcechanges` table is planned. |
| Manual | Only when you select **Refresh now** in the dashboard. |

**Refresh now** works in every mode. The dashboard puts a message in a storage queue and the collector picks it up, so the collector exposes no public endpoint. Only one assessment runs at a time.

To change the schedule later without redeploying, edit the `REFRESH_CRON` application setting of the Function App (a six field NCRONTAB expression, for example `0 0 2 * * *`). To turn the schedule off, set `AzureWebJobs.scheduled_refresh.Disabled` to `true`.

## History and comparison

- **History** (`/history`): the last 30 runs with duration, resources, findings, a score per pillar and a line chart of the scores over time.
- **Compare** (`/compare`): the findings that are new, resolved or unchanged between two runs, and the score change per pillar. By default it compares the latest completed run with the one before it.
- Findings are kept for 90 days (`FINDINGS_RETENTION_DAYS` application setting of the Function App, `0` keeps them forever). Run summaries and scores are kept.

## What it checks

Every source is read-only and needs only the **Reader** role. Everything runs tenant wide: one query covers all subscriptions, so adding a subscription needs no change.

| Source | What it adds |
|---|---|
| **Built-in rules** (44) | Storage, Key Vault, App Service, SQL, network, backup, orphaned and idle resources (disks, IPs, NICs, old snapshots, empty App Service plans, NAT gateways, load balancers), older VM size series, tags, and Azure Hybrid Benefit for Windows VMs, SQL Server VMs, SQL Managed Instance and vCore databases (usage and rate optimization from the [FinOps toolkit](https://aka.ms/finops/toolkit)). See [`rules.py`](src/collector/waf_pulse/rules.py). |
| **Azure Optimization Engine style rules** | Scale sets not spread across zones or with no instances, availability sets with fewer than two machines, empty subnets, subnets running out of addresses or reserving far too many, network security groups with rules that point at empty subnets, subscriptions close to the limit of role assignments (4,000) or resource groups (980). They run in the built-in rule pass. |
| **Azure review checklists** (162 automated checks) | The community [Azure review checklists](https://github.com/Azure/review-checklists) that carry a Resource Graph query: general WAF, landing zone, AKS, storage, App Service, networking, APIM, Front Door, SAP and more. |
| **Azure Advisor** | Every recommendation in the five categories, grouped by recommendation type, with the annual savings of the usage recommendations. Reservation and savings plan recommendations are reported separately on the Cost page (Rate optimization): Advisor repeats them per term and lookback window, so only the longest lookback window is kept and the 1 and 3 year options are shown side by side, never added together. |
| **Defender for Cloud** | Unhealthy security recommendations and, where Defender provides it, the Secure Score and its controls. |
| **Quotas** | Compute and network quota usage per subscription and region (where there are resources), from the usages APIs with Reader. A quota at 80% or more of its limit is a finding (95% is high), and the Reliability page lists the ones closest to the limit. Quotas of 1 to 3 (a switch, not a pool) are ignored. |
| **Azure Monitor metrics** | Right-sizing from the last 30 days: idle, underutilized and saturated virtual machines, SQL databases and App Service plans, and storage accounts without transactions. Read with the metrics batch API, 50 resources per call. For virtual machines the size limits (memory, disk IOPS) come from the Compute SKUs API, one call per subscription and region. |
| **Network** | Cross-resource checks that need the whole picture (Resource Graph, Reader): subnets with no security group (SEC-NET-001, reserved subnets excluded), subnets next to an Azure Firewall that do not send their traffic through it (SEC-NET-002: no 0.0.0.0/0 route to a virtual appliance; delegated subnets are skipped), internet-facing Application Gateways without WAF (SEC-NET-003), Azure Firewall with threat intelligence off (SEC-NET-004, firewalls without a policy), peerings that are disconnected or exist on one side only (REL-NET-002), overlapping address space inside a group of peered networks (REL-NET-003), Basic SKU public IPs and load balancers, retired on 30 September 2025 (REL-NET-004), VPN and ExpressRoute gateways that are not zone redundant (REL-NET-005), virtual networks with no flow logs (OPS-NET-004) and private DNS zones linked to no network (OPS-NET-005). They join the older network rules (security groups open to the internet, public IPs on virtual machines, subnets that are full or empty, no DDoS plan, unused public IPs, NAT gateways, load balancers and application gateways). |
| **Waste and commitments** | The Cost page adds **Waste you can remove**: what the resources behind the findings that ask to delete or shut something down (unattached disks and public IPs, old snapshots, idle machines, empty plans, unused gateways...) cost in the last 30 days, the most that removing them saves (also a column in Action items). It also shows the **utilization of your reservations and savings plans** of the last full month (from the amortized cost: the cost of the usage each one covered against the charge for what nobody used) and raises a finding for the ones used under 80%. |
| **Cost Management** | Follows the [FinOps hub](https://learn.microsoft.com/cloud-computing/finops/toolkit/hubs/finops-hubs-overview) approach using the Cost Management APIs (no hub required): **billed** and **effective (amortized)** cost per month and per service for six months, a 60-day daily series, daily **anomaly detection** (each day against the median of the previous 14 days, flagging the day the spend jumps), month over month change, a simple forecast, and budgets, plus breakdowns by service, region, resource group, resource type and pricing model, the daily cost by service and the most expensive resources, plus the cost per resource group and per tag key for the Chargeback page (7 more queries per scope, and one per tag key, within a 4 minute budget; a partial read is flagged on the page). It asks for the whole tenant first (management group scope) and falls back to one subscription at a time (3 API calls each, within a 7 minute budget; if some subscriptions do not fit, tenant totals are hidden instead of shown partially). Needs the Cost Management Reader role; without it the Cost page explains what is missing and the rest keeps working. Checks: no budget, exhausted or forecast-to-exceed budget, month over month growth and daily spend anomalies. |
| **Access and policy** | Read from Resource Graph with Reader: Owner, User Access Administrator, RBAC Administrator and Contributor assignments (findings for users and applications with the control roles at subscription or group scope, subscriptions with more than three owners, custom roles that allow every action), policy compliance by assignment, non-compliant resources (one finding each) and policy exemptions that expired. Identities show by object id: Resource Graph does not have their names. |
| **Security signals** | Read from Resource Graph with Reader: Defender for Cloud alerts (active ones become findings by severity), installed software with known vulnerabilities or past its end of support and pending patches (Defender for Servers software inventory, Azure Update Manager), the regulatory compliance standards and failed controls, public IP exposure, and the security-relevant resource changes of the last 14 days. Each part reports as not available when the tenant does not have the Defender plan or Update Manager behind it. The exposure rules (SEC-NSG-001 to 003: management ports, database and file sharing ports, or any port open to the internet; SEC-VM-004: virtual machine with a public IP) are part of the built-in rules and judge each allow rule on its own, without evaluating the deny rules around it. |
| **Storage lifecycle** | Storage accounts without a lifecycle management policy, asked one by one through ARM (Reader is enough). |
| **Diagnostic settings** | For the resource types where logs matter most (Key Vault, firewalls, application gateways, NSGs, App Service and Functions, AKS, Cosmos DB, SQL Managed Instance, messaging, API Management, Redis), whether a diagnostic setting sends logs or metrics anywhere. Read with the ARM diagnostic settings API, Reader is enough. Shown on the Governance page. |
| **Key Vault expirations** | Secrets, keys and certificates that expired, expire within 30 days or have no expiration date. Needs the optional Key Vault Reader role; vaults that cannot be listed are counted on the Governance page, not treated as errors. |
| **Microsoft Entra** | From Microsoft Graph: app registrations with expired credentials, credentials that expire within 30 days (unless a newer one already covers them) or live more than two years, guest invitations never accepted after 30 days, and open Defender XDR incidents. Needs the optional Graph permissions; a missing one shows as "not available" on the Governance page, never as an error. Only metadata is read. |
| **Governance** | Management group hierarchy, Azure Policy (assignments, compliance, exemptions), role assignments and owners, resource locks and Defender plans. Shown on the Governance page, with checks for too many owners, missing locks, non-compliance, risky exemptions and disabled Defender plans. |

Each finding keeps its source, and the dashboard can filter by pillar, severity and source.

### Scoring

Each check is scored against the resources it actually evaluates, so one finding is not diluted by unrelated resources:

- `prevalence = affected / applicable` for every check that has at least one applicable resource.
- `score = 100 - (sum of weight x prevalence / sum of weights) x 100`, with weights critical 10, high 5, medium 2 and low 1.
- The worst severity found caps the pillar: a critical finding limits it to 49, a high to 79 and a medium to 89.
- A pillar with nothing to evaluate shows `n/a`.

### Not collected yet

Reservation utilization. They are planned and some need permissions beyond Reader.

### Updating the checklists

```bash
git clone https://github.com/Azure/review-checklists
python tools/update_checklists.py --source review-checklists/checklists
```

Three upstream queries are not valid Resource Graph queries; they are reported as checks that could not run and do not affect the rest.
## Security notes

- The collector secret lives only in Key Vault and is read through a Key Vault reference. It is not stored in app settings, outputs or this repository.
- The web app, Functions, Cosmos DB and Storage use a managed identity. Cosmos DB local auth and Storage shared keys are disabled.
- Resources use public endpoints so a one-click deployment works anywhere. Add private endpoints if your policy requires them.
- Key Vault soft delete keeps a deleted vault name reserved for 90 days.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Deployment succeeds but the Function App has no functions | The collector package could not be published. Check the deployment outputs `collectorDeployed` and `collectorDeploymentMessage`. The script and its log stay in the resource group for two hours (`az deployment-scripts show-log`). To publish by hand: download `collector.zip` from the latest release and run `az functionapp deployment source config-zip --src collector.zip --name <function-app> --resource-group <rg> --build-remote true`. |
| A nested deployment `Failure-Anomalies-Alert-Rule-Deployment-...` shows `MissingSubscriptionRegistration` | Register `Microsoft.AlertsManagement` (see prerequisites). The rest of the deployment is not affected. |
| The dashboard says no assessment has completed | Select **Refresh now** and wait for the run. Check the Function App logs in Application Insights. |
| The dashboard shows "data store is not reachable" | The managed identity may still be receiving its Cosmos DB role. Wait a few minutes and reload. |

## Update to a new version

Releases are published on the [Releases page](https://github.com/stmora98/waf-pulse/releases). Redeploying the template with the same resource group also works. To update an existing deployment by hand:

```bash
# Dashboard: point the package setting at the versioned URL.
# Restarting the app is not enough, the package is only downloaded again when the URL changes.
az webapp config appsettings set -g <rg> -n <app-service> \
  --settings WEBSITE_RUN_FROM_PACKAGE=https://github.com/stmora98/waf-pulse/releases/download/<tag>/dashboard.zip

# Collector: download collector.zip from the release, then publish it with a remote build.
az functionapp deployment source config-zip --src collector.zip \
  --name <function-app> --resource-group <rg> --build-remote true
```

## Clean up

Delete the resource group you deployed into. The service principal and its role assignments are yours and are not removed.

## Repository layout

```text
src/
  collector/               Azure Functions (Python, Durable Functions)
  dashboard/               Flask web app
tests/                     Unit tests
infra/
  main.bicep               Source of truth (resource group scope)
  modules/                 One module per Azure service
  azuredeploy.json         Compiled ARM template used by the button
  createUiDefinition.json  Portal form
  main.parameters.json     Example parameters
.github/workflows/         Tests, template check, release
```

## Development

```bash
pip install pytest -r src/collector/requirements.txt -r src/dashboard/requirements.txt
python -m pytest tests -q
```

Publish a release (the Deploy to Azure template downloads `dashboard.zip` and `collector.zip` from the latest release):

```bash
git tag v0.1.0 && git push origin v0.1.0
```

The button supports ARM JSON only, so `azuredeploy.json` is committed. After changing Bicep, rebuild it:

```bash
az bicep build --file infra/main.bicep --outfile infra/azuredeploy.json
```

A workflow checks that the committed template matches the Bicep source.

## Acknowledgements

Inspired by the [Azure Optimization Engine](https://learn.microsoft.com/cloud-computing/finops/toolkit/optimization-engine/overview) and the CAF-WAF workshop toolkit.

## License

[MIT](LICENSE)

## Design

The dashboard follows the motion and polish guidelines from [emilkowalski/skills](https://github.com/emilkowalski/skills) (MIT): short ease-out transitions on transform, opacity and color only, press feedback on every pressable element, hover effects only on devices with a real pointer, a short staggered entrance, light and dark themes that follow the system, and full respect for reduced motion. The menu is on the left, like the Azure portal: the hamburger button shrinks it to icons (or hides it on small screens) and remembers the choice. The **Theme** button next to Refresh switches between automatic (follows the system), light and dark, and remembers the choice in the browser. There are no inline styles or scripts, so the content security policy stays strict.
