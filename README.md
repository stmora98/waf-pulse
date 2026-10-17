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

### Optional permissions

Each one unlocks extra findings. Skipping any of them is fine.

| Permission | How to grant | Unlocks |
|---|---|---|
| `Cost Management Reader` | `az role assignment create --assignee <appId> --role "Cost Management Reader" --scope /providers/Microsoft.Management/managementGroups/<tenant-id>` | The Cost page: monthly spend, forecast and budgets |
| `Security Reader` | Same command with `--role "Security Reader"` | Defender for Cloud posture |
| `Key Vault Reader` | Same command with `--role "Key Vault Reader"` and a subscription or management group scope. Vaults that use access policies need a list permission for secrets, keys and certificates, and a vault with a firewall must allow the collector | Expired and expiring secrets, keys and certificates. Only metadata is read, never a value |
| Microsoft Graph application permissions `Application.Read.All`, `User.Read.All`, `SecurityIncident.Read.All` (each one is independent) | App registration > API permissions > Add > Microsoft Graph > Application permissions, then **Grant admin consent** | Expiring app credentials, guest users, Defender incidents |

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
| **Action items** | Every recommendation of the assessment in one place, grouped by problem, with pillar, source and severity filters and a search box. Select one to see what to do and every affected resource. The other pages do not repeat these lists. |
| **Security, Reliability, Cost, Performance, Operations** | Score, severity counts, charts, and the insights that belong to it: Defender for Cloud coverage by plan and tier, the Secure Score controls, Entra and Key Vault for Security, diagnostic settings for Operations. **Cost** also holds the spend, laid out like the [FinOps hub dashboard](https://learn.microsoft.com/cloud-computing/finops/toolkit/hubs/finops-hubs-overview): summary cards, monthly trends by service, resource group, region and resource type, the most expensive resources, daily spend, anomalies and running total, cost by pricing model and commitment coverage, reservation and savings plan options, budgets and subscriptions. |
| **Right-sizing** | Charts of how many virtual machines, SQL databases, App Service plans and storage accounts are idle, underutilized, right-sized or saturated. Select a bar to list the resources with their size, average and maximum CPU, resource group and assessment. |
| **Action item detail** | Select any action item to see what to do, the documentation link, every affected resource and how many resources it affected in each earlier run. |
| **Governance** | The management group hierarchy drawn as a landing zone diagram (each group with its subscriptions), next to the Azure landing zone reference architecture with the groups your tenant already has marked, plus policy, access, locks, Defender, diagnostics, Key Vault and Entra. |
| **History** | Runs, score trend and what changed between two runs. |
### Landing zone mapping

The Governance page matches each of your management groups to a role of the Azure landing zone reference architecture, without depending on the names being the same. It tries, in this order:

1. **Manual mapping** (below), always wins.
2. **The name**, in English, Spanish or Portuguese and without accents (`Plataforma`, `Conectividad`, `Zonas de aterrizaje`, `Dado de baja`, `Pruebas` ...).
3. **Policy assignments** made on the group. The reference architecture assigns well known ones: `Enforce-ALZ-Sandbox` marks the sandbox, `Enforce-ALZ-Decomm` the decommissioned group, `Deny-IP-Forwarding` and similar the landing zones, `Deploy-Private-DNS-Zones` the corp group, `Enable-DDoS-VNET` the connectivity group.
4. **What the subscriptions contain**, only for groups under a platform group: firewalls, VPN or ExpressRoute gateways and virtual hubs point to connectivity, domain services to identity, Log Analytics workspaces and Automation accounts to management.

Each match shows how it was made (name, policy, content or manual) when you hover a box and in the panel that opens when you click it.

**Map it yourself in the page.** In the Governance page, click a box of the reference diagram. A small panel opens with a dropdown that offers every management group and subscription of your tenant (you can also type a name). Choose one and select **Map it**; the names you mapped show as chips you can remove. A subscription works too, which helps tenants without management groups: it appears under the box like the key icons of the reference diagram. Names that match nothing are flagged. **Remove this box** takes a box that does not apply to you out of the diagram and the count (a box takes its children with it); it can be put back from the chips below the diagram. **Reset everything** clears your names and brings the boxes back.

What you save is kept in the dashboard's database, so it survives new runs and restarts. Without dashboard sign-in, anyone with the URL can change it; it only affects how this page is drawn. With sign-in on, only the users you allowed can.

**Or set it at deployment.** Fill the **Landing zone mapping** field of the form (Advanced) or the `LANDING_ZONE_MAP` setting of the dashboard App Service with a JSON object. Each role takes one name or id, or a list of them:

```json
{"connectivity": "mg-hub", "platform": ["Plataforma", "mg-plat-prod"], "sandbox": "Laboratorio"}
```

Roles: `platform`, `security`, `management`, `identity`, `connectivity`, `landingzones`, `corp`, `online`, `local`, `sandbox`, `decommissioned`. Names are compared without caring about case. What is typed in the page replaces the deployment setting for that role. Changing the setting restarts the dashboard, and the mapping applies right away; no new run is needed.

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
| **Built-in rules** (31) | Storage, Key Vault, App Service, SQL, network, backup, orphaned and idle resources (disks, IPs, NICs, old snapshots, empty App Service plans, NAT gateways, load balancers), older VM size series, tags, and Azure Hybrid Benefit for Windows VMs, SQL Server VMs, SQL Managed Instance and vCore databases (usage and rate optimization from the [FinOps toolkit](https://aka.ms/finops/toolkit)). See [`rules.py`](src/collector/waf_pulse/rules.py). |
| **Azure review checklists** (162 automated checks) | The community [Azure review checklists](https://github.com/Azure/review-checklists) that carry a Resource Graph query: general WAF, landing zone, AKS, storage, App Service, networking, APIM, Front Door, SAP and more. |
| **Azure Advisor** | Every recommendation in the five categories, grouped by recommendation type, with the annual savings of the usage recommendations. Reservation and savings plan recommendations are reported separately on the Cost page (Rate optimization): Advisor repeats them per term and lookback window, so only the longest lookback window is kept and the 1 and 3 year options are shown side by side, never added together. |
| **Defender for Cloud** | Unhealthy security recommendations and, where Defender provides it, the Secure Score and its controls. |
| **Azure Monitor metrics** | Right-sizing from the last 30 days: idle, underutilized and saturated virtual machines, SQL databases and App Service plans, and storage accounts without transactions. Read with the metrics batch API, 50 resources per call. |
| **Cost Management** | Follows the [FinOps hub](https://learn.microsoft.com/cloud-computing/finops/toolkit/hubs/finops-hubs-overview) approach using the Cost Management APIs (no hub required): **billed** and **effective (amortized)** cost per month and per service for six months, a 60-day daily series, daily **anomaly detection** (each day against the median of the previous 14 days, flagging the day the spend jumps), month over month change, a simple forecast, and budgets, plus breakdowns by service, region, resource group, resource type and pricing model, the daily cost by service and the most expensive resources (5 more queries per scope, within a 4 minute budget; a partial read is flagged on the page). It asks for the whole tenant first (management group scope) and falls back to one subscription at a time (3 API calls each, within a 7 minute budget; if some subscriptions do not fit, tenant totals are hidden instead of shown partially). Needs the Cost Management Reader role; without it the Cost page explains what is missing and the rest keeps working. Checks: no budget, exhausted or forecast-to-exceed budget, month over month growth and daily spend anomalies. |
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
