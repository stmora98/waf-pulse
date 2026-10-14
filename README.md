# WAF Pulse

Continuous Azure Well-Architected Framework (WAF) and Cloud Adoption Framework (CAF) assessment for your entire Microsoft Entra tenant. A scheduled collector reads your Azure estate, stores the results, and a dashboard shows them scored against the five WAF pillars.

Each company deploys its **own isolated copy** into its **own subscription** with one click, using its **own service principal**. Nothing is shared and nothing leaves your tenant.

> **Status:** the infrastructure template and the Deploy to Azure experience are ready. The dashboard and collector application packages (`dashboard.zip`, `collector.zip`) are published to GitHub Releases by a release workflow that is not part of this repository yet. Until the first release exists, a deployment creates all Azure resources but the dashboard shows an error page and the collector has no functions.

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
| `Cost Management Reader` | `az role assignment create --assignee <appId> --role "Cost Management Reader" --scope /providers/Microsoft.Management/managementGroups/<tenant-id>` | Spend, budgets, savings recommendations |
| `Security Reader` | Same command with `--role "Security Reader"` | Defender for Cloud posture |
| Microsoft Graph application permissions `Application.Read.All`, `User.Read.All`, `SecurityIncident.Read.All`, `SecurityAlert.Read.All` | App registration > API permissions > Add > Microsoft Graph > Application permissions, then **Grant admin consent** | Expiring app credentials, guest users, Defender incidents |

### Secret expiry

Client secrets expire (`--years 1` above). When it expires, create a new secret and update the Key Vault secret `collector-client-secret`. No redeployment is needed.

## 3. Deploy

1. Select the **Deploy to Azure** button.
2. Fill in the form, using the tenant ID, client ID and secret from step 2.
3. Select **Review + create**, then **Create**.
4. When the deployment finishes, open the **Outputs** tab and copy `dashboardUrl`.

## 4. Enable dashboard sign-in

The dashboard has no sign-in until you enable it. Do this before sharing the URL.

1. Open the App Service in the portal.
2. Select **Authentication > Add identity provider > Microsoft**.
3. Choose **Require authentication** and save.

Alternatively, pass an existing app registration client ID in the `dashboardAuthClientId` field of the form.

## Refresh modes

| Mode | Behavior |
|---|---|
| Daily | Full collection once a day. |
| Weekly | Full collection once a week. |
| Near real time | Every 5 to 60 minutes (default 15) one Azure Resource Graph `resourcechanges` query covers the whole tenant and refreshes only what changed. |
| Manual | Only when you select the refresh button. |

## Security notes

- The collector secret lives only in Key Vault and is read through a Key Vault reference. It is not stored in app settings, outputs or this repository.
- The web app, Functions, Cosmos DB and Storage use a managed identity. Cosmos DB local auth and Storage shared keys are disabled.
- Resources use public endpoints so a one-click deployment works anywhere. Add private endpoints if your policy requires them.
- Key Vault soft delete keeps a deleted vault name reserved for 90 days.

## Clean up

Delete the resource group you deployed into. The service principal and its role assignments are yours and are not removed.

## Repository layout

```text
infra/
  main.bicep               Source of truth (resource group scope)
  modules/                 One module per Azure service
  azuredeploy.json         Compiled ARM template used by the button
  createUiDefinition.json  Portal form
  main.parameters.json     Example parameters
```

The button supports ARM JSON only, so `azuredeploy.json` is committed. After changing Bicep, rebuild it:

```bash
az bicep build --file infra/main.bicep --outfile infra/azuredeploy.json
```

A workflow checks that the committed template matches the Bicep source.

## Acknowledgements

Inspired by the [Azure Optimization Engine](https://learn.microsoft.com/cloud-computing/finops/toolkit/optimization-engine/overview) and the CAF-WAF workshop toolkit.
