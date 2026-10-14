targetScope = 'resourceGroup'

@description('Azure region for all resources. Defaults to the region of the selected resource group.')
param location string = resourceGroup().location

@description('Name of the tool. Used in every resource name (2 to 10 lowercase letters or digits).')
@minLength(2)
@maxLength(10)
param toolName string = 'wafpulse'

@description('Environment label recorded in tags.')
param environmentName string = 'prod'

@description('Identifier recorded in tags.')
param sessionId string = 'deploy-to-azure'

@description('Who deployed this instance. Recorded in tags.')
param deployedBy string = 'deploy-to-azure'

@description('Deployment timestamp recorded in tags.')
param createdAt string = utcNow()

@description('Microsoft Entra tenant ID of the customer service principal used by the collector.')
param collectorTenantId string

@description('Application (client) ID of the customer service principal used by the collector.')
param collectorClientId string

@description('Client secret of the customer service principal. Stored in Key Vault.')
@secure()
param collectorClientSecret string

@description('How the collector refreshes data.')
@allowed([
  'daily'
  'weekly'
  'nearRealTime'
  'manual'
])
param refreshMode string = 'daily'

@description('Polling interval in minutes for nearRealTime mode.')
@minValue(5)
@maxValue(60)
param nearRealTimeIntervalMinutes int = 15

@description('Optional comma separated subscription IDs. Empty scans the entire tenant.')
param subscriptionFilter string = ''

@description('App Service plan SKU for the dashboard.')
@allowed([
  'B1'
  'P1v3'
])
param appServiceSku string = 'B1'

@description('Optional Microsoft Entra app registration client ID used by App Service authentication. Empty skips authentication configuration.')
param dashboardAuthClientId string = ''

@description('Dashboard package URL (run from package).')
param webPackageUrl string = 'https://github.com/stmora98/waf-pulse/releases/latest/download/dashboard.zip'

@description('Collector package URL deployed to the Function App.')
param collectorPackageUrl string = 'https://github.com/stmora98/waf-pulse/releases/latest/download/collector.zip'

@description('Optional object ID of a user who also needs to manage Key Vault secrets. Empty by default.')
param deployerObjectId string = ''

var suffix = take(uniqueString(resourceGroup().id), 6)
var baseName = '${toolName}-${suffix}'
var tags = {
  'app-onboard-skill': 'true'
  'app-onboard-session-id': sessionId
  'created-at': createdAt
  environment: environmentName
  'deployed-by': deployedBy
}

module managedIdentity './modules/managed-identity.bicep' = {
  name: 'managed-identity'
  params: {
    location: location
    tags: tags
    identityName: 'id-${baseName}'
  }
}

module logAnalytics './modules/log-analytics.bicep' = {
  name: 'log-analytics'
  params: {
    location: location
    tags: tags
    workspaceName: 'log-${baseName}'
  }
}

module appInsights './modules/app-insights.bicep' = {
  name: 'app-insights'
  params: {
    location: location
    tags: tags
    appInsightsName: 'appi-${baseName}'
    workspaceId: logAnalytics.outputs.workspaceId
  }
}

module keyVault './modules/key-vault.bicep' = {
  name: 'key-vault'
  params: {
    location: location
    tags: tags
    kvName: 'kv-${baseName}'
    tenantId: subscription().tenantId
    collectorClientSecret: collectorClientSecret
    workspaceId: logAnalytics.outputs.workspaceId
  }
}

module storage './modules/storage.bicep' = {
  name: 'storage'
  params: {
    location: location
    tags: tags
    storageAccountName: 'st${toolName}${suffix}'
  }
}

module cosmosDb './modules/cosmos-db.bicep' = {
  name: 'cosmos-db'
  params: {
    location: location
    tags: tags
    cosmosName: 'cosmos-${baseName}'
    managedIdentityPrincipalId: managedIdentity.outputs.principalId
    workspaceId: logAnalytics.outputs.workspaceId
  }
}

module roleAssignments './modules/role-assignments.bicep' = {
  name: 'role-assignments'
  params: {
    managedIdentityPrincipalId: managedIdentity.outputs.principalId
    kvName: keyVault.outputs.kvName
    storageAccountName: storage.outputs.storageAccountName
    deployerObjectId: deployerObjectId
  }
}

module appServicePlan './modules/app-service-plan.bicep' = {
  name: 'app-service-plan'
  params: {
    location: location
    tags: tags
    planName: 'asp-${baseName}'
    sku: appServiceSku
  }
}

module dashboardApp './modules/app-service.bicep' = {
  name: 'dashboard-app'
  params: {
    location: location
    tags: tags
    appName: 'app-${baseName}'
    appServicePlanId: appServicePlan.outputs.planId
    managedIdentityId: managedIdentity.outputs.identityId
    managedIdentityClientId: managedIdentity.outputs.clientId
    cosmosEndpoint: cosmosDb.outputs.endpoint
    cosmosDatabase: cosmosDb.outputs.databaseName
    storageAccountUrl: storage.outputs.blobEndpoint
    storageQueueEndpoint: storage.outputs.queueEndpoint
    appInsightsConnectionString: appInsights.outputs.connectionString
    webPackageUrl: webPackageUrl
    dashboardAuthClientId: dashboardAuthClientId
    workspaceId: logAnalytics.outputs.workspaceId
  }
  dependsOn: [
    roleAssignments
  ]
}

module collectorFunction './modules/function-app.bicep' = {
  name: 'collector-function'
  params: {
    location: location
    tags: tags
    functionName: 'func-${baseName}'
    planName: 'asp-func-${baseName}'
    storageAccountName: storage.outputs.storageAccountName
    storageBlobEndpoint: storage.outputs.blobEndpoint
    deploymentContainerName: storage.outputs.deploymentContainerName
    managedIdentityId: managedIdentity.outputs.identityId
    managedIdentityClientId: managedIdentity.outputs.clientId
    collectorSecretUri: keyVault.outputs.collectorSecretUri
    cosmosEndpoint: cosmosDb.outputs.endpoint
    cosmosDatabase: cosmosDb.outputs.databaseName
    appInsightsConnectionString: appInsights.outputs.connectionString
    collectorTenantId: collectorTenantId
    collectorClientId: collectorClientId
    refreshMode: refreshMode
    nearRealTimeIntervalMinutes: nearRealTimeIntervalMinutes
    subscriptionFilter: subscriptionFilter
  }
  dependsOn: [
    roleAssignments
  ]
}

module collectorDeployment './modules/deployment-script.bicep' = {
  name: 'collector-deployment'
  params: {
    location: location
    tags: tags
    scriptName: 'ds-${baseName}'
    managedIdentityId: managedIdentity.outputs.identityId
    managedIdentityPrincipalId: managedIdentity.outputs.principalId
    managedIdentityClientId: managedIdentity.outputs.clientId
    functionAppName: collectorFunction.outputs.functionName
    resourceGroupName: resourceGroup().name
    collectorPackageUrl: collectorPackageUrl
  }
}

output dashboardUrl string = 'https://${dashboardApp.outputs.defaultHostname}'
output functionAppName string = collectorFunction.outputs.functionName
output cosmosEndpoint string = cosmosDb.outputs.endpoint
output storageAccountName string = storage.outputs.storageAccountName
output keyVaultName string = keyVault.outputs.kvName
output managedIdentityClientId string = managedIdentity.outputs.clientId
output collectorDeployed bool = collectorDeployment.outputs.deployed
