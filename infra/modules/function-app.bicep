param location string
param tags object
param functionName string
param planName string
param storageAccountName string
param storageBlobEndpoint string
param deploymentContainerName string
param managedIdentityId string
param managedIdentityClientId string
param collectorSecretUri string
param cosmosEndpoint string
param cosmosDatabase string
param appInsightsConnectionString string
param collectorTenantId string
param collectorClientId string
param refreshMode string
param nearRealTimeIntervalMinutes int
param subscriptionFilter string

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  tags: tags
  kind: 'functionapp'
  sku: {
    name: 'FC1'
    tier: 'FlexConsumption'
  }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    keyVaultReferenceIdentity: managedIdentityId
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'AzureWebJobsStorage__accountName'
          value: storageAccountName
        }
        {
          name: 'AzureWebJobsStorage__credential'
          value: 'managedidentity'
        }
        {
          name: 'AzureWebJobsStorage__clientId'
          value: managedIdentityClientId
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsightsConnectionString
        }
        {
          name: 'MANAGED_IDENTITY_CLIENT_ID'
          value: managedIdentityClientId
        }
        {
          name: 'COSMOS_ENDPOINT'
          value: cosmosEndpoint
        }
        {
          name: 'COSMOS_DATABASE'
          value: cosmosDatabase
        }
        {
          name: 'STORAGE_ACCOUNT_URL'
          value: storageBlobEndpoint
        }
        {
          name: 'COLLECTOR_TENANT_ID'
          value: collectorTenantId
        }
        {
          name: 'COLLECTOR_CLIENT_ID'
          value: collectorClientId
        }
        {
          name: 'COLLECTOR_CLIENT_SECRET'
          value: '@Microsoft.KeyVault(SecretUri=${collectorSecretUri})'
        }
        {
          name: 'REFRESH_MODE'
          value: refreshMode
        }
        {
          name: 'NEAR_REAL_TIME_INTERVAL_MINUTES'
          value: string(nearRealTimeIntervalMinutes)
        }
        {
          name: 'SUBSCRIPTION_FILTER'
          value: subscriptionFilter
        }
      ]
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storageBlobEndpoint}${deploymentContainerName}'
          authentication: {
            type: 'UserAssignedIdentity'
            userAssignedIdentityResourceId: managedIdentityId
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: 40
        instanceMemoryMB: 2048
      }
      runtime: {
        name: 'python'
        version: '3.12'
      }
    }
  }
}

output functionName string = functionApp.name
output functionId string = functionApp.id
