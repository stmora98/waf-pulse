param location string
param tags object
param cosmosName string
param managedIdentityPrincipalId string
param workspaceId string

var databaseName = 'cafwaf'
// defaultTtl -1 enables per-document expiry. Only findings set a ttl, so the other containers never expire.
var containers = [
  {
    name: 'runs'
    partitionKey: '/subscriptionId'
  }
  {
    name: 'findings'
    partitionKey: '/runId'
  }
  {
    name: 'summaries'
    partitionKey: '/runId'
  }
  {
    name: 'scores'
    partitionKey: '/subscriptionId'
  }
]

resource cosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2024-05-15' = {
  name: cosmosName
  location: location
  tags: tags
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    enableFreeTier: false
    capabilities: [
      {
        name: 'EnableServerless'
      }
    ]
    disableLocalAuth: true
    minimalTlsVersion: 'Tls12'
    publicNetworkAccess: 'Enabled'
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
    locations: [
      {
        locationName: location
        failoverPriority: 0
        isZoneRedundant: false
      }
    ]
  }
}

resource database 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2024-05-15' = {
  parent: cosmosAccount
  name: databaseName
  properties: {
    resource: {
      id: databaseName
    }
  }
}

resource container 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = [
  for c in containers: {
    parent: database
    name: c.name
    properties: {
      resource: {
        id: c.name
        defaultTtl: -1
        partitionKey: {
          paths: [
            c.partitionKey
          ]
          kind: 'Hash'
        }
      }
    }
  }
]

// Built-in "Cosmos DB Built-in Data Contributor" data-plane role
resource dataContributor 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2024-05-15' = {
  parent: cosmosAccount
  name: guid(cosmosAccount.id, managedIdentityPrincipalId, '00000000-0000-0000-0000-000000000002')
  properties: {
    roleDefinitionId: '${cosmosAccount.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002'
    principalId: managedIdentityPrincipalId
    scope: cosmosAccount.id
  }
}

resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: cosmosAccount
  name: 'to-log-analytics'
  properties: {
    workspaceId: workspaceId
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
  }
}

output endpoint string = cosmosAccount.properties.documentEndpoint
output cosmosId string = cosmosAccount.id
output databaseName string = database.name
