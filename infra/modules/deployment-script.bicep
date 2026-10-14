param location string
param tags object
param scriptName string
param managedIdentityId string
param managedIdentityPrincipalId string
param managedIdentityClientId string
param functionAppName string
param resourceGroupName string
param collectorPackageUrl string

var websiteContributor = 'de139f84-1756-47ae-9be6-808fbbe84772'

resource functionApp 'Microsoft.Web/sites@2023-12-01' existing = {
  name: functionAppName
}

// Lets the identity publish the package through the management plane (basic publishing credentials are not used).
resource websiteContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: functionApp
  name: guid(functionApp.id, managedIdentityPrincipalId, websiteContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', websiteContributor)
    principalId: managedIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource deployCollector 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: scriptName
  location: location
  tags: tags
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  dependsOn: [
    websiteContributorRole
  ]
  properties: {
    azCliVersion: '2.67.0'
    timeout: 'PT30M'
    retentionInterval: 'PT1H'
    cleanupPreference: 'OnSuccess'
    environmentVariables: [
      {
        name: 'PACKAGE_URL'
        value: collectorPackageUrl
      }
      {
        name: 'FUNCTION_APP'
        value: functionAppName
      }
      {
        name: 'RESOURCE_GROUP'
        value: resourceGroupName
      }
      {
        name: 'IDENTITY_CLIENT_ID'
        value: managedIdentityClientId
      }
    ]
    scriptContent: '''
#!/bin/bash
set -u

result() {
  echo "{\"deployed\": $1, \"message\": \"$2\"}" > "$AZ_SCRIPTS_OUTPUT_PATH"
}

# The package may not be published yet; infrastructure must still deploy.
if ! curl -fsSL "$PACKAGE_URL" -o /tmp/collector.zip; then
  echo "WARNING: could not download $PACKAGE_URL. Publish a release and run the deployment again."
  result false "package not available"
  exit 0
fi

az login --identity --username "$IDENTITY_CLIENT_ID" --allow-no-subscriptions --output none

# Role assignments can take a few minutes to propagate.
for attempt in 1 2 3 4 5 6; do
  if az functionapp deploy --resource-group "$RESOURCE_GROUP" --name "$FUNCTION_APP" --src-path /tmp/collector.zip --type zip --output none; then
    result true "collector package deployed"
    exit 0
  fi
  echo "Attempt $attempt failed, retrying in 30 seconds"
  sleep 30
done

echo "WARNING: collector package could not be deployed."
result false "deployment failed"
exit 0
'''
  }
}

output deployed bool = deployCollector.properties.outputs.deployed
