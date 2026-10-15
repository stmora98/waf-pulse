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

// Lets the identity publish the package to the Function App.
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
    // Keep the script and its log for two hours so a failed publish can be diagnosed.
    retentionInterval: 'PT2H'
    cleanupPreference: 'OnExpiration'
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

# One line, no quotes or backslashes, so the text is safe inside the JSON output.
clean() {
  printf '%s' "$1" | tr -d '"\\\r' | tr '\n' ' ' | cut -c1-300
}

# The package may not be published yet; infrastructure must still deploy.
if ! curl -fsSL "$PACKAGE_URL" -o /tmp/collector.zip; then
  echo "WARNING: could not download $PACKAGE_URL. Publish a release and run the deployment again."
  result false "package not available"
  exit 0
fi

az login --identity --username "$IDENTITY_CLIENT_ID" --allow-no-subscriptions --output none

# Python on Flex Consumption is published with a remote build (dependencies are installed by the platform).
# Role assignments can take a few minutes to propagate, so failures are retried.
error=""
for attempt in 1 2 3; do
  if error=$(az functionapp deployment source config-zip \
      --src /tmp/collector.zip --name "$FUNCTION_APP" --resource-group "$RESOURCE_GROUP" \
      --build-remote true 2>&1); then
    result true "collector package deployed"
    exit 0
  fi
  echo "Attempt $attempt failed: $error"
  sleep 60
done

echo "WARNING: collector package could not be deployed."
result false "$(clean "$error")"
exit 0
'''
  }
}

output deployed bool = deployCollector.properties.outputs.deployed
output message string = deployCollector.properties.outputs.message
