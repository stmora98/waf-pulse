param location string
param tags object
param appName string
param appServicePlanId string
param managedIdentityId string
param managedIdentityClientId string
param cosmosEndpoint string
param cosmosDatabase string
param storageAccountUrl string
param storageQueueEndpoint string
param appInsightsConnectionString string
param webPackageUrl string
param signInEnabled bool
param authClientId string
param authTenantId string
param authSecretUri string
param allowedUserIds array
param landingZoneMap string = ''
param workspaceId string

resource appService 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    serverFarmId: appServicePlanId
    httpsOnly: true
    keyVaultReferenceIdentity: managedIdentityId
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      alwaysOn: true
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      http20Enabled: true
      healthCheckPath: '/api/health'
      // Dependencies are vendored in the package, so the app starts without a build step.
      appCommandLine: 'PYTHONPATH=/home/site/wwwroot/.python_packages/lib/site-packages python -m gunicorn --bind=0.0.0.0:8000 --timeout 120 --workers 2 app:app'
      appSettings: concat([
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: webPackageUrl
        }
        {
          name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
          value: 'false'
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
          value: storageAccountUrl
        }
        {
          name: 'STORAGE_QUEUE_URL'
          value: storageQueueEndpoint
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsightsConnectionString
        }
        {
          name: 'WEBSITE_HEALTHCHECK_MAXPINGFAILURES'
          value: '10'
        }
        {
          name: 'LANDING_ZONE_MAP'
          value: landingZoneMap
        }
      ], signInEnabled ? [
        {
          name: 'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET'
          value: '@Microsoft.KeyVault(SecretUri=${authSecretUri})'
        }
      ] : [])
    }
  }
}

resource scmAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: appService
  name: 'scm'
  properties: {
    allow: false
  }
}

resource ftpAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: appService
  name: 'ftp'
  properties: {
    allow: false
  }
}

// Sign-in with Microsoft Entra ID through App Service authentication. It reuses the app registration of the
// collector, so the customer only adds the redirect URI after deployment. Only the listed users get in.
resource easyAuth 'Microsoft.Web/sites/config@2023-12-01' = if (signInEnabled) {
  parent: appService
  name: 'authsettingsV2'
  properties: {
    platform: {
      enabled: true
      runtimeVersion: '~1'
    }
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'RedirectToLoginPage'
      redirectToProvider: 'azureactivedirectory'
      excludedPaths: [
        '/api/health'
      ]
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: authClientId
          clientSecretSettingName: 'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET'
          openIdIssuer: '${environment().authentication.loginEndpoint}${authTenantId}/v2.0'
        }
        validation: {
          allowedAudiences: [
            authClientId
          ]
          defaultAuthorizationPolicy: {
            allowedPrincipals: {
              identities: allowedUserIds
            }
          }
        }
      }
    }
    login: {
      preserveUrlFragmentsForLogins: true
    }
  }
}
resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: appService
  name: 'to-log-analytics'
  properties: {
    workspaceId: workspaceId
    logs: [
      {
        category: 'AppServiceHTTPLogs'
        enabled: true
      }
      {
        category: 'AppServiceConsoleLogs'
        enabled: true
      }
      {
        category: 'AppServiceAppLogs'
        enabled: true
      }
    ]
  }
}

output appServiceId string = appService.id
output defaultHostname string = appService.properties.defaultHostName
