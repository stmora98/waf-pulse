param location string
param tags object
param planName string

@allowed(['B1', 'P1v3'])
param sku string = 'B1'

var skuConfig = {
  B1: {
    name: 'B1'
    tier: 'Basic'
    capacity: 1
  }
  P1v3: {
    name: 'P1v3'
    tier: 'PremiumV3'
    capacity: 1
  }
}

resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  tags: tags
  kind: 'Linux'
  sku: {
    name: skuConfig[sku].name
    tier: skuConfig[sku].tier
    capacity: skuConfig[sku].capacity
  }
  properties: {
    reserved: true
  }
}

output planId string = appServicePlan.id
