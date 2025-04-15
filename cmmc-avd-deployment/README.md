
# 🇺🇸 Azure Gov ARM Deployments – NetworkCoverage

This repository contains modular ARM templates for deploying secure and scalable infrastructure in Azure Government.

---

## 📡 Step 1: Deploy Management Networking Infrastructure

This step provisions the core management environment:

- **Management Virtual Network** with 4 subnets:
  - `AzureFirewallSubnet` – for Azure Firewall
  - `AzureBastionSubnet` – for Azure Bastion
  - `ztna-snet` – Appgate collective
  - `avd-snet` – AVD management
- **Azure Firewall** with policy and application rules
- **Azure Bastion** (Standard SKU with tunneling, shareable link, file copy)
- **Route Table** with a default route
- **Diagnostic Settings** for monitoring
- **Log Analytics Workspaces** (for both firewall and VNet logs)

[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FNetworkCoverage%2Fazure-resource-manager%2Fmain%2Fcmmc-avd-deployment%2Fvirtual-network%2F1-mgmt-vnet-ui.json)

> 📁 [`1-mgmt-vnet.json`](https://github.com/NetworkCoverage/azure-resource-manager/blob/main/cmmc-avd-deployment/cmmc-avd-deployment/virtual-network/1-mgmt-vnet.json)

---

## 🧱 Step 2: Deploy Production Networking Infrastructure

This step provisions a dedicated production network environment:

- **Production Virtual Network** with 2 subnets:
  - AVD host servers
  - Application servers
- **Diagnostic Settings** and a dedicated **Log Analytics Workspace**
- **VNet Peering** to the management network for secure cross-network communication

[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FNetworkCoverage%2Fazure-resource-manager%2Fmain%2Fcmmc-avd-deployment%2Fvirtual-network%2F2-prod-vnet-ui.json)

> 📁 [`2-prod-vnet.json`](https://github.com/NetworkCoverage/azure-resource-manager/blob/main/cmmc-avd-deployment/virtual-network/2-prod-vnet.json)

---

## ⚠️ Legal Notice

These templates are provided as-is for internal authorized use. Please review parameters and configurations before deployment to production.
