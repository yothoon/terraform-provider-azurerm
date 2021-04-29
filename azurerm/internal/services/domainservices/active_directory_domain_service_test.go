package domainservices_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance/check"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/clients"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/domainservices/parse"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

type ActiveDirectoryDomainServiceResource struct {
	adminPassword string
}

// Running all tests sequentially here in the same acctest (including the data source) since you can create only one
// AADDS resource per tenant, or per location, or per subscription, making parallel testing infeasible.
func TestAccActiveDirectoryDomainService_complete(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_active_directory_domain_service", "test")
	replicaSetTwoData := acceptance.BuildTestData(t, "azurerm_active_directory_domain_service_replica_set", "test_two")
	//replicaSetThreeData := acceptance.BuildTestData(t, "azurerm_active_directory_domain_service_replica_set", "test_three")
	//dataSourceData := acceptance.BuildTestData(t, "data.azurerm_active_directory_domain_service", "test")

	r := ActiveDirectoryDomainServiceResource{
		adminPassword: fmt.Sprintf("%s%s", "p@$$Wd", acctest.RandString(6)),
	}

	data.ResourceTest(t, r, []resource.TestStep{
		//{
		//	Config: r.complete(data),
		//	Check: resource.ComposeTestCheckFunc(
		//		check.That(data.ResourceName).ExistsInAzure(r),
		//		resource.TestCheckResourceAttr(data.ResourceName, "initial_replica_set.0.domain_controller_ip_addresses.#", "2"),
		//	),
		//},
		//data.ImportStep("secure_ldap.0.pfx_certificate", "secure_ldap.0.pfx_certificate_password"),

		{
			Config: r.completeWithReplicaSets(data),
			Check: resource.ComposeTestCheckFunc(
				//check.That(data.ResourceName).ExistsInAzure(r),
				check.That(replicaSetTwoData.ResourceName).ExistsInAzure(r),
			),
		},
		replicaSetTwoData.ImportStep(),

		// TODO: go back to the initial r.complete() config and use a custom check to ensure additional replica sets are gone

		//{
		//	Config: r.dataSource(data),
		//	Check: resource.ComposeTestCheckFunc(
		//		check.That(dataSourceName).ExistsInAzure(r),
		//		check.That(dataSourceName).Key("filtered_sync_enabled").HasValue("false"),
		//		check.That(dataSourceName).Key("secure_ldap.#").HasValue("1"),
		//		check.That(dataSourceName).Key("secure_ldap.0.enabled").HasValue("false"),
		//		check.That(dataSourceName).Key("location").HasValue(azure.NormalizeLocation(data.Locations.Primary)),
		//		check.That(dataSourceName).Key("notifications.#").HasValue("1"),
		//		check.That(dataSourceName).Key("notifications.0.additional_recipients.#").HasValue("2"),
		//		check.That(dataSourceName).Key("notifications.0.notify_dc_admins").HasValue("true"),
		//		check.That(dataSourceName).Key("notifications.0.notify_global_admins").HasValue("true"),
		//		check.That(dataSourceName).Key("initial_replica_set.#").HasValue("1"),
		//		check.That(dataSourceName).Key("initial_replica_set.0.domain_controller_ip_addresses.#").HasValue("2"),
		//		check.That(dataSourceName).Key("initial_replica_set.0.location").HasValue(azure.NormalizeLocation(data.Locations.Primary)),
		//		check.That(dataSourceName).Key("initial_replica_set.0.id").Exists(),
		//		check.That(dataSourceName).Key("initial_replica_set.0.service_status").Exists(),
		//		check.That(dataSourceName).Key("initial_replica_set.0.subnet_id").Exists(),
		//		//check.That(dataSourceName).Key("replica_sets.1.domain_controller_ip_addresses.#").HasValue("2"),
		//		//check.That(dataSourceName).Key("replica_sets.1.location").HasValue(azure.NormalizeLocation(data.Locations.Secondary)),
		//		//check.That(dataSourceName).Key("replica_sets.1.id").Exists(),
		//		//check.That(dataSourceName).Key("replica_sets.1.service_status").Exists(),
		//		//check.That(dataSourceName).Key("replica_sets.1.subnet_id").Exists(),
		//		check.That(dataSourceName).Key("resource_forest.#").HasValue("0"),
		//		check.That(dataSourceName).Key("security.#").HasValue("1"),
		//		check.That(dataSourceName).Key("security.0.ntlm_v1_enabled").HasValue("true"),
		//		check.That(dataSourceName).Key("security.0.sync_kerberos_passwords").HasValue("true"),
		//		check.That(dataSourceName).Key("security.0.sync_ntlm_passwords").HasValue("true"),
		//		check.That(dataSourceName).Key("security.0.sync_on_prem_passwords").HasValue("true"),
		//		check.That(dataSourceName).Key("security.0.tls_v1_enabled").HasValue("true"),
		//		check.That(dataSourceName).Key("sku").HasValue("Enterprise"),
		//	),
		//},
		//{
		//	Config:      r.requiresImport(data),
		//	ExpectError: acceptance.RequiresImportError(data.ResourceType),
		//},
	})
}

func (ActiveDirectoryDomainServiceResource) Exists(ctx context.Context, client *clients.Client, state *terraform.InstanceState) (*bool, error) {
	id, err := parse.DomainServiceID(state.ID)
	if err != nil {
		return nil, err
	}

	resp, err := client.DomainServices.DomainServicesClient.Get(ctx, id.ResourceGroup, id.Name)
	if err != nil {
		return nil, fmt.Errorf("reading DomainService: %+v", err)
	}

	return utils.Bool(resp.ID != nil), nil
}
func (r ActiveDirectoryDomainServiceResource) complete(data acceptance.TestData) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

provider "azuread" {}

resource "azurerm_resource_group" "test_one" {
  name     = "acctestRG-aadds-one-%[2]d"
  location = "%[1]s"
}

resource "azurerm_virtual_network" "test_one" {
  name                = "acctestVnet-aadds-one-%[2]d"
  location            = azurerm_resource_group.test_one.location
  resource_group_name = azurerm_resource_group.test_one.name
  address_space       = ["10.10.0.0/16"]
}

resource "azurerm_subnet" "aadds_one" {
  name                 = "acctestSubnet-aadds-one-%[2]d"
  resource_group_name  = azurerm_resource_group.test_one.name
  virtual_network_name = azurerm_virtual_network.test_one.name
  address_prefixes     = [cidrsubnet(azurerm_virtual_network.test_one.address_space.0, 8, 0)]
}

resource "azurerm_subnet" "workload_one" {
  name                 = "acctestSubnet-workload-one-%[2]d"
  resource_group_name  = azurerm_resource_group.test_one.name
  virtual_network_name = azurerm_virtual_network.test_one.name
  address_prefixes     = [cidrsubnet(azurerm_virtual_network.test_one.address_space.0, 8, 1)]
}

resource "azurerm_network_security_group" "aadds_one" {
  name                = "acctestNSG-aadds-one-%[2]d"
  location            = azurerm_resource_group.test_one.location
  resource_group_name = azurerm_resource_group.test_one.name

  security_rule {
    name                       = "AllowSyncWithAzureAD"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "AzureActiveDirectoryDomainServices"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowRD"
    priority                   = 201
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "CorpNetSaw"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowPSRemoting"
    priority                   = 301
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5986"
    source_address_prefix      = "AzureActiveDirectoryDomainServices"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowLDAPS"
    priority                   = 401
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "636"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource azurerm_subnet_network_security_group_association "test_one" {
  subnet_id                 = azurerm_subnet.aadds_one.id
  network_security_group_id = azurerm_network_security_group.aadds_one.id
}

resource "azurerm_resource_group" "aadds" {
  name     = "acctestRG-aadds-%[2]d"
  location = "%[1]s"
}

data "azuread_domains" "test" {
  only_initial = true
}

resource "azuread_service_principal" "test" {
  application_id = "2565bd9d-da50-47d4-8b85-4c97f669dc36" // published app for domain services
}

resource "azuread_group" "test" {
  name        = "AAD DC Administrators"
  description = "Delegated group to administer Azure AD Domain Services"
}

resource "azuread_user" "test" {
  user_principal_name = "acctestAADDSAdminUser-%[2]d@${data.azuread_domains.test.domains.0.domain_name}"
  display_name        = "acctestAADDSAdminUser-%[2]d"
  password            = "%[4]s"
}

resource "azuread_group_member" "test" {
  group_object_id  = azuread_group.test.object_id
  member_object_id = azuread_user.test.object_id
}

resource "azurerm_active_directory_domain_service" "test" {
  name                = "acctest-%[3]s"
  location            = azurerm_resource_group.aadds.location
  resource_group_name = azurerm_resource_group.aadds.name

  domain_name           = "never.gonna.shut.you.down"
  sku                   = "Enterprise"
  filtered_sync_enabled = false

  notifications {
    additional_recipients = ["notifyA@example.net", "notifyB@example.org"]
    notify_dc_admins      = true
    notify_global_admins  = true
  }

  initial_replica_set {
    location  = azurerm_virtual_network.test_one.location
    subnet_id = azurerm_subnet.aadds_one.id
  }

  //replica_set {
  //  location  = azurerm_virtual_network.test_two.location
  //  subnet_id = azurerm_subnet.aadds_two.id
  //}

  //secure_ldap {
  //  enabled                  = true
  //  external_access          = true
  //  pfx_certificate          = "TODO Generate a dummy pfx key+cert (https://docs.microsoft.com/en-us/azure/active-directory-domain-services/tutorial-configure-ldaps)"
  //  pfx_certificate_password = "test"
  //}

  security {
    ntlm_v1_enabled         = true
    sync_kerberos_passwords = true
    sync_ntlm_passwords     = true
    sync_on_prem_passwords  = true
    tls_v1_enabled          = true
  }

  tags = {
    Environment = "test"
  }

  depends_on = [
    azuread_service_principal.test,
    azurerm_subnet_network_security_group_association.test_one,
  ]
}

resource "azurerm_virtual_network_dns_servers" "test_one" {
  virtual_network_id = azurerm_virtual_network.test_one.id
  dns_servers        = azurerm_active_directory_domain_service.test.initial_replica_set.0.domain_controller_ip_addresses
}
`, data.Locations.Primary, data.RandomInteger, data.RandomString, r.adminPassword)
}

func (r ActiveDirectoryDomainServiceResource) completeWithReplicaSets(data acceptance.TestData) string {
	return fmt.Sprintf(`
%[1]s

// TODO: data source for testing, remove this
data "azurerm_active_directory_domain_service" "test" {
  name                = "acctest-3rd83"
  resource_group_name = "acctestRG-aadds-210428111031210654"
}

## REPLICA SET 2

resource "azurerm_resource_group" "test_two" {
  name     = "acctestRG-aadds-two-%[4]d"
  location = "%[2]s"
}

resource "azurerm_virtual_network" "test_two" {
  name                = "acctestVnet-aadds-two-%[4]d"
  location            = azurerm_resource_group.test_two.location
  resource_group_name = azurerm_resource_group.test_two.name
  address_space       = ["10.20.0.0/16"]
}

resource "azurerm_subnet" "aadds_two" {
  name                 = "acctestSubnet-aadds-two-%[4]d"
  resource_group_name  = azurerm_resource_group.test_two.name
  virtual_network_name = azurerm_virtual_network.test_two.name
  address_prefixes     = [cidrsubnet(azurerm_virtual_network.test_two.address_space.0, 8, 0)]
}

resource "azurerm_subnet" "workload_two" {
  name                 = "acctestSubnet-workload-two-%[4]d"
  resource_group_name  = azurerm_resource_group.test_two.name
  virtual_network_name = azurerm_virtual_network.test_two.name
  address_prefixes     = [cidrsubnet(azurerm_virtual_network.test_two.address_space.0, 8, 1)]
}

resource "azurerm_network_security_group" "aadds_two" {
  name                = "acctestNSG-aadds-two-%[4]d"
  location            = azurerm_resource_group.test_two.location
  resource_group_name = azurerm_resource_group.test_two.name

  security_rule {
    name                       = "AllowSyncWithAzureAD"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "AzureActiveDirectoryDomainServices"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowRD"
    priority                   = 201
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "CorpNetSaw"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowPSRemoting"
    priority                   = 301
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5986"
    source_address_prefix      = "AzureActiveDirectoryDomainServices"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowLDAPS"
    priority                   = 401
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "636"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource azurerm_subnet_network_security_group_association "test_two" {
  subnet_id                 = azurerm_subnet.aadds_two.id
  network_security_group_id = azurerm_network_security_group.aadds_two.id
}

resource "azurerm_virtual_network_peering" "test_one_two" {
  name = "acctestVnet-aadds-one-two-%[4]d"
  //resource_group_name       = azurerm_virtual_network.test_one.resource_group_name
  //virtual_network_name      = azurerm_virtual_network.test_one.name
  resource_group_name       = "acctestRG-aadds-one-210428111031210654"
  virtual_network_name      = "acctestVnet-aadds-one-210428111031210654"
  remote_virtual_network_id = azurerm_virtual_network.test_two.id

  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  allow_virtual_network_access = true
  use_remote_gateways          = false
}

resource "azurerm_virtual_network_peering" "test_two_one" {
  name                      = "acctestVnet-aadds-two-one-%[4]d"
  resource_group_name       = azurerm_virtual_network.test_two.resource_group_name
  virtual_network_name      = azurerm_virtual_network.test_two.name
  remote_virtual_network_id = "/subscriptions/1a6092a6-137e-4025-9a7c-ef77f76f2c02/resourceGroups/acctestRG-aadds-one-210428111031210654/providers/Microsoft.Network/virtualNetworks/acctestVnet-aadds-one-210428111031210654"

  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  allow_virtual_network_access = true
  use_remote_gateways          = false
}

resource "azurerm_virtual_network_dns_servers" "test_two" {
  virtual_network_id = azurerm_virtual_network.test_two.id
  //dns_servers        = azurerm_active_directory_domain_service.test.initial_replica_set.0.domain_controller_ip_addresses
  dns_servers = data.azurerm_active_directory_domain_service.test.initial_replica_set.0.domain_controller_ip_addresses
}

//resource "azurerm_active_directory_domain_service_replica_set" "test_two" {
//  //domain_service_id = azurerm_active_directory_domain_service.test.id
//  domain_service_id = data.azurerm_active_directory_domain_service.test.id
//  location          = azurerm_resource_group.test_two.location
//  subnet_id         = azurerm_subnet.aadds_two.id
//
//  depends_on = [
//    azurerm_subnet_network_security_group_association.test_two,
//    azurerm_virtual_network_peering.test_one_two,
//    azurerm_virtual_network_peering.test_two_one,
//  ]
//}

## REPLICA SET 3

//resource "azurerm_resource_group" "test_three" {
//  name     = "acctestRG-aadds-three-%[4]d"
//  location = "%[3]s"
//}
//
//resource "azurerm_virtual_network" "test_three" {
//  name                = "acctestVnet-aadds-three-%[4]d"
//  location            = azurerm_resource_group.test_three.location
//  resource_group_name = azurerm_resource_group.test_three.name
//  address_space       = ["10.30.0.0/16"]
//}
//
//resource "azurerm_subnet" "aadds_three" {
//  name                 = "acctestSubnet-aadds-three-%[4]d"
//  resource_group_name  = azurerm_resource_group.test_three.name
//  virtual_network_name = azurerm_virtual_network.test_three.name
//  address_prefixes     = [cidrsubnet(azurerm_virtual_network.test_three.address_space.0, 8, 0)]
//}
//
//resource "azurerm_subnet" "workload_three" {
//  name                 = "acctestSubnet-workload-three-%[4]d"
//  resource_group_name  = azurerm_resource_group.test_three.name
//  virtual_network_name = azurerm_virtual_network.test_three.name
//  address_prefixes     = [cidrsubnet(azurerm_virtual_network.test_three.address_space.0, 8, 1)]
//}
//
//resource "azurerm_network_security_group" "aadds_three" {
//  name                = "acctestNSG-aadds-three-%[4]d"
//  location            = azurerm_resource_group.test_three.location
//  resource_group_name = azurerm_resource_group.test_three.name
//
//  security_rule {
//    name                       = "AllowSyncWithAzureAD"
//    priority                   = 101
//    direction                  = "Inbound"
//    access                     = "Allow"
//    protocol                   = "Tcp"
//    source_port_range          = "*"
//    destination_port_range     = "443"
//    source_address_prefix      = "AzureActiveDirectoryDomainServices"
//    destination_address_prefix = "*"
//  }
//
//  security_rule {
//    name                       = "AllowRD"
//    priority                   = 201
//    direction                  = "Inbound"
//    access                     = "Allow"
//    protocol                   = "Tcp"
//    source_port_range          = "*"
//    destination_port_range     = "3389"
//    source_address_prefix      = "CorpNetSaw"
//    destination_address_prefix = "*"
//  }
//
//  security_rule {
//    name                       = "AllowPSRemoting"
//    priority                   = 301
//    direction                  = "Inbound"
//    access                     = "Allow"
//    protocol                   = "Tcp"
//    source_port_range          = "*"
//    destination_port_range     = "5986"
//    source_address_prefix      = "AzureActiveDirectoryDomainServices"
//    destination_address_prefix = "*"
//  }
//
//  security_rule {
//    name                       = "AllowLDAPS"
//    priority                   = 401
//    direction                  = "Inbound"
//    access                     = "Allow"
//    protocol                   = "Tcp"
//    source_port_range          = "*"
//    destination_port_range     = "636"
//    source_address_prefix      = "*"
//    destination_address_prefix = "*"
//  }
//}
//
//resource azurerm_subnet_network_security_group_association "test_three" {
//  subnet_id                 = azurerm_subnet.aadds_three.id
//  network_security_group_id = azurerm_network_security_group.aadds_three.id
//}
//
//resource "azurerm_virtual_network_peering" "test_one_three" {
//  name                      = "acctestVnet-aadds-one-three-%[4]d"
//  resource_group_name       = azurerm_virtual_network.test_one.resource_group_name
//  virtual_network_name      = azurerm_virtual_network.test_one.name
//  remote_virtual_network_id = azurerm_virtual_network.test_three.id
//
//  allow_forwarded_traffic      = true
//  allow_gateway_transit        = false
//  allow_virtual_network_access = true
//  use_remote_gateways          = false
//}
//
//resource "azurerm_virtual_network_peering" "test_three_one" {
//  name                      = "acctestVnet-aadds-three-one-%[4]d"
//  resource_group_name       = azurerm_virtual_network.test_three.resource_group_name
//  virtual_network_name      = azurerm_virtual_network.test_three.name
//  remote_virtual_network_id = azurerm_virtual_network.test_one.id
//
//  allow_forwarded_traffic      = true
//  allow_gateway_transit        = false
//  allow_virtual_network_access = true
//  use_remote_gateways          = false
//}
//
//resource "azurerm_virtual_network_dns_servers" "test_three" {
//  virtual_network_id = azurerm_virtual_network.test_three.id
//  //dns_servers        = azurerm_active_directory_domain_service.test.initial_replica_set.0.domain_controller_ip_addresses
//  dns_servers = data.azurerm_active_directory_domain_service.test.initial_replica_set.0.domain_controller_ip_addresses
//}
//
//resource "azurerm_active_directory_domain_service_replica_set" "test_three" {
//  //domain_service_id = azurerm_active_directory_domain_service.test.id
//  domain_service_id = data.azurerm_active_directory_domain_service.test.id
//  location          = azurerm_resource_group.test_three.location
//  subnet_id         = azurerm_subnet.aadds_three.id
//
//  depends_on = [
//    azurerm_subnet_network_security_group_association.test_three,
//    azurerm_virtual_network_peering.test_one_three,
//    azurerm_virtual_network_peering.test_three_one,
//  ]
//}
`, "", data.Locations.Secondary, data.Locations.Ternary, data.RandomInteger)
}

func (r ActiveDirectoryDomainServiceResource) dataSource(data acceptance.TestData) string {
	return fmt.Sprintf(`
%[1]s

data "azurerm_active_directory_domain_service" "test" {
  name                = azurerm_active_directory_domain_service.test.name
  resource_group_name = azurerm_active_directory_domain_service.test.resource_group_name
}
`, "") //r.completeWithReplicaSets(data))
}

func (r ActiveDirectoryDomainServiceResource) requiresImport(data acceptance.TestData) string {
	return fmt.Sprintf(`
%[1]s

resource "azurerm_active_directory_domain_service" "import" {
  domain_name         = azurerm_active_directory_domain_service.test.domain_name
  location            = azurerm_active_directory_domain_service.test.location
  name                = azurerm_active_directory_domain_service.test.name
  resource_group_name = azurerm_active_directory_domain_service.test.resource_group_name
  sku                 = azurerm_active_directory_domain_service.test.sku

  replica_set {
    location  = azurerm_active_directory_domain_service.test.replica_set.0.location
    subnet_id = azurerm_active_directory_domain_service.test.replica_set.0.subnet_id
  }

  replica_set {
    location  = azurerm_active_directory_domain_service.test.replica_set.1.location
    subnet_id = azurerm_active_directory_domain_service.test.replica_set.1.subnet_id
  }
}
`, r.complete(data))
}
