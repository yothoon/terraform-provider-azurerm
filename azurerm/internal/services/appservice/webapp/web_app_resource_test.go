package webapp_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance/check"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/clients"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/appservice/parse"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tf/pluginsdk"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

type WebAppResource struct{}

const osTypeWindows = "Windows"
const osTypeLinux = "Linux"

func TestAccWebApp_basicWindows(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.basic(data, osTypeWindows),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_basicLinux(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.basic(data, osTypeLinux),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("kind").HasValue("app,linux"),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_requiresImport(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.basic(data, osTypeWindows),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.RequiresImportErrorStep(r.requiresImport),
	})
}

func TestAccWebApp_completeWindows(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.completeWindows(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_completeUpdated(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.completeWindows(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
		{
			Config: r.completeUpdate(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_windowsLogsUpdate(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.basic(data, osTypeWindows),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
		{
			Config: r.logsEnabled(data, osTypeWindows),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
		{
			Config: r.basic(data, osTypeWindows),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_windowsWithDotNet(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.windowsDotNet(data, "v4.0"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_windowsWithPhp(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.windowsPhp(data, "7.3"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_windowsWithPhpUpdate(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.windowsPhp(data, "7.3"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
		{
			Config: r.windowsPhp(data, "7.4"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
		{
			Config: r.windowsPhp(data, "5.6"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_windowsWithPython(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.windowsPython(data, "2.7"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_windowsWithPythonUpdate(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.basic(data, osTypeWindows),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
		{
			Config: r.windowsPython(data, "2.7"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
		{
			Config: r.basic(data, osTypeWindows),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("site_config.0.windows_application_stack.0.python_version").HasValue(""),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_windowsWithJava7Java(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.windowsJava(data, "1.7", "JAVA", "9.3"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_windowsWithJava8Java(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.windowsJava(data, "1.8", "JAVA", "9.3"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_windowsWithJava11Java(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.windowsJava(data, "11", "JAVA", "9.3"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_windowsWithJava7Jetty(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.windowsJava(data, "1.7", "JETTY", "9.3"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_basicDockerContainer(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.windowsDocker(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("site_config.0.windows_fx_version").HasValue("DOCKER|mcr.microsoft.com/azure-app-service/samples/aspnethelloworld:latest"),
			),
		},
		data.ImportStep(),
	})
}

// TODO: More Java matrix tests...

func TestAccWebApp_windowsWithNode(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.windowsNode(data, "10.1"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccWebApp_windowsWithMultiStack(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_web_app", "test")
	r := WebAppResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.windowsMultiStack(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func (r WebAppResource) Exists(ctx context.Context, client *clients.Client, state *pluginsdk.InstanceState) (*bool, error) {
	id, err := parse.WebAppID(state.ID)
	if err != nil {
		return nil, err
	}

	resp, err := client.AppService.WebAppsClient.Get(ctx, id.ResourceGroup, id.SiteName)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			return utils.Bool(false), nil
		}
		return nil, fmt.Errorf("retrieving Web App %s: %+v", id, err)
	}
	if utils.ResponseWasNotFound(resp.Response) {
		return utils.Bool(false), nil
	}
	return utils.Bool(true), nil
}

func (r WebAppResource) basic(data acceptance.TestData, osType string) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_web_app" "test" {
  name                = "acctestAS-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  service_plan_id     = azurerm_app_service_plan.test.id
}
`, r.baseTemplate(data, osType), data.RandomInteger)
}

func (r WebAppResource) completeWindows(data acceptance.TestData) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_web_app" "test" {
  name                = "acctestAS-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  service_plan_id     = azurerm_app_service_plan.test.id

  app_settings = {
    foo = "bar"
  }

  auth_settings {
    enabled = true
    issuer  = "https://sts.windows.net/%s"

    additional_login_params = {
      test_key = "test_value"
    }

    active_directory {
      client_id     = "aadclientid"
      client_secret = "aadsecret"

      allowed_audiences = [
        "activedirectorytokenaudiences",
      ]
    }

    facebook {
      app_id     = "facebookappid"
      app_secret = "facebookappsecret"

      oauth_scopes = [
        "facebookscope",
      ]
    }
  }

  backup {
    name                = "acctest"
    storage_account_url = "https://${azurerm_storage_account.test.name}.blob.core.windows.net/${azurerm_storage_container.test.name}${data.azurerm_storage_account_sas.test.sas}&sr=b"
    schedule {
      frequency_interval = 1
      frequency_unit     = "Day"
    }
  }

  logs {
    application_logs {
      file_system_level = "Warning"
      azure_blob_storage {
        level             = "Information"
        sas_url           = "http://x.com/"
        retention_in_days = 2
      }
    }

    http_logs {
      azure_blob_storage {
        sas_url           = "https://${azurerm_storage_account.test.name}.blob.core.windows.net/${azurerm_storage_container.test.name}${data.azurerm_storage_account_sas.test.sas}&sr=b"
        retention_in_days = 3
      }
    }
  }

  client_affinity_enabled = true
  client_cert_enabled     = true
  client_cert_mode        = "Optional"

  connection_string {
    name  = "First"
    value = "first-connection-string"
    type  = "Custom"
  }

  connection_string {
    name  = "Second"
    value = "some-postgresql-connection-string"
    type  = "PostgreSQL"
  }

  enabled    = false
  https_only = true

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.test.id]
  }

  site_config {
    always_on = true
    // api_management_config_id = // TODO
    app_command_line = "/sbin/myserver -b 0.0.0.0"
    default_documents = [
      "first.html",
      "second.jsp",
      "third.aspx",
      "hostingstart.html",
    ]
    http2_enabled               = true
    scm_use_main_ip_restriction = true
    local_mysql                 = true
    managed_pipeline_mode       = "Integrated"
    remote_debugging            = true
    remote_debugging_version    = "VS2019"
    use_32_bit_worker           = true
    websockets                  = true
    ftps_state                  = "FtpsOnly"
    health_check_path           = "/health"
    number_of_workers           = 1
    minimum_tls_version         = "1.1"
    scm_minimum_tls_version     = "1.1"
    cors {
      allowed_origins = [
        "http://www.contoso.com",
        "www.contoso.com",
      ]

      support_credentials = true
    }

    // auto_swap_slot_name = // TODO
  }

  storage_account {
    name         = "files"
    type         = "AzureFiles"
    account_name = azurerm_storage_account.test.name
    share_name   = azurerm_storage_share.test.name
    access_key   = azurerm_storage_account.test.primary_access_key
    mount_path   = "\\mounts\\files"
  }

  tags = {
    foo = "bar"
  }
}
`, r.templateWithStorageAccount(data, osTypeWindows), data.RandomInteger, data.Client().TenantID)
}

func (r WebAppResource) completeUpdate(data acceptance.TestData) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_web_app" "test" {
  name                = "acctestAS-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  service_plan_id     = azurerm_app_service_plan.test.id

  app_settings = {
    foo    = "bar"
    SECRET = "sauce"
  }

  auth_settings {
    enabled = true
    issuer  = "https://sts.windows.net/%s"

    additional_login_params = {
      test_key = "test_value_new"
    }

    active_directory {
      client_id     = "aadclientid"
      client_secret = "aadsecretNew"

      allowed_audiences = [
        "activedirectorytokenaudiences",
      ]
    }

    facebook {
      app_id     = "updatedfacebookappid"
      app_secret = "updatedfacebookappsecret"

      oauth_scopes = [
        "facebookscope",
        "facebookscope2"
      ]
    }
  }

  backup {
    name                = "acctest"
    storage_account_url = "https://${azurerm_storage_account.test.name}.blob.core.windows.net/${azurerm_storage_container.test.name}${data.azurerm_storage_account_sas.test.sas}&sr=b"
    schedule {
      frequency_interval = 12
      frequency_unit     = "Hour"
    }
  }

  logs {
    application_logs {
      file_system_level = "Warning"
      azure_blob_storage {
        level             = "Warning"
        sas_url           = "http://x.com/"
        retention_in_days = 7
      }
    }

    http_logs {
      azure_blob_storage {
        sas_url           = "https://${azurerm_storage_account.test.name}.blob.core.windows.net/${azurerm_storage_container.test.name}${data.azurerm_storage_account_sas.test.sas}&sr=b"
        retention_in_days = 5
      }
    }
  }

  client_affinity_enabled = true
  client_cert_enabled     = true
  client_cert_mode        = "Optional"

  connection_string {
    name  = "First"
    value = "first-connection-string"
    type  = "Custom"
  }

  enabled    = true
  https_only = true

  identity {
    type         = "SystemAssigned, UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.test.id]
  }

  site_config {
    always_on = true
    // api_management_config_id = // TODO
    app_command_line = "/sbin/myserver -b 0.0.0.0"
    default_documents = [
      "first.html",
      "second.jsp",
      "third.aspx",
      "hostingstart.html",
    ]
    http2_enabled               = true
    scm_use_main_ip_restriction = true
    local_mysql                 = true
    managed_pipeline_mode       = "Integrated"
    remote_debugging            = true
    remote_debugging_version    = "VS2017"
    websockets                  = true
    ftps_state                  = "FtpsOnly"
    health_check_path           = "/health2"
    number_of_workers           = 2
    // windows_fx_version          = "DOCKER|mcr.microsoft.com/azure-app-service/samples/aspnethelloworld:latest"
    minimum_tls_version     = "1.2"
    scm_minimum_tls_version = "1.2"
    cors {
      allowed_origins = [
        "http://www.contoso.com",
        "www.contoso.com",
        "contoso.com",
      ]

      support_credentials = true
    }
    // auto_swap_slot_name = // TODO - Not supported yet
  }

  storage_account {
    name         = "files"
    type         = "AzureFiles"
    account_name = azurerm_storage_account.test.name
    share_name   = azurerm_storage_share.test.name
    access_key   = azurerm_storage_account.test.primary_access_key
    mount_path   = "\\mounts\\updatedfiles"
  }

  tags = {
    foo = "bar"
  }
}
`, r.templateWithStorageAccount(data, "Windows"), data.RandomInteger, data.Client().TenantID)
}

func (r WebAppResource) requiresImport(data acceptance.TestData) string {
	return fmt.Sprintf(`
%s

resource "azurerm_web_app" "import" {
  name                = azurerm_web_app.test.name
  location            = azurerm_web_app.test.location
  resource_group_name = azurerm_web_app.test.resource_group_name
  service_plan_id     = azurerm_web_app.test.service_plan_id
}
`, r.basic(data, osTypeWindows))
}

func (r WebAppResource) windowsDotNet(data acceptance.TestData, dotNetVersion string) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_web_app" "test" {
  name                = "acctestWA-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  service_plan_id     = azurerm_app_service_plan.test.id

  site_config {
    windows_application_stack {
      dotnet_framework_version = "%s"
    }
  }
}

`, r.baseTemplate(data, osTypeWindows), data.RandomInteger, dotNetVersion)
}

func (r WebAppResource) windowsDocker(data acceptance.TestData) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_web_app" "test" {
  name                = "acctestWA-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  service_plan_id     = azurerm_app_service_plan.test.id

  app_settings = {
    "DOCKER_REGISTRY_SERVER_URL"      = "https://mcr.microsoft.com"
    "DOCKER_REGISTRY_SERVER_USERNAME" = ""
    "DOCKER_REGISTRY_SERVER_PASSWORD" = ""
  }

  site_config {
    windows_application_stack {
      docker_container_registry = "%s"
      docker_container_name     = "%s"
      docker_container_tag      = "%s"
    }
  }
}

`, r.baseTemplate(data, osTypeWindows), data.RandomInteger, "mcr.microsoft.com", "azure-app-service/samples/aspnethelloworld", "latest")
}

func (r WebAppResource) windowsNode(data acceptance.TestData, nodeVersion string) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_web_app" "test" {
  name                = "acctestWA-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  service_plan_id     = azurerm_app_service_plan.test.id

  site_config {
    windows_application_stack {
      node_version = "%s"
    }
  }
}

`, r.baseTemplate(data, osTypeWindows), data.RandomInteger, nodeVersion)
}

func (r WebAppResource) windowsPhp(data acceptance.TestData, phpVersion string) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_web_app" "test" {
  name                = "acctestWA-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  service_plan_id     = azurerm_app_service_plan.test.id

  site_config {
    windows_application_stack {
      php_version = "%s"
    }
  }
}

`, r.baseTemplate(data, osTypeWindows), data.RandomInteger, phpVersion)
}

func (r WebAppResource) windowsPython(data acceptance.TestData, pythonVersion string) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_web_app" "test" {
  name                = "acctestWA-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  service_plan_id     = azurerm_app_service_plan.test.id

  site_config {
    windows_application_stack {
      python_version = "%s"
    }
  }
}

`, r.baseTemplate(data, osTypeWindows), data.RandomInteger, pythonVersion)
}

func (r WebAppResource) windowsJava(data acceptance.TestData, javaVersion string, javaContainer string, javaContainerVersion string) string {
	javaContainerStr := ""
	if javaContainer != "" {
		javaContainerStr = fmt.Sprintf("java_container = %q", javaContainer)
	}
	javaContainerVersionStr := ""
	if javaContainerVersion != "" {
		javaContainerVersionStr = fmt.Sprintf("java_container_version = %q", javaContainerVersion)
	}

	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_web_app" "test" {
  name                = "acctestWA-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  service_plan_id     = azurerm_app_service_plan.test.id

  site_config {
    windows_application_stack {
      java_version = "%s"
      %s
      %s
    }
  }
}

`, r.baseTemplate(data, osTypeWindows), data.RandomInteger, javaVersion, javaContainerStr, javaContainerVersionStr)
}

func (r WebAppResource) windowsMultiStack(data acceptance.TestData) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_web_app" "test" {
  name                = "acctestWA-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  service_plan_id     = azurerm_app_service_plan.test.id

  site_config {
    windows_application_stack {
      dotnet_framework_version = "%s"
      php_version              = "%s"
      python_version           = "%s"
      java_version             = "%s"
      java_container           = "%s"
      java_container_version   = "%s"
    }
  }
}

`, r.baseTemplate(data, osTypeWindows), data.RandomInteger, "v4.0", "7.4", "2.7", "1.8", "TOMCAT", "9.0")
}

func (r WebAppResource) logsEnabled(data acceptance.TestData, osType string) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_web_app" "test" {
  name                = "acctestAS-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  service_plan_id     = azurerm_app_service_plan.test.id

  logs {
    application_logs {
      file_system_level = "Warning"
      azure_blob_storage {
        level             = "Information"
        sas_url           = "http://x.com/"
        retention_in_days = 2
      }
    }

    http_logs {
      azure_blob_storage {
        sas_url           = "https://${azurerm_storage_account.test.name}.blob.core.windows.net/${azurerm_storage_container.test.name}${data.azurerm_storage_account_sas.test.sas}&sr=b"
        retention_in_days = 3
      }
    }
  }
}

`, r.templateWithStorageAccount(data, osType), data.RandomInteger)
}

// Templates

func (WebAppResource) baseTemplate(data acceptance.TestData, osType string) string {
	return fmt.Sprintf(`

resource "azurerm_resource_group" "test" {
  name     = "acctestRG-%d"
  location = "%s"
}

resource "azurerm_app_service_plan" "test" {
  name                = "acctestASP-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  kind                = "%s"
  reserved            = %t

  sku {
    tier = "Standard"
    size = "S1"
  }
}
`, data.RandomInteger, data.Locations.Primary, data.RandomInteger, osType, osType == osTypeLinux)
}

func (r WebAppResource) templateWithStorageAccount(data acceptance.TestData, osType string) string {
	return fmt.Sprintf(`

%s

resource "azurerm_user_assigned_identity" "test" {
  name                = "acct-%d"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
}

resource "azurerm_storage_account" "test" {
  name                     = "acctestsa%s"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = azurerm_resource_group.test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "test" {
  name                  = "test"
  storage_account_name  = azurerm_storage_account.test.name
  container_access_type = "private"
}

resource "azurerm_storage_share" "test" {
  name                 = "test"
  storage_account_name = azurerm_storage_account.test.name
}

data "azurerm_storage_account_sas" "test" {
  connection_string = azurerm_storage_account.test.primary_connection_string
  https_only        = true

  resource_types {
    service   = false
    container = false
    object    = true
  }

  services {
    blob  = true
    queue = false
    table = false
    file  = false
  }

  start  = "2021-04-01"
  expiry = "2024-03-30"

  permissions {
    read    = false
    write   = true
    delete  = false
    list    = false
    add     = false
    create  = false
    update  = false
    process = false
  }
}
`, r.baseTemplate(data, osType), data.RandomInteger, data.RandomString)
}
