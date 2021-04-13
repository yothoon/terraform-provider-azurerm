package webapp

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/appservice"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tags"

	"github.com/Azure/azure-sdk-for-go/services/web/mgmt/2020-06-01/web"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/sdk"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/appservice/parse"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/appservice/validate"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

type AppResource struct{}

type AppModel struct {
	Name                          string                      `tfschema:"name"`
	ResourceGroup                 string                      `tfschema:"resource_group_name"`
	Location                      string                      `tfschema:"location"`
	ServicePlanId                 string                      `tfschema:"service_plan_id"`
	AppSettings                   map[string]string           `tfschema:"app_settings"`
	AuthSettings                  []appservice.AuthSettings   `tfschema:"auth_settings"`
	Backup                        []Backup                    `tfschema:"backup"`
	ClientAffinityEnabled         bool                        `tfschema:"client_affinity_enabled"`
	ClientCertEnabled             bool                        `tfschema:"client_cert_enabled"`
	ClientCertMode                string                      `tfschema:"client_cert_mode"`
	Enabled                       bool                        `tfschema:"enabled"`
	HttpsOnly                     bool                        `tfschema:"https_only"`
	Identity                      []appservice.Identity       `tfschema:"identity"`
	SiteConfig                    []SiteConfig                `tfschema:"site_config"`
	StorageAccounts               []StorageAccount            `tfschema:"storage_account"`
	Tags                          map[string]interface{}      `tfschema:"tags"`
	CustomDomainVerificationId    string                      `tfschema:"custom_domain_verification_id"`
	DefaultHostname               string                      `tfschema:"default_hostname"`
	Kind                          string                      `tfschema:"kind"`
	OutboundIPAddresses           string                      `tfschema:"outbound_ip_addresses"`
	OutboundIPAddressList         []string                    `tfschema:"outbound_ip_address_list"`
	PossibleOutboundIPAddresses   string                      `tfschema:"possible_outbound_ip_addresses"`
	PossibleOutboundIPAddressList []string                    `tfschema:"possible_outbound_ip_address_list"`
	SiteCredentials               []appservice.SiteCredential `tfschema:"site_credential"`
}

var _ sdk.Resource = AppResource{}
var _ sdk.ResourceWithUpdate = AppResource{}

func (r AppResource) Arguments() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"name": {
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validate.WebAppName,
		},

		"resource_group_name": azure.SchemaResourceGroupName(),

		"location": azure.SchemaLocation(),

		"service_plan_id": {
			Type:         schema.TypeString,
			Required:     true,
			ValidateFunc: validate.ServicePlanID,
		},

		// Optional

		"app_setting": {
			Type:     schema.TypeMap,
			Optional: true,
			Computed: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},

		"auth_settings": appservice.AuthSettingsSchema(),

		"backup": backupSchema(),

		"client_affinity_enabled": {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		"client_cert_enabled": {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		"client_cert_mode": {
			Type:     schema.TypeString,
			Optional: true,
			ValidateFunc: validation.StringInSlice([]string{
				string(web.Optional),
				string(web.Required),
			}, false),
		},

		"connection_string": connectionStringSchema(),

		"enabled": {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		"https_only": {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		"identity": appservice.IdentitySchema(),

		"site_config": siteConfigSchema(),

		"storage_account": storageAccountSchema(),

		"tags": tags.Schema(),
	}
}

func (r AppResource) Attributes() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"custom_domain_verification_id": {
			Type:      schema.TypeString,
			Computed:  true,
			Sensitive: true,
		},

		"default_hostname": {
			Type:     schema.TypeString,
			Computed: true,
		},

		"kind": {
			Type:     schema.TypeString,
			Computed: true,
		},

		"outbound_ip_addresses": {
			Type:     schema.TypeString,
			Computed: true,
		},

		"outbound_ip_address_list": {
			Type:     schema.TypeList,
			Computed: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},

		"possible_outbound_ip_addresses": {
			Type:     schema.TypeString,
			Computed: true,
		},

		"possible_outbound_ip_address_list": {
			Type:     schema.TypeList,
			Computed: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},

		"site_credential": appservice.SiteCredentialSchema(),
	}
}

func (r AppResource) ModelObject() interface{} {
	return AppModel{}
}

func (r AppResource) ResourceType() string {
	return "azurerm_web_app"
}

func (r AppResource) Create() sdk.ResourceFunc {
	return sdk.ResourceFunc{
		Func: func(ctx context.Context, metadata sdk.ResourceMetaData) error {
			var webApp AppModel
			if err := metadata.Decode(&webApp); err != nil {
				return err
			}

			client := metadata.Client.AppService.WebAppsClient
			servicePlanClient := metadata.Client.AppService.ServicePlanClient
			subscriptionId := metadata.Client.Account.SubscriptionId

			id := parse.NewWebAppID(subscriptionId, webApp.ResourceGroup, webApp.Name)

			existing, err := client.Get(ctx, id.ResourceGroup, id.SiteName)
			if err != nil && !utils.ResponseWasNotFound(existing.Response) {
				return fmt.Errorf("checking for presence of existing Web App with %s: %+v", id, err)
			}

			if !utils.ResponseWasNotFound(existing.Response) {
				return metadata.ResourceRequiresImport(r.ResourceType(), id)
			}

			availabilityRequest := web.ResourceNameAvailabilityRequest{
				Name: utils.String(webApp.Name),
				Type: web.CheckNameResourceTypesMicrosoftWebsites,
			}

			servicePlanId, err := parse.ServicePlanID(webApp.ServicePlanId)
			if err != nil {
				return err
			}

			servicePlan, err := servicePlanClient.Get(ctx, servicePlanId.ResourceGroup, servicePlanId.ServerfarmName)
			if err != nil {
				return fmt.Errorf("reading App %s: %+v", servicePlanId)
			}
			// TODO - Does this change for Private Link?
			if servicePlan.HostingEnvironmentProfile != nil {
				// TODO - Check this for Gov / Sovereign cloud
				availabilityRequest.Name = utils.String(fmt.Sprintf("%s.%s.appserviceenvironment.net", webApp.Name, servicePlanId.ServerfarmName))
				availabilityRequest.IsFqdn = utils.Bool(true)
			}

			checkName, err := client.CheckNameAvailability(ctx, availabilityRequest)
			if err != nil {
				return fmt.Errorf("checking name availability for %s: %+v", id, err)
			}
			if !*checkName.NameAvailable {
				return fmt.Errorf("the Site Name %q failed the availabilty check: %+v", id.SiteName, *checkName.Message)
			}

			siteConfig, err := expandSiteConfig(&webApp.SiteConfig)
			if err != nil {
				return err
			}

			siteEnvelope := web.Site{
				Location: utils.String(webApp.Location),
				Tags:     tags.Expand(webApp.Tags),
				SiteProperties: &web.SiteProperties{
					ServerFarmID:          utils.String(webApp.ServicePlanId),
					Enabled:               utils.Bool(webApp.Enabled),
					HTTPSOnly:             utils.Bool(webApp.HttpsOnly),
					SiteConfig:            siteConfig,
					ClientAffinityEnabled: utils.Bool(webApp.ClientAffinityEnabled),
					ClientCertEnabled:     utils.Bool(webApp.ClientCertEnabled),
					ClientCertMode:        web.ClientCertMode(webApp.ClientCertMode),
				},
			}

			if len(webApp.Identity) > 0 {
				identity, err := appservice.ExpandIdentity(webApp.Identity)
				if err != nil {
					return err
				}
				siteEnvelope.Identity = identity
			}

			if _, err := client.CreateOrUpdate(ctx, id.ResourceGroup, id.SiteName, siteEnvelope); err != nil {
				return fmt.Errorf("creating Web App %s: %+v", id, err)
			}

			metadata.SetID(id)

			auth, err := appservice.ExpandAuthSettings(webApp.AuthSettings)
			if err != nil {
				return err
			}

			if _, err := client.UpdateAuthSettings(ctx, id.ResourceGroup, id.SiteName, *auth); err != nil {
				return fmt.Errorf("setting Authorisation settings for %s: %+v", id, err)
			}

			// logSettings := expandLogsSettings(webApp.Logs)
			return nil
		},

		Timeout: 30 * time.Minute,
	}
}

func (r AppResource) Read() sdk.ResourceFunc {
	panic("implement me")
}

func (r AppResource) Delete() sdk.ResourceFunc {
	panic("implement me")
}

func (r AppResource) IDValidationFunc() schema.SchemaValidateFunc {
	panic("implement me")
}

func (r AppResource) Update() sdk.ResourceFunc {
	panic("implement me")
}
