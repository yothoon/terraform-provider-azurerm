package helpers

import (
	"fmt"
	"strings"

	msiParse "github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/msi/parse"

	"github.com/Azure/azure-sdk-for-go/services/web/mgmt/2020-12-01/web"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/msi/validate"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

type IpRestriction struct {
	IpAddress    string                 `tfschema:"ip_address"`
	ServiceTag   string                 `tfschema:"service_tag"`
	VnetSubnetId string                 `tfschema:"virtual_network_subnet_id"`
	Name         string                 `tfschema:"name"`
	Priority     int                    `tfschema:"priority"`
	Action       string                 `tfschema:"action"`
	Headers      []IpRestrictionHeaders `tfschema:"headers"`
}

type IpRestrictionHeaders struct {
	XForwardedHost []string `tfschema:"x_forwarded_host"`
	XForwardedFor  []string `tfschema:"x_forwarded_for"`
	XAzureFDID     []string `tfschema:"x_azure_fdid"`
	XFDHealthProbe []string `tfschema:"x_fd_health_probe"`
}

func (v IpRestriction) Validate() error {
	hasIpAddress := v.IpAddress != ""
	hasServiceTag := v.ServiceTag != ""
	hasVnetSubnetId := v.VnetSubnetId != ""

	if (hasIpAddress && hasServiceTag) || (hasIpAddress && hasVnetSubnetId) || (hasServiceTag && hasVnetSubnetId) {
		return fmt.Errorf("only one of `ip_address`, `service_tag`, or `virtual_network_subnet_id` can be specified")
	}

	if !hasIpAddress && !hasServiceTag && !hasVnetSubnetId {
		return fmt.Errorf("one of `ip_address`, `service_tag`, or `virtual_network_subnet_id` must be specified")
	}

	return nil
}

func IpRestrictionSchema() *schema.Schema {
	return &schema.Schema{
		Type:       schema.TypeList,
		Optional:   true,
		Computed:   true,
		ConfigMode: schema.SchemaConfigModeAttr,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"ip_address": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.StringIsNotEmpty,
				},

				"service_tag": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.StringIsNotEmpty,
				},

				"virtual_network_subnet_id": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.StringIsNotEmpty,
				},

				"name": {
					Type:         schema.TypeString,
					Optional:     true,
					Computed:     true,
					ValidateFunc: validation.StringIsNotEmpty,
				},

				"priority": {
					Type:         schema.TypeInt,
					Optional:     true,
					Default:      65000,
					ValidateFunc: validation.IntBetween(1, 2147483647),
				},

				"action": {
					Type:     schema.TypeString,
					Default:  "Allow",
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"Allow",
						"Deny",
					}, false),
				},

				"headers": IpRestrictionHeadersSchema(),
			},
		},
	}
}

func IpRestrictionHeadersSchema() *schema.Schema {
	return &schema.Schema{
		Type:       schema.TypeList,
		MaxItems:   1,
		Computed:   true,
		Optional:   true,
		ConfigMode: schema.SchemaConfigModeAttr,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"x_forwarded_host": {
					Type:     schema.TypeList,
					MaxItems: 8,
					Optional: true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},

				"x_forwarded_for": {
					Type:     schema.TypeList,
					MaxItems: 8,
					Optional: true,
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: validation.IsCIDR,
					},
				},

				"x_azure_fdid": { // Front Door ID (UUID)
					Type:     schema.TypeList,
					MaxItems: 8,
					Optional: true,
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: validation.IsUUID,
					},
				},

				"x_fd_health_probe": { // 1 or absent
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Schema{
						Type: schema.TypeString,
						ValidateFunc: validation.StringInSlice([]string{
							"1",
						}, false),
					},
				},
			},
		},
	}
}

type Identity struct {
	IdentityIds []string `tfschema:"identity_ids"`
	Type        string   `tfschema:"type"`
	PrincipalId string   `tfschema:"principal_id"`
	TenantId    string   `tfschema:"tenant_id"`
}

func IdentitySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"identity_ids": {
					Type:     schema.TypeList,
					Optional: true,
					MinItems: 1,
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: validate.UserAssignedIdentityID,
					},
				},

				"type": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(web.ManagedServiceIdentityTypeNone),
						string(web.ManagedServiceIdentityTypeSystemAssigned),
						string(web.ManagedServiceIdentityTypeSystemAssignedUserAssigned),
						string(web.ManagedServiceIdentityTypeUserAssigned),
					}, true),
				},

				"principal_id": {
					Type:     schema.TypeString,
					Computed: true,
				},

				"tenant_id": {
					Type:     schema.TypeString,
					Computed: true,
				},
			},
		},
	}
}

type CorsSetting struct {
	AllowedOrigins     []string `tfschema:"allowed_origins"`
	SupportCredentials bool     `tfschema:"support_credentials"`
}

func CorsSettingsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"allowed_origins": {
					Type:     schema.TypeSet,
					Required: true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},

				"support_credentials": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},
			},
		},
	}
}

type SourceControl struct {
	RepoURL           string `tfschema:"repo_url"`
	Branch            string `tfschema:"branch"`
	ManualIntegration bool   `tfschema:"manual_integration"`
	UseMercurial      bool   `tfschema:"use_mercurial"`
	RollbackEnabled   bool   `tfschema:"rollback_enabled"`
}

// SourceControlSchema TODO - Make a separate resource
func SourceControlSchema() *schema.Schema {
	return &schema.Schema{
		Type:          schema.TypeList,
		Optional:      true,
		MaxItems:      1,
		Computed:      true,
		ConflictsWith: []string{"site_config.0.scm_type"},
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"repo_url": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
				},

				"branch": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
				},

				"manual_integration": {
					Type:     schema.TypeBool,
					Optional: true,
					Computed: true,
				},

				"use_mercurial": {
					Type:     schema.TypeBool,
					Optional: true,
					Computed: true,
				},

				"rollback_enabled": {
					Type:     schema.TypeBool,
					Optional: true,
					Computed: true,
				},
			},
		},
	}
}

type SiteCredential struct {
	Username string `tfschema:"name"`
	Password string `tfschema:"password"`
}

func SiteCredentialSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:     schema.TypeString,
					Computed: true,
				},

				"password": {
					Type:      schema.TypeString,
					Computed:  true,
					Sensitive: true,
				},
			},
		},
	}
}

type AuthSettings struct {
	Enabled                     bool                    `tfschema:"enabled"`
	AdditionalLoginParameters   map[string]string       `tfschema:"additional_login_params"`
	AllowedExternalRedirectUrls []string                `tfschema:"allowed_external_redirect_urls"`
	DefaultProvider             string                  `tfschema:"default_provider"`
	Issuer                      string                  `tfschema:"issuer"`
	RuntimeVersion              string                  `tfschema:"runtime_version"`
	TokenRefreshExtensionHours  float64                 `tfschema:"token_refresh_extension_hours"`
	TokenStoreEnabled           bool                    `tfschema:"token_store_enabled"`
	UnauthenticatedClientAction string                  `tfschema:"unauthenticated_client_action"`
	AzureActiveDirectoryAuth    []AadAuthSettings       `tfschema:"active_directory"`
	FacebookAuth                []FacebookAuthSettings  `tfschema:"facebook"`
	GithubAuth                  []GithubAuthSettings    `tfschema:"github"`
	GoogleAuth                  []GoogleAuthSettings    `tfschema:"google"`
	MicrosoftAuth               []MicrosoftAuthSettings `tfschema:"microsoft"`
	TwitterAuth                 []TwitterAuthSettings   `tfschema:"twitter"`
}

func AuthSettingsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"enabled": {
					Type:     schema.TypeBool,
					Required: true,
				},

				"additional_login_params": {
					Type:     schema.TypeMap,
					Optional: true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},

				"allowed_external_redirect_urls": {
					Type:     schema.TypeList,
					Optional: true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},

				"default_provider": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(web.BuiltInAuthenticationProviderAzureActiveDirectory),
						string(web.BuiltInAuthenticationProviderFacebook),
						string(web.BuiltInAuthenticationProviderGithub),
						string(web.BuiltInAuthenticationProviderGoogle),
						string(web.BuiltInAuthenticationProviderMicrosoftAccount),
						string(web.BuiltInAuthenticationProviderTwitter),
					}, false),
				},

				"issuer": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.IsURLWithScheme([]string{"http", "https"}),
				},

				"runtime_version": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
				},

				"token_refresh_extension_hours": {
					Type:     schema.TypeFloat,
					Optional: true,
					Default:  72,
				},

				"token_store_enabled": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},

				"unauthenticated_client_action": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(web.AllowAnonymous),
						string(web.RedirectToLoginPage),
					}, false),
				},

				"active_directory": AadAuthSettingsSchema(),

				"facebook": FacebookAuthSettingsSchema(),

				"github": GithubAuthSettingsSchema(),

				"google": GoogleAuthSettingsSchema(),

				"microsoft": MicrosoftAuthSettingsSchema(),

				"twitter": TwitterAuthSettingsSchema(),
			},
		},
	}
}

type AadAuthSettings struct {
	ClientId                string   `tfschema:"client_id"`
	ClientSecret            string   `tfschema:"client_secret"`
	ClientSecretSettingName string   `tfschema:"client_secret_setting_name"`
	AllowedAudiences        []string `tfschema:"allowed_audiences"`
}

func AadAuthSettingsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id": {
					Type:     schema.TypeString,
					Required: true,
				},

				"client_secret": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
					ExactlyOneOf: []string{
						"auth_settings.0.active_directory.0.client_secret",
						"auth_settings.0.active_directory.0.client_secret_setting_name",
					},
				},

				"client_secret_setting_name": {
					Type:     schema.TypeString,
					Optional: true,
					ExactlyOneOf: []string{
						"auth_settings.0.active_directory.0.client_secret",
						"auth_settings.0.active_directory.0.client_secret_setting_name",
					},
				},

				"allowed_audiences": {
					Type:     schema.TypeList,
					Optional: true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
			},
		},
	}
}

type FacebookAuthSettings struct {
	AppId                string   `tfschema:"app_id"`
	AppSecret            string   `tfschema:"app_secret"`
	AppSecretSettingName string   `tfschema:"app_secret_setting_name"`
	OauthScopes          []string `tfschema:"oauth_scopes"`
}

func FacebookAuthSettingsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"app_id": {
					Type:     schema.TypeString,
					Required: true,
				},

				"app_secret": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
					ExactlyOneOf: []string{
						"auth_settings.0.facebook.0.app_secret",
						"auth_settings.0.facebook.0.app_secret_setting_name",
					},
				},

				"app_secret_setting_name": {
					Type:     schema.TypeString,
					Optional: true,
					ExactlyOneOf: []string{
						"auth_settings.0.facebook.0.app_secret",
						"auth_settings.0.facebook.0.app_secret_setting_name",
					},
				},

				"oauth_scopes": {
					Type:     schema.TypeList,
					Optional: true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
			},
		},
	}
}

type GoogleAuthSettings struct {
	ClientId                string   `tfschema:"client_id"`
	ClientSecret            string   `tfschema:"client_schema"`
	ClientSecretSettingName string   `tfschema:"client_secret_setting_name"`
	OauthScopes             []string `tfschema:"oauth_scopes"`
}

func GoogleAuthSettingsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id": {
					Type:     schema.TypeString,
					Required: true,
				},

				"client_secret": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
					ExactlyOneOf: []string{
						"auth_settings.0.google.0.client_secret",
						"auth_settings.0.google.0.client_secret_setting_name",
					},
				},

				"client_secret_setting_name": {
					Type:     schema.TypeString,
					Optional: true,
					ExactlyOneOf: []string{
						"auth_settings.0.google.0.client_secret",
						"auth_settings.0.google.0.client_secret_setting_name",
					},
				},

				"oauth_scopes": {
					Type:     schema.TypeList,
					Optional: true,
					Elem:     &schema.Schema{Type: schema.TypeString},
				},
			},
		},
	}
}

type MicrosoftAuthSettings struct {
	ClientId                string   `tfschema:"client_id"`
	ClientSecret            string   `tfschema:"client_schema"`
	ClientSecretSettingName string   `tfschema:"client_secret_setting_name"`
	OauthScopes             []string `tfschema:"oauth_scopes"`
}

func MicrosoftAuthSettingsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id": {
					Type:     schema.TypeString,
					Required: true,
				},

				"client_secret": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
					ExactlyOneOf: []string{
						"auth_settings.0.microsoft.0.client_secret",
						"auth_settings.0.microsoft.0.client_secret_setting_name",
					},
				},

				"client_secret_setting_name": {
					Type:     schema.TypeString,
					Optional: true,
					ExactlyOneOf: []string{
						"auth_settings.0.microsoft.0.client_secret",
						"auth_settings.0.microsoft.0.client_secret_setting_name",
					},
				},

				"oauth_scopes": {
					Type:     schema.TypeList,
					Optional: true,
					Elem:     &schema.Schema{Type: schema.TypeString},
				},
			},
		},
	}
}

type TwitterAuthSettings struct {
	ConsumerKey               string `tfschema:"consumer_key"`
	ConsumerSecret            string `tfschema:"consumer_secret"`
	ConsumerSecretSettingName string `tfschema:"consumer_secret_setting_name"`
}

func TwitterAuthSettingsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"consumer_key": {
					Type:     schema.TypeString,
					Required: true,
				},

				"consumer_secret": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
					ExactlyOneOf: []string{
						"auth_settings.0.twitter.0.consumer_secret",
						"auth_settings.0.twitter.0.consumer_secret_setting_name",
					},
				},

				"consumer_secret_setting_name": {
					Type:     schema.TypeString,
					Optional: true,
				},
			},
		},
	}
}

type GithubAuthSettings struct {
	ClientId                string   `tfschema:"client_id"`
	ClientSecret            string   `tfschema:"client_secret"`
	ClientSecretSettingName string   `tfschema:"client_secret_setting_name"`
	OAuthScopes             []string `tfschema:"oauth_scopes"`
}

func GithubAuthSettingsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id": {
					Type:     schema.TypeString,
					Required: true,
				},

				"client_secret": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
					ExactlyOneOf: []string{
						"auth_settings.0.github.0.client_secret",
						"auth_settings.0.github.0.client_secret_setting_name",
					},
				},

				"client_secret_setting_name": {
					Type:     schema.TypeString,
					Optional: true,
					ExactlyOneOf: []string{
						"auth_settings.0.github.0.client_secret",
						"auth_settings.0.github.0.client_secret_setting_name",
					},
				},

				"oauth_scopes": {
					Type:     schema.TypeList,
					Optional: true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
			},
		},
	}
}

func ExpandIpRestrictions(restrictions []IpRestriction) (*[]web.IPSecurityRestriction, error) {
	var expanded []web.IPSecurityRestriction
	if len(restrictions) == 0 {
		return &expanded, nil
	}

	for _, v := range restrictions {
		if err := v.Validate(); err != nil {
			return nil, err
		}

		var restriction web.IPSecurityRestriction
		if v.Name != "" {
			restriction.Name = utils.String(v.Name)
		}

		if v.IpAddress != "" {
			restriction.IPAddress = utils.String(v.IpAddress)
		}

		if v.ServiceTag != "" {
			restriction.IPAddress = utils.String(v.ServiceTag)
			restriction.Tag = web.ServiceTag
		}

		if v.VnetSubnetId != "" {
			restriction.VnetSubnetResourceID = utils.String(v.VnetSubnetId)
		}

		restriction.Priority = utils.Int32(int32(v.Priority))

		restriction.Action = utils.String(v.Action)

		restriction.Headers = expandIpRestrictionHeaders(v.Headers)

		expanded = append(expanded, restriction)
	}

	return &expanded, nil
}

func expandIpRestrictionHeaders(headers []IpRestrictionHeaders) map[string][]string {
	result := make(map[string][]string)
	if len(headers) == 0 {
		return result
	}

	for _, v := range headers {
		if len(v.XForwardedHost) > 0 {
			result["x-forwarded-host"] = v.XForwardedHost
		}
		if len(v.XForwardedFor) > 0 {
			result["x-forwarded-for"] = v.XForwardedFor
		}
		if len(v.XAzureFDID) > 0 {
			result["x-azure-fd-id"] = v.XAzureFDID
		}
		if len(v.XFDHealthProbe) > 0 {
			result["x-fd-healthprobe"] = v.XFDHealthProbe
		}
	}
	return result
}

func ExpandCorsSettings(input []CorsSetting) *web.CorsSettings {
	if len(input) == 0 {
		return nil
	}
	var result web.CorsSettings
	for _, v := range input {
		if v.SupportCredentials {
			result.SupportCredentials = utils.Bool(v.SupportCredentials)
		}

		result.AllowedOrigins = &v.AllowedOrigins
	}
	return &result
}

func ExpandIdentity(identities []Identity) *web.ManagedServiceIdentity {
	if len(identities) == 0 {
		return nil
	}
	var result web.ManagedServiceIdentity
	for _, v := range identities {
		result.Type = web.ManagedServiceIdentityType(v.Type)
		if result.Type == web.ManagedServiceIdentityTypeUserAssigned || result.Type == web.ManagedServiceIdentityTypeSystemAssignedUserAssigned {
			identityIds := make(map[string]*web.ManagedServiceIdentityUserAssignedIdentitiesValue)
			for _, i := range v.IdentityIds {
				identityIds[i] = &web.ManagedServiceIdentityUserAssignedIdentitiesValue{}
			}
			result.UserAssignedIdentities = identityIds
		}
	}
	return &result
}

func ExpandAuthSettings(auth []AuthSettings) *web.SiteAuthSettings {
	if len(auth) == 0 {
		return nil
	}

	props := &web.SiteAuthSettingsProperties{}

	for _, v := range auth {
		if v.Enabled {
			props.Enabled = utils.Bool(v.Enabled)
		}
		if len(v.AdditionalLoginParameters) > 0 {
			var additionalLoginParams []string
			for k, s := range v.AdditionalLoginParameters {
				additionalLoginParams = append(additionalLoginParams, fmt.Sprintf("%s=%s", k, s))
			}
			props.AdditionalLoginParams = &additionalLoginParams
		}

		if len(v.AllowedExternalRedirectUrls) != 0 && v.AllowedExternalRedirectUrls != nil {
			props.AllowedExternalRedirectUrls = &v.AllowedExternalRedirectUrls
		}

		if v.DefaultProvider != "" {
			props.DefaultProvider = web.BuiltInAuthenticationProvider(v.DefaultProvider)
		}

		if v.Issuer != "" {
			props.Issuer = utils.String(v.Issuer)
		}

		if v.RuntimeVersion != "" {
			props.RuntimeVersion = utils.String(v.RuntimeVersion)
		}

		if v.TokenRefreshExtensionHours != 0 {
			props.TokenRefreshExtensionHours = utils.Float(v.TokenRefreshExtensionHours)
		}

		if v.UnauthenticatedClientAction != "" {
			props.UnauthenticatedClientAction = web.UnauthenticatedClientAction(v.UnauthenticatedClientAction)
		}

		if len(v.AzureActiveDirectoryAuth) == 1 {
			a := v.AzureActiveDirectoryAuth[0]
			props.ClientID = utils.String(a.ClientId)

			if a.ClientSecret != "" {
				props.ClientSecret = utils.String(a.ClientSecret)
			}

			if a.ClientSecretSettingName != "" {
				props.ClientSecretSettingName = utils.String(a.ClientSecretSettingName)
			}

			props.AllowedAudiences = &a.AllowedAudiences
		}

		if len(v.FacebookAuth) == 1 {
			f := v.FacebookAuth[0]
			props.FacebookAppID = utils.String(f.AppId)

			if f.AppSecret != "" {
				props.FacebookAppSecret = utils.String(f.AppSecret)
			}

			if f.AppSecretSettingName != "" {
				props.FacebookAppSecretSettingName = utils.String(f.AppSecretSettingName)
			}

			props.FacebookOAuthScopes = &f.OauthScopes
		}

		if len(v.GithubAuth) == 1 {
			g := v.GithubAuth[0]
			props.GitHubClientID = utils.String(g.ClientId)
			if g.ClientSecret != "" {
				props.GitHubClientID = utils.String(g.ClientId)
			}

			if g.ClientSecretSettingName != "" {
				props.GitHubClientSecretSettingName = utils.String(g.ClientSecretSettingName)
			}

			props.GitHubOAuthScopes = &g.OAuthScopes
		}

		if len(v.GoogleAuth) == 1 {
			g := v.GoogleAuth[0]
			props.GoogleClientID = utils.String(g.ClientId)

			if g.ClientSecret != "" {
				props.GoogleClientSecret = utils.String(g.ClientSecret)
			}

			if g.ClientSecretSettingName != "" {
				props.GoogleClientSecretSettingName = utils.String(g.ClientSecretSettingName)
			}

			props.GoogleOAuthScopes = &g.OauthScopes
		}

		if len(v.MicrosoftAuth) == 1 {
			m := v.MicrosoftAuth[0]
			props.MicrosoftAccountClientID = utils.String(m.ClientId)

			if m.ClientSecret != "" {
				props.MicrosoftAccountClientSecret = utils.String(m.ClientSecret)
			}

			if m.ClientSecretSettingName != "" {
				props.MicrosoftAccountClientSecretSettingName = utils.String(m.ClientSecretSettingName)
			}

			props.MicrosoftAccountOAuthScopes = &m.OauthScopes
		}

		if len(v.TwitterAuth) == 1 {
			t := v.TwitterAuth[0]
			props.TwitterConsumerKey = utils.String(t.ConsumerKey)

			if t.ConsumerSecret != "" {
				props.TwitterConsumerSecret = utils.String(t.ConsumerSecret)
			}

			if t.ConsumerSecretSettingName != "" {
				props.TwitterConsumerSecretSettingName = utils.String(t.ConsumerSecretSettingName)
			}
		}
	}

	return &web.SiteAuthSettings{
		SiteAuthSettingsProperties: props,
	}
}

func FlattenAuthSettings(auth web.SiteAuthSettings) []AuthSettings {
	if auth.SiteAuthSettingsProperties == nil {
		return nil
	}

	props := *auth.SiteAuthSettingsProperties

	result := AuthSettings{
		DefaultProvider:             string(props.DefaultProvider),
		UnauthenticatedClientAction: string(props.UnauthenticatedClientAction),
	}

	if props.Enabled != nil {
		result.Enabled = *props.Enabled
	}

	if props.AdditionalLoginParams != nil {
		params := make(map[string]string)
		for _, v := range *props.AdditionalLoginParams {
			parts := strings.Split(v, "=")
			if len(parts) != 2 {
				continue
			}
			params[parts[0]] = parts[1]
		}
		result.AdditionalLoginParameters = params
	}

	if props.AllowedExternalRedirectUrls != nil {
		result.AllowedExternalRedirectUrls = *props.AllowedExternalRedirectUrls
	}

	if props.Issuer != nil {
		result.Issuer = *props.Issuer
	}

	if props.RuntimeVersion != nil {
		result.RuntimeVersion = *props.RuntimeVersion
	}

	if props.TokenRefreshExtensionHours != nil {
		result.TokenRefreshExtensionHours = *props.TokenRefreshExtensionHours
	}

	if props.TokenStoreEnabled != nil {
		result.TokenStoreEnabled = *props.TokenStoreEnabled
	}

	// AAD Auth
	if props.ClientID != nil {
		aadAuthSettings := AadAuthSettings{
			ClientId: *props.ClientID,
		}

		if props.ClientSecret != nil {
			aadAuthSettings.ClientSecret = *props.ClientSecret
		}

		if props.ClientSecretSettingName != nil {
			aadAuthSettings.ClientSecretSettingName = *props.ClientSecretSettingName
		}

		if props.AllowedAudiences != nil {
			aadAuthSettings.AllowedAudiences = *props.AllowedAudiences
		}

		result.AzureActiveDirectoryAuth = []AadAuthSettings{aadAuthSettings}
	}

	if props.FacebookAppID != nil {
		facebookAuthSettings := FacebookAuthSettings{
			AppId: *props.FacebookAppID,
		}

		if props.FacebookAppSecret != nil {
			facebookAuthSettings.AppSecret = *props.FacebookAppSecret
		}

		if props.FacebookAppSecretSettingName != nil {
			facebookAuthSettings.AppSecretSettingName = *props.FacebookAppSecretSettingName
		}

		if props.FacebookOAuthScopes != nil {
			facebookAuthSettings.OauthScopes = *props.FacebookOAuthScopes
		}

		result.FacebookAuth = []FacebookAuthSettings{facebookAuthSettings}
	}

	if props.GitHubClientID != nil {
		githubAuthSetting := GithubAuthSettings{
			ClientId: *props.GitHubClientID,
		}

		if props.GitHubClientSecret != nil {
			githubAuthSetting.ClientSecret = *props.GitHubClientSecret
		}

		if props.GitHubClientSecretSettingName != nil {
			githubAuthSetting.ClientSecretSettingName = *props.GitHubClientSecretSettingName
		}

		result.GithubAuth = []GithubAuthSettings{githubAuthSetting}
	}

	if props.GoogleClientID != nil {
		googleAuthSettings := GoogleAuthSettings{
			ClientId: *props.GoogleClientID,
		}

		if props.GoogleClientSecret != nil {
			googleAuthSettings.ClientSecret = *props.GoogleClientSecret
		}

		if props.GoogleClientSecretSettingName != nil {
			googleAuthSettings.ClientSecretSettingName = *props.GoogleClientSecretSettingName
		}

		if props.GoogleOAuthScopes != nil {
			googleAuthSettings.OauthScopes = *props.GoogleOAuthScopes
		}

		result.GoogleAuth = []GoogleAuthSettings{googleAuthSettings}
	}

	if props.MicrosoftAccountClientID != nil {
		microsoftAuthSettings := MicrosoftAuthSettings{
			ClientId: *props.MicrosoftAccountClientID,
		}

		if props.MicrosoftAccountClientSecret != nil {
			microsoftAuthSettings.ClientSecret = *props.MicrosoftAccountClientSecret
		}

		if props.MicrosoftAccountClientSecretSettingName != nil {
			microsoftAuthSettings.ClientSecretSettingName = *props.MicrosoftAccountClientSecretSettingName
		}

		if props.MicrosoftAccountOAuthScopes != nil {
			microsoftAuthSettings.OauthScopes = *props.MicrosoftAccountOAuthScopes
		}

		result.MicrosoftAuth = []MicrosoftAuthSettings{microsoftAuthSettings}
	}

	if props.TwitterConsumerKey != nil {
		twitterAuthSetting := TwitterAuthSettings{
			ConsumerKey: *props.TwitterConsumerKey,
		}
		if props.TwitterConsumerSecret != nil {
			twitterAuthSetting.ConsumerSecret = *props.TwitterConsumerSecret
		}
		if props.TwitterConsumerSecretSettingName != nil {
			twitterAuthSetting.ConsumerSecretSettingName = *props.TwitterConsumerSecretSettingName
		}

		result.TwitterAuth = []TwitterAuthSettings{twitterAuthSetting}
	}

	return []AuthSettings{result}
}

func FlattenIdentity(appIdentity *web.ManagedServiceIdentity) []Identity {
	if appIdentity == nil {
		return nil
	}
	identity := Identity{
		Type: string(appIdentity.Type),
	}

	if len(appIdentity.UserAssignedIdentities) != 0 {
		var identityIds []string
		for k := range appIdentity.UserAssignedIdentities {
			// Service can return broken case IDs, so we normalise here and discard invalid entries
			id, err := msiParse.UserAssignedIdentityID(k)
			if err == nil {
				identityIds = append(identityIds, id.ID())
			}
		}
		identity.IdentityIds = identityIds
	}

	if appIdentity.PrincipalID != nil {
		identity.PrincipalId = *appIdentity.PrincipalID
	}

	if appIdentity.TenantID != nil {
		identity.TenantId = *appIdentity.TenantID
	}

	return []Identity{identity}
}

func FlattenIpRestrictions(ipRestrictionsList *[]web.IPSecurityRestriction) []IpRestriction {
	if ipRestrictionsList == nil {
		return nil
	}

	var ipRestrictions []IpRestriction
	for _, v := range *ipRestrictionsList {
		ipRestriction := IpRestriction{}

		if v.Name != nil {
			ipRestriction.Name = *v.Name
		}

		if v.IPAddress != nil {
			if *v.IPAddress == "Any" {
				continue
			}
			ipRestriction.IpAddress = *v.IPAddress
			if v.Tag == web.ServiceTag {
				ipRestriction.ServiceTag = *v.IPAddress
			} else {
				ipRestriction.IpAddress = *v.IPAddress
			}
		}

		if v.VnetSubnetResourceID != nil {
			ipRestriction.VnetSubnetId = *v.VnetSubnetResourceID
		}

		if v.Priority != nil {
			ipRestriction.Priority = int(*v.Priority)
		}

		if v.Action != nil {
			ipRestriction.Action = *v.Action
		}

		ipRestriction.Headers = flattenIpRestrictionHeaders(v.Headers)

		ipRestrictions = append(ipRestrictions, ipRestriction)
	}

	return ipRestrictions
}

func flattenIpRestrictionHeaders(headers map[string][]string) []IpRestrictionHeaders {
	if len(headers) == 0 {
		return nil
	}
	ipRestrictionHeader := IpRestrictionHeaders{}
	if xForwardFor, ok := headers["x-forwarded-for"]; ok {
		ipRestrictionHeader.XForwardedFor = xForwardFor
	}

	if xForwardedHost, ok := headers["x-forwarded-host"]; ok {
		ipRestrictionHeader.XForwardedHost = xForwardedHost
	}

	if xAzureFDID, ok := headers["x-azure-fd-id"]; ok {
		ipRestrictionHeader.XAzureFDID = xAzureFDID
	}

	if xFDHealthProbe, ok := headers["x-fc-healthprobe"]; ok {
		ipRestrictionHeader.XFDHealthProbe = xFDHealthProbe
	}

	return []IpRestrictionHeaders{ipRestrictionHeader}
}

func FlattenWebStringDictionary(input web.StringDictionary) map[string]string {
	result := make(map[string]string)
	for k, v := range input.Properties {
		result[k] = utils.NormalizeNilableString(v)
	}

	return result
}
