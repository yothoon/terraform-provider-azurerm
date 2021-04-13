package appservice

import (
	"fmt"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/msi/validate"

	"github.com/Azure/azure-sdk-for-go/services/web/mgmt/2020-06-01/web"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
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
					Elem: &schema.Schema{
						Type:     schema.TypeString,
						MaxItems: 1,
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
	Username string `tfschema:"username"`
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
	TokenRefreshExtensionHours  float32                 `tfschema:"token_refresh_extension_hours"`
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
					Elem:     &schema.Schema{Type: schema.TypeString},
				},

				"default_provider": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(web.BuiltInAuthenticationProviderAzureActiveDirectory),
						string(web.BuiltInAuthenticationProviderFacebook),
						// TODO: add GitHub Auth when API bump merged
						// string(web.BuiltInAuthenticationProviderGithub),
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
						"site_config.0.auth_settings.0.active_directory.0.client_secret",
						"site_config.0.auth_settings.0.active_directory.0.client_secret_setting_name",
					},
				},

				"client_secret_setting_name": {
					Type:     schema.TypeString,
					Optional: true,
					ExactlyOneOf: []string{
						"site_config.0.auth_settings.0.active_directory.0.client_secret",
						"site_config.0.auth_settings.0.active_directory.0.client_secret_setting_name",
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
						"site_config.0.auth_settings.0.facebook.0.app_secret",
						"site_config.0.auth_settings.0.facebook.0.app_secret_setting_name",
					},
				},

				"app_secret_setting_name": {
					Type:     schema.TypeString,
					Optional: true,
					ExactlyOneOf: []string{
						"site_config.0.auth_settings.0.facebook.0.app_secret",
						"site_config.0.auth_settings.0.facebook.0.app_secret_setting_name",
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
						"site_config.0.auth_settings.0.google.0.client_secret",
						"site_config.0.auth_settings.0.google.0.client_secret_setting_name",
					},
				},

				"client_secret_setting_name": {
					Type:     schema.TypeString,
					Optional: true,
					ExactlyOneOf: []string{
						"site_config.0.auth_settings.0.google.0.client_secret",
						"site_config.0.auth_settings.0.google.0.client_secret_setting_name",
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
						"site_config.0.auth_settings.0.microsoft.0.client_secret",
						"site_config.0.auth_settings.0.microsoft.0.client_secret_setting_name",
					},
				},

				"client_secret_setting_name": {
					Type:     schema.TypeString,
					Optional: true,
					ExactlyOneOf: []string{
						"site_config.0.auth_settings.0.microsoft.0.client_secret",
						"site_config.0.auth_settings.0.microsoft.0.client_secret_setting_name",
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
					Required:  true,
					Sensitive: true,
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
					Required:  true,
					Sensitive: true,
					ExactlyOneOf: []string{
						"site_config.0.auth_settings.0.github.0.client_secret",
						"site_config.0.auth_settings.0.github.0.client_secret_setting_name",
					},
				},

				"client_secret_setting_name": {
					Type:     schema.TypeString,
					Optional: true,
					ExactlyOneOf: []string{
						"site_config.0.auth_settings.0.github.0.client_secret",
						"site_config.0.auth_settings.0.github.0.client_secret_setting_name",
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

		headers, err := expandIpRestrictionHeaders(v.Headers)
		if err != nil {
			return nil, err
		}
		restriction.Headers = headers

		expanded = append(expanded, restriction)
	}

	return &expanded, nil
}

func expandIpRestrictionHeaders(headers []IpRestrictionHeaders) (map[string][]string, error) {
	result := make(map[string][]string)
	if len(headers) == 0 {
		return result, nil
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
	return result, nil
}

func ExpandCorsSettings(input []CorsSetting) (*web.CorsSettings, error) {
	if len(input) == 0 {
		return nil, nil
	}
	var result web.CorsSettings
	for _, v := range input {
		if v.SupportCredentials {
			result.SupportCredentials = utils.Bool(v.SupportCredentials)
		}

		result.AllowedOrigins = &v.AllowedOrigins
	}
	return &result, nil
}

func ExpandIdentity(identities []Identity) (*web.ManagedServiceIdentity, error) {
	if len(identities) == 0 {
		return nil, nil
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
	return &result, nil
}

func ExpandAuthSettings(auth []AuthSettings) (*web.SiteAuthSettings, error) {
	if len(auth) == 0 {
		return nil, nil
	}
	var result web.SiteAuthSettings

	for _, v := range auth {
		if v.Enabled {
			result.Enabled = utils.Bool(v.Enabled)
		}
		if len(v.AdditionalLoginParameters) > 0 {
			var additionalLoginParams []string
			for k, s := range v.AdditionalLoginParameters {
				additionalLoginParams = append(additionalLoginParams, fmt.Sprintf("%s=%s", k, s))
			}
			result.AdditionalLoginParams = &additionalLoginParams
		}

		if len(v.AllowedExternalRedirectUrls) > 0 {
			result.AllowedExternalRedirectUrls = &v.AllowedExternalRedirectUrls
		}

		if v.DefaultProvider != "" {
			result.DefaultProvider = web.BuiltInAuthenticationProvider(v.DefaultProvider)
		}

		if len(v.AzureActiveDirectoryAuth) == 1 {
			a := v.AzureActiveDirectoryAuth[0]
			result.ClientID = utils.String(a.ClientId)

			if a.ClientSecret != "" {
				result.ClientSecret = utils.String(a.ClientSecret)
			}

			if a.ClientSecretSettingName != "" {
				result.ClientSecretSettingName = utils.String(a.ClientSecretSettingName)
			}

			result.AllowedAudiences = &a.AllowedAudiences
		}

		if len(v.FacebookAuth) == 1 {
			f := v.FacebookAuth[0]
			result.FacebookAppID = utils.String(f.AppId)

			if f.AppSecret != "" {
				result.FacebookAppSecret = utils.String(f.AppSecret)
			}

			if f.AppSecretSettingName != "" {
				result.FacebookAppSecretSettingName = utils.String(f.AppSecretSettingName)
			}

			result.FacebookOAuthScopes = &f.OauthScopes
		}

		if len(v.GithubAuth) == 1 {
			g := v.GithubAuth[0]
			result.GitHubClientID = utils.String(g.ClientId)
			if g.ClientSecret != "" {
				result.GitHubClientID = utils.String(g.ClientId)
			}

			if g.ClientSecretSettingName != "" {
				result.GitHubClientSecretSettingName = utils.String(g.ClientSecretSettingName)
			}

			result.GitHubOAuthScopes = &g.OAuthScopes
		}

		if len(v.GoogleAuth) == 1 {
			g := v.GoogleAuth[0]
			result.GoogleClientID = utils.String(g.ClientId)

			if g.ClientSecret != "" {
				result.GoogleClientSecret = utils.String(g.ClientSecret)
			}

			if g.ClientSecretSettingName != "" {
				result.GoogleClientSecretSettingName = utils.String(g.ClientSecretSettingName)
			}

			result.GoogleOAuthScopes = &g.OauthScopes
		}

		if len(v.MicrosoftAuth) == 1 {
			m := v.MicrosoftAuth[0]
			result.MicrosoftAccountClientID = utils.String(m.ClientId)

			if m.ClientSecret != "" {
				result.MicrosoftAccountClientSecret = utils.String(m.ClientSecret)
			}

			if m.ClientSecretSettingName != "" {
				result.MicrosoftAccountClientSecretSettingName = utils.String(m.ClientSecretSettingName)
			}

			result.MicrosoftAccountOAuthScopes = &m.OauthScopes
		}

		if len(v.TwitterAuth) == 1 {
			t := v.TwitterAuth[0]
			result.TwitterConsumerKey = utils.String(t.ConsumerKey)

			if t.ConsumerSecret != "" {
				result.TwitterConsumerSecret = utils.String(t.ConsumerSecret)
			}

			if t.ConsumerSecretSettingName != "" {
				result.TwitterConsumerSecretSettingName = utils.String(t.ConsumerSecretSettingName)
			}
		}

	}

	return &result, nil
}
