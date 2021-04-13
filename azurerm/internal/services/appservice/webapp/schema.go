package webapp

import (
	"github.com/Azure/azure-sdk-for-go/services/web/mgmt/2020-06-01/web"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	apimValidate "github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/apimanagement/validate"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/appservice"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tf/suppress"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

// TODO - Stack handling

type SiteConfig struct {
	AlwaysOn                bool                       `tfschema:"always_on"`
	ApiManagementConfig     string                     `tfschema:"api_management_config_id"`
	AppCommandLine          string                     `tfschema:"app_command_line"`
	DefaultDocuments        []string                   `tfschema:"default_documents"`
	Http2Enabled            bool                       `tfschema:"http2_enabled"`
	IpRestriction           []appservice.IpRestriction `tfschema:"ip_restriction"`
	ScmUseMainIpRestriction bool                       `tfschema:"scm_use_main_ip_restriction"`
	ScmIpRestriction        []appservice.IpRestriction `tfschema:"scm_ip_restriction"`
	LocalMysql              bool                       `tfschema:"local_mysql"`
	ManagedPipelineMode     string                     `tfschema:"managed_pipeline_mode"`
	RemoteDebugging         bool                       `tfschema:"remote_debugging"`
	RemoteDebuggingVersion  string                     `tfschema:"remote_debugging_version"`
	ScmType                 string                     `tfschema:"scm_type"`
	Use32BitWorker          bool                       `tfschema:"use_32_bit_worker"`
	WebSockets              bool                       `tfschema:"websockets"`
	FtpsState               string                     `tfschema:"ftps_state"`
	HealthCheckPath         string                     `tfschema:"health_check_path"`
	NumberOfWorkers         int                        `tfschema:"number_of_workers"`
	LinuxFxVersion          string                     `tfschema:"linux_fx_version"`
	WindowsFxVersion        string                     `tfschema:"windows_fx_version"`
	MinTlsVersion           string                     `tfschema:"minimum_tls_version"`
	ScmMinTlsVersion        string                     `tfschema:"scm_minimum_tls_version"`
	AutoSwapSlotName        string                     `tfschema:"auto_swap_slot_name"`
	Cors                    []appservice.CorsSetting   `tfschema:"cors"`
}

func siteConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"always_on": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},

				"api_management_config_id": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: apimValidate.ApiManagementID,
				},

				"app_command_line": {
					Type:     schema.TypeString,
					Optional: true,
				},

				"default_documents": {
					Type:     schema.TypeList,
					Optional: true,
					Elem:     &schema.Schema{Type: schema.TypeString},
				},

				"http2_enabled": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},

				"ip_restriction": appservice.IpRestrictionSchema(),

				"scm_use_main_ip_restriction": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},

				"scm_ip_restriction": appservice.IpRestrictionSchema(),

				"local_mysql": {
					Type:     schema.TypeBool,
					Optional: true,
					Computed: true,
				},

				"managed_pipeline_mode": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(web.Classic),
						string(web.Integrated),
					}, true),
				},

				"remote_debugging": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},

				"remote_debugging_version": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						"VS2017",
						"VS2019",
					}, false),
					DiffSuppressFunc: suppress.CaseDifference,
				},

				"scm_type": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(web.ScmTypeBitbucketGit),
						string(web.ScmTypeBitbucketHg),
						string(web.ScmTypeCodePlexGit),
						string(web.ScmTypeCodePlexHg),
						string(web.ScmTypeDropbox),
						string(web.ScmTypeExternalGit),
						string(web.ScmTypeExternalHg),
						string(web.ScmTypeGitHub),
						string(web.ScmTypeLocalGit),
						string(web.ScmTypeNone),
						string(web.ScmTypeOneDrive),
						string(web.ScmTypeTfs),
						string(web.ScmTypeVSO),
						string(web.ScmTypeVSTSRM),
					}, false),
				},

				"use_32_bit_worker": {
					Type:     schema.TypeBool,
					Optional: true,
				},

				"websockets": {
					Type:     schema.TypeBool,
					Optional: true,
					Computed: true,
				},

				"ftps_state": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(web.AllAllowed),
						string(web.Disabled),
						string(web.FtpsOnly),
					}, false),
				},

				"health_check_path": {
					Type:     schema.TypeString,
					Optional: true,
				},

				"number_of_workers": {
					Type:         schema.TypeInt,
					Optional:     true,
					Computed:     true,
					ValidateFunc: validation.IntBetween(1, 100),
				},

				"linux_fx_version": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
				},

				"windows_fx_version": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
				},

				"minimum_tls_version": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(web.OneFullStopZero),
						string(web.OneFullStopOne),
						string(web.OneFullStopTwo),
					}, false),
				},

				"scm_minimum_tls_version": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(web.OneFullStopZero),
						string(web.OneFullStopOne),
						string(web.OneFullStopTwo),
					}, false),
				},

				"cors": appservice.CorsSettingsSchema(),

				"auto_swap_slot_name": {
					Type:     schema.TypeString,
					Optional: true,
					// TODO - Add slot name validation here?
				},
			},
		},
	}
}

type StorageAccount struct {
	Name        string `tfschema:"name"`
	Type        string `tfschema:"type"`
	AccountName string `tfschema:"account_name"`
	ShareName   string `tfschema:"share_name"`
	AccessKey   string `tfschema:"access_key"`
	MountPath   string `tfschema:"mount_path"`
}

func storageAccountSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringIsNotEmpty,
				},

				"type": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(web.AzureBlob),
						string(web.AzureFiles),
					}, false),
				},

				"account_name": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringIsNotEmpty,
				},

				"share_name": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringIsNotEmpty,
				},

				"access_key": {
					Type:         schema.TypeString,
					Required:     true,
					Sensitive:    true,
					ValidateFunc: validation.StringIsNotEmpty,
				},

				"mount_path": {
					Type:     schema.TypeString,
					Optional: true,
				},
			},
		},
	}
}

type Backup struct {
	Name              string           `tfschema:"name"`
	StorageAccountUrl string           `tfschema:"storage_account_url"`
	Enabled           bool             `tfschema:"enabled"`
	Schedule          []BackupSchedule `tfschema:"schedule"`
}

type BackupSchedule struct {
	FrequencyInterval    int32  `tfschema:"frequency_interval"`
	FrequencyUnit        string `tfschema:"frequency_unit"`
	KeepAtLeastOneBackup bool   `tfschema:"keep_at_least_one_backup"`
	RetentionPeriodDays  int    `tfschema:"retention_period_days"`
	StartTime            string `tfschema:"start_time"`
}

func backupSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringIsNotEmpty,
				},

				"storage_account_url": {
					Type:         schema.TypeString,
					Required:     true,
					Sensitive:    true,
					ValidateFunc: validation.IsURLWithHTTPS,
				},

				"enabled": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  true,
				},

				"schedule": {
					Type:     schema.TypeList,
					Required: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"frequency_interval": {
								Type:         schema.TypeInt,
								Required:     true,
								ValidateFunc: validation.IntBetween(0, 1000),
							},

							"frequency_unit": {
								Type:     schema.TypeString,
								Required: true,
								ValidateFunc: validation.StringInSlice([]string{
									"Day",
									"Hour",
								}, false),
							},

							"keep_at_least_one_backup": {
								Type:     schema.TypeBool,
								Optional: true,
								Default:  false,
							},

							"retention_period_days": {
								Type:         schema.TypeInt,
								Optional:     true,
								Default:      30,
								ValidateFunc: validation.IntBetween(0, 9999999),
							},

							"start_time": {
								Type:             schema.TypeString,
								Optional:         true,
								DiffSuppressFunc: suppress.RFC3339Time,
								ValidateFunc:     validation.IsRFC3339Time,
							},
						},
					},
				},
			},
		},
	}
}

type ConnectionString struct {
	Name  string `tfschema:"name"`
	Type  string `tfschema:"type"`
	Value string `tfschema:"value"`
}

func connectionStringSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:     schema.TypeString,
					Required: true,
				},

				"type": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(web.APIHub),
						string(web.Custom),
						string(web.DocDb),
						string(web.EventHub),
						string(web.MySQL),
						string(web.NotificationHub),
						string(web.PostgreSQL),
						string(web.RedisCache),
						string(web.ServiceBus),
						string(web.SQLAzure),
						string(web.SQLServer),
					}, true),
					DiffSuppressFunc: suppress.CaseDifference,
				},

				"value": {
					Type:      schema.TypeString,
					Required:  true,
					Sensitive: true,
				},
			},
		},
	}
}

func expandSiteConfig(siteConfig *[]SiteConfig) (*web.SiteConfig, error) {
	if siteConfig == nil {
		return nil, nil
	}

	var expanded web.SiteConfig

	for _, v := range *siteConfig {
		expanded.AlwaysOn = utils.Bool(v.AlwaysOn)

		if v.ApiManagementConfig != "" {
			expanded.APIManagementConfig = &web.APIManagementConfig{
				ID: utils.String(v.ApiManagementConfig),
			}
		}

		if v.AppCommandLine != "" {
			expanded.AppCommandLine = utils.String(v.AppCommandLine)
		}

		if len(v.DefaultDocuments) != 0 {
			expanded.DefaultDocuments = &v.DefaultDocuments
		}

		expanded.HTTP20Enabled = utils.Bool(v.Http2Enabled)

		if len(v.IpRestriction) != 0 {
			ipRestrictions, err := appservice.ExpandIpRestrictions(v.IpRestriction)
			if err != nil {
				return nil, err
			}
			expanded.IPSecurityRestrictions = ipRestrictions
		}

		expanded.ScmIPSecurityRestrictionsUseMain = utils.Bool(v.ScmUseMainIpRestriction)

		if len(v.ScmIpRestriction) != 0 {
			scmIpRestrictions, err := appservice.ExpandIpRestrictions(v.ScmIpRestriction)
			if err != nil {
				return nil, err
			}
			expanded.ScmIPSecurityRestrictions = scmIpRestrictions
		}

		expanded.LocalMySQLEnabled = utils.Bool(v.LocalMysql)

		if v.ManagedPipelineMode != "" {
			expanded.ManagedPipelineMode = web.ManagedPipelineMode(v.ManagedPipelineMode)
		}

		if v.RemoteDebugging {
			expanded.RemoteDebuggingEnabled = utils.Bool(v.RemoteDebugging)
		}

		if v.RemoteDebuggingVersion != "" {
			expanded.RemoteDebuggingVersion = utils.String(v.RemoteDebuggingVersion)
		}

		if v.ScmType != "" {
			expanded.ScmType = web.ScmType(v.ScmType)
		}

		if v.Use32BitWorker {
			expanded.Use32BitWorkerProcess = utils.Bool(v.Use32BitWorker)
		}

		if v.WebSockets {
			expanded.WebSocketsEnabled = utils.Bool(v.WebSockets)
		}

		if v.FtpsState != "" {
			expanded.FtpsState = web.FtpsState(v.FtpsState)
		}

		if v.HealthCheckPath != "" {
			expanded.HealthCheckPath = utils.String(v.HealthCheckPath)
		}

		if v.NumberOfWorkers != 0 {
			expanded.NumberOfWorkers = utils.Int32(int32(v.NumberOfWorkers))
		}

		if v.LinuxFxVersion != "" {
			expanded.LinuxFxVersion = utils.String(v.LinuxFxVersion)
		}

		if v.WindowsFxVersion != "" {
			expanded.WindowsFxVersion = utils.String(v.WindowsFxVersion)
		}

		if v.MinTlsVersion != "" {
			expanded.MinTLSVersion = web.SupportedTLSVersions(v.MinTlsVersion)
		}

		if v.ScmMinTlsVersion != "" {
			expanded.ScmMinTLSVersion = web.SupportedTLSVersions(v.ScmMinTlsVersion)
		}

		if v.AutoSwapSlotName != "" {
			expanded.AutoSwapSlotName = utils.String(v.AutoSwapSlotName)
		}

		if len(v.Cors) != 0 {
			corsSettings, err := appservice.ExpandCorsSettings(v.Cors)
			if err != nil {
				return nil, err
			}
			expanded.Cors = corsSettings
		}
	}

	return &expanded, nil
}
