package webapp

import (
	"strings"
	"time"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/appservice/helpers"

	"github.com/Azure/azure-sdk-for-go/services/web/mgmt/2020-12-01/web"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	apimValidate "github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/apimanagement/validate"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tf/suppress"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tf/validation"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

// TODO - Stack handling

type SiteConfig struct {
	AlwaysOn              bool     `tfschema:"always_on"`
	ApiManagementConfigId string   `tfschema:"api_management_config_id"`
	AppCommandLine        string   `tfschema:"app_command_line"`
	DefaultDocuments      []string `tfschema:"default_documents"`
	// DetailedErrorLogging bool `tfschema:"detailed_error_logging"` // TODO - New field to support, defaults to `false`
	Http2Enabled            bool                    `tfschema:"http2_enabled"`
	IpRestriction           []helpers.IpRestriction `tfschema:"ip_restriction"`
	ScmUseMainIpRestriction bool                    `tfschema:"scm_use_main_ip_restriction"`
	ScmIpRestriction        []helpers.IpRestriction `tfschema:"scm_ip_restriction"`
	// LoadBalancing string `tfschema:"load_balancing_mode"` // TODO - New field to support, defaults to `LeastRequests`
	LocalMysql              bool                      `tfschema:"local_mysql"`
	ManagedPipelineMode     string                    `tfschema:"managed_pipeline_mode"`
	RemoteDebugging         bool                      `tfschema:"remote_debugging"`
	RemoteDebuggingVersion  string                    `tfschema:"remote_debugging_version"`
	ScmType                 string                    `tfschema:"scm_type"`
	Use32BitWorker          bool                      `tfschema:"use_32_bit_worker"`
	WebSockets              bool                      `tfschema:"websockets"`
	FtpsState               string                    `tfschema:"ftps_state"`
	HealthCheckPath         string                    `tfschema:"health_check_path"`
	NumberOfWorkers         int                       `tfschema:"number_of_workers"`
	WindowsApplicationStack []WindowsApplicationStack `tfschema:"windows_application_stack"`
	MinTlsVersion           string                    `tfschema:"minimum_tls_version"`
	ScmMinTlsVersion        string                    `tfschema:"scm_minimum_tls_version"`
	AutoSwapSlotName        string                    `tfschema:"auto_swap_slot_name"`
	Cors                    []helpers.CorsSetting     `tfschema:"cors"`
	LinuxFxVersion          string                    `tfschema:"linux_fx_version"`
	WindowsFxVersion        string                    `tfschema:"windows_fx_version"`
	// Push  []PushSetting `tfschema:"push"` // TODO - new block to (possibly) support?
	// SiteLimits []SiteLimitsSettings `tfschema:"site_limits"` // TODO - New block to (possibly) support?
	// VirtualApplications []VirtualApplications //TODO - New (computed?) block to (possibly) support?
	// Stacks
	// TODO fields
	// AutoHeal bool
	// AutoHealRules []AutoHealRule
}

func siteConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"always_on": {
					Type:     schema.TypeBool,
					Optional: true,
					Computed: true,
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

				"windows_application_stack": windowsApplicationStackSchema(),

				"default_documents": {
					Type:     schema.TypeList,
					Optional: true,
					Computed: true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},

				"http2_enabled": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},

				"ip_restriction": helpers.IpRestrictionSchema(),

				"scm_use_main_ip_restriction": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},

				"scm_ip_restriction": helpers.IpRestrictionSchema(),

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
					Computed: true,
				},

				"use_32_bit_worker": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},

				"websockets": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
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

				"cors": helpers.CorsSettingsSchema(),

				"auto_swap_slot_name": {
					Type:     schema.TypeString,
					Optional: true,
					// TODO - Add slot name validation here?
				},

				"linux_fx_version": {
					Type:     schema.TypeString,
					Computed: true,
				},

				"windows_fx_version": {
					Type:     schema.TypeString,
					Computed: true,
				},
			},
		},
	}
}

type WindowsApplicationStack struct {
	NetFrameworkVersion  string `tfschema:"dotnet_framework_version"`
	PhpVersion           string `tfschema:"php_version"`
	JavaVersion          string `tfschema:"java_version"`
	PythonVersion        string `tfschema:"python_version"` // Linux Only
	NodeVersion          string `tfschema:"node_version"`
	JavaContainer        string `tfschema:"java_container"`
	JavaContainerVersion string `tfschema:"java_container_version"`
	// PowerShellVersion    string `tfschema:"powershell_version"` // Function Apps Only...
}

// Version information for the below validations was taken in part from - https://github.com/Azure/app-service-linux-docs/tree/master/Runtime_Support
func windowsApplicationStackSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"dotnet_framework_version": { // Windows Only
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						"v2.0",
						"v3.0",
						"v4.0",
						"v5.0",
					}, false),
					//ExactlyOneOf: []string{
					//	"application_stack.0.dotnet_framework_version",
					//	"application_stack.0.dotnetcore_framework_version",
					//	"application_stack.0.php_version",
					//	"application_stack.0.python_version",
					//	"application_stack.0.node_version",
					//	"application_stack.0.powershell_version",
					//	"application_stack.0.java_version",
					//	"application_stack.0.java_container_version",
					//},
				},

				"php_version": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						"5.6",
						"7.3",
						"7.4",
					}, false),
					//ExactlyOneOf: []string{
					//	"application_stack.0.dotnet_framework_version",
					//	"application_stack.0.php_version",
					//	"application_stack.0.python_version",
					//	"application_stack.0.node_version",
					//	"application_stack.0.powershell_version",
					//	"application_stack.0.java_version",
					//},
				},

				"python_version": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"2.7", // Windows supported?
						"3.6", // Both
						"3.7", // Linux Only
						"3.8", // Linux Only?
					}, false),
					//ExactlyOneOf: []string{
					//	"application_stack.0.dotnet_framework_version",
					//	"application_stack.0.php_version",
					//	"application_stack.0.python_version",
					//	"application_stack.0.node_version",
					//	"application_stack.0.powershell_version",
					//	"application_stack.0.java_version",
					//},
				},

				"node_version": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"10.1",   // Linux Only
						"10.6",   // Linux Only
						"10.10",  // Linux Only
						"10.14",  // Linux Only
						"10-LTS", // Linux Only
						"12-LTS",
						"14-LTS",
					}, false),
					//ExactlyOneOf: []string{
					//	"application_stack.0.dotnet_framework_version",
					//	"application_stack.0.php_version",
					//	"application_stack.0.python_version",
					//	"application_stack.0.node_version",
					//	"application_stack.0.powershell_version",
					//	"application_stack.0.java_version",
					//},
				},
				// TODO - powershell is Function App only - leaving here as signpost for later
				// "powershell_version": {
				//	Type:     schema.TypeString,
				//	Optional: true,
				//	ValidateFunc: validation.StringInSlice([]string{
				//		"", // TODO - Valid strings are....?
				//	}, false),
				//	ExactlyOneOf: []string{
				//		"application_stack.0.dotnet_framework_version",
				//		"application_stack.0.php_version",
				//		"application_stack.0.python_version",
				//		"application_stack.0.node_version",
				//		"application_stack.0.powershell_version",
				//		"application_stack.0.java_version",
				//	},
				// },

				"java_version": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"1.7", // Windows Only
						"1.8",
						"11",
					}, false),
					//ExactlyOneOf: []string{
					//	"application_stack.0.dotnet_framework_version",
					//	"application_stack.0.php_version",
					//	"application_stack.0.python_version",
					//	"application_stack.0.node_version",
					//	"application_stack.0.powershell_version",
					//	"application_stack.0.java_version",
					//},
				},

				"java_container": {Type: schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						"JAVA",
						"JETTY",
						"TOMCAT",
					}, false),
					//ConflictsWith: []string{
					//	"application_stack.0.dotnet_framework_version",
					//	"application_stack.0.php_version",
					//	"application_stack.0.python_version",
					//	"application_stack.0.node_version",
					//	"application_stack.0.powershell_version",
					//},
				},

				"java_container_version": {
					Type:     schema.TypeString,
					Optional: true,
					RequiredWith: []string{
						"site_config.0.windows_application_stack.0.java_container",
					},
					//ConflictsWith: []string{
					//	"application_stack.0.dotnet_framework_version",
					//	"application_stack.0.php_version",
					//	"application_stack.0.python_version",
					//	"application_stack.0.node_version",
					//	"application_stack.0.powershell_version",
					//},
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
	FrequencyInterval    int    `tfschema:"frequency_interval"`
	FrequencyUnit        string `tfschema:"frequency_unit"`
	KeepAtLeastOneBackup bool   `tfschema:"keep_at_least_one_backup"`
	RetentionPeriodDays  int    `tfschema:"retention_period_days"`
	StartTime            string `tfschema:"start_time"`
	LastExecutionTime    string `tfschema:"last_execution_time"`
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
								Computed:         true,
								DiffSuppressFunc: suppress.RFC3339Time,
								ValidateFunc:     validation.IsRFC3339Time,
							},

							"last_execution_time": {
								Type:     schema.TypeString,
								Computed: true,
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

type LogsConfig struct {
	ApplicationLogs       []ApplicationLog `tfschema:"application_logs"`
	HttpLogs              []HttpLog        `tfschema:"http_logs"`
	DetailedErrorMessages bool             `tfschema:"detailed_error_messages"`
	FailedRequestTracing  bool             `tfschema:"failed_request_tracing"`
}

type ApplicationLog struct {
	FileSystemLevel  string             `tfschema:"file_system_level"`
	AzureBlobStorage []AzureBlobStorage `tfschema:"azure_blob_storage"`
}

type AzureBlobStorage struct {
	Level           string `tfschema:"level"`
	SasUrl          string `tfschema:"sas_url"`
	RetentionInDays int    `tfschema:"retention_in_days"`
}

type HttpLog struct {
	FileSystems      []FileSystem           `tfschema:"file_system"`
	AzureBlobStorage []AzureBlobStorageHttp `tfschema:"azure_blob_storage"`
}

type AzureBlobStorageHttp struct {
	SasUrl          string `tfschema:"sas_url"`
	RetentionInDays int    `tfschema:"retention_in_days"`
}

type FileSystem struct {
	RetentionMB   int `tfschema:"retention_in_mb"`
	RetentionDays int `tfschema:"retention_in_days"`
}

func logsConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"application_logs": applicationLogSchema(),

				"http_logs": httpLogSchema(),

				"failed_request_tracing": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},

				"detailed_error_messages": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},
			},
		},
	}
}

func applicationLogSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"file_system_level": {
					Type:     schema.TypeString,
					Optional: true,
					Default:  "Off",
					ValidateFunc: validation.StringInSlice([]string{
						string(web.Error),
						string(web.Information),
						string(web.Off),
						string(web.Verbose),
						string(web.Warning),
					}, false),
				},

				"azure_blob_storage": appLogBlobStorageSchema(),
			},
		},
	}
}

func appLogBlobStorageSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"level": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.StringInSlice([]string{
						string(web.Error),
						string(web.Information),
						string(web.Off),
						string(web.Verbose),
						string(web.Warning),
					}, false),
				},
				"sas_url": {
					Type:      schema.TypeString,
					Required:  true,
					Sensitive: true,
				},
				"retention_in_days": {
					Type:     schema.TypeInt,
					Required: true,
					// TODO: Validation here?
				},
			},
		},
	}
}

func httpLogSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"file_system": httpLogFileSystemSchema(),

				"azure_blob_storage": httpLogBlobStorageSchema(),
			},
		},
	}
}

func httpLogFileSystemSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"retention_in_mb": {
					Type:         schema.TypeInt,
					Required:     true,
					ValidateFunc: validation.IntBetween(25, 100),
				},

				"retention_in_days": {
					Type:         schema.TypeInt,
					Required:     true,
					ValidateFunc: validation.IntAtLeast(0),
				},
			},
		},
	}
}

func httpLogBlobStorageSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"sas_url": {
					Type:      schema.TypeString,
					Required:  true,
					Sensitive: true,
				},
				"retention_in_days": {
					Type:     schema.TypeInt,
					Required: true,
				},
			},
		},
	}
}

func expandSiteConfig(siteConfig []SiteConfig, kind string) (*web.SiteConfig, error) {
	if len(siteConfig) == 0 {
		return nil, nil
	}
	expanded := &web.SiteConfig{}

	for _, v := range siteConfig {
		expanded.AlwaysOn = utils.Bool(v.AlwaysOn)

		if v.ApiManagementConfigId != "" {
			expanded.APIManagementConfig = &web.APIManagementConfig{
				ID: utils.String(v.ApiManagementConfigId),
			}
		}

		if v.AppCommandLine != "" {
			expanded.AppCommandLine = utils.String(v.AppCommandLine)
		}

		if len(v.WindowsApplicationStack) == 1 {
			winAppStack := v.WindowsApplicationStack[0]
			if winAppStack.NetFrameworkVersion != "" {
				expanded.NetFrameworkVersion = utils.String(winAppStack.NetFrameworkVersion)
			}

			if winAppStack.PhpVersion != "" {
				expanded.PhpVersion = utils.String(winAppStack.PhpVersion)
			}

			if winAppStack.NodeVersion != "" {
				expanded.NodeVersion = utils.String(winAppStack.NodeVersion)
			}

			if winAppStack.PythonVersion != "" {
				expanded.PythonVersion = utils.String(winAppStack.PythonVersion)
			}

			if winAppStack.JavaVersion != "" {
				expanded.JavaVersion = utils.String(winAppStack.JavaVersion)
			}

			if winAppStack.JavaContainer != "" {
				expanded.JavaContainer = utils.String(winAppStack.JavaContainer)
			}

			if winAppStack.JavaContainerVersion != "" {
				expanded.JavaContainerVersion = utils.String(winAppStack.JavaContainerVersion)
			}
		}

		if len(v.DefaultDocuments) != 0 {
			expanded.DefaultDocuments = &v.DefaultDocuments
		}

		expanded.HTTP20Enabled = utils.Bool(v.Http2Enabled)

		if len(v.IpRestriction) != 0 {
			ipRestrictions, err := helpers.ExpandIpRestrictions(v.IpRestriction)
			if err != nil {
				return nil, err
			}
			expanded.IPSecurityRestrictions = ipRestrictions
		}

		expanded.ScmIPSecurityRestrictionsUseMain = utils.Bool(v.ScmUseMainIpRestriction)

		if len(v.ScmIpRestriction) != 0 {
			scmIpRestrictions, err := helpers.ExpandIpRestrictions(v.ScmIpRestriction)
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

		expanded.Use32BitWorkerProcess = utils.Bool(v.Use32BitWorker)

		expanded.WebSocketsEnabled = utils.Bool(v.WebSockets)

		if v.FtpsState != "" {
			expanded.FtpsState = web.FtpsState(v.FtpsState)
		}

		if v.HealthCheckPath != "" {
			expanded.HealthCheckPath = utils.String(v.HealthCheckPath)
		}

		if v.NumberOfWorkers != 0 {
			expanded.NumberOfWorkers = utils.Int32(int32(v.NumberOfWorkers))
		}

		if strings.EqualFold(kind, "linux") {
			// TODO - expand schema for linux stack strings
			expanded.LinuxFxVersion = utils.String("")
		}

		if strings.EqualFold(kind, "Windows") {
			// `WindowsFxVersion` is only for Docker Image specification, which we need to collect from app_settings
			expanded.WindowsFxVersion = utils.String("")
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
			expanded.Cors = helpers.ExpandCorsSettings(v.Cors)
		}
	}

	return expanded, nil
}

func expandLogsConfig(config []LogsConfig) *web.SiteLogsConfig {
	if len(config) == 0 {
		return nil
	}

	siteLogsConfig := &web.SiteLogsConfig{
		SiteLogsConfigProperties: &web.SiteLogsConfigProperties{},
	}
	logsConfig := config[0]

	if len(logsConfig.ApplicationLogs) == 1 {
		appLogs := logsConfig.ApplicationLogs[0]
		siteLogsConfig.SiteLogsConfigProperties.ApplicationLogs = &web.ApplicationLogsConfig{
			FileSystem: &web.FileSystemApplicationLogsConfig{ // TODO - Does this conflict with the use of `AzureBlobStorage` below?
				Level: web.LogLevel(appLogs.FileSystemLevel),
			},
		}
		if len(appLogs.AzureBlobStorage) == 1 {
			appLogsBlobs := appLogs.AzureBlobStorage[0]
			siteLogsConfig.SiteLogsConfigProperties.ApplicationLogs.AzureBlobStorage = &web.AzureBlobStorageApplicationLogsConfig{
				Level:           web.LogLevel(appLogsBlobs.Level),
				SasURL:          utils.String(appLogsBlobs.SasUrl),
				RetentionInDays: utils.Int32(int32(appLogsBlobs.RetentionInDays)),
			}
		}
	}

	if len(logsConfig.HttpLogs) == 1 {
		httpLogs := logsConfig.HttpLogs[0]
		siteLogsConfig.HTTPLogs = &web.HTTPLogsConfig{}

		if len(httpLogs.FileSystems) == 1 {
			httpLogFileSystem := httpLogs.FileSystems[0]
			siteLogsConfig.HTTPLogs.FileSystem = &web.FileSystemHTTPLogsConfig{
				Enabled:         utils.Bool(true),
				RetentionInMb:   utils.Int32(int32(httpLogFileSystem.RetentionMB)),
				RetentionInDays: utils.Int32(int32(httpLogFileSystem.RetentionDays)),
			}
		}

		if len(httpLogs.AzureBlobStorage) == 1 {
			httpLogsBlobStorage := httpLogs.AzureBlobStorage[0]
			siteLogsConfig.HTTPLogs.AzureBlobStorage = &web.AzureBlobStorageHTTPLogsConfig{
				Enabled:         utils.Bool(true),
				SasURL:          utils.String(httpLogsBlobStorage.SasUrl),
				RetentionInDays: utils.Int32(int32(httpLogsBlobStorage.RetentionInDays)),
			}
		}
	}

	if logsConfig.DetailedErrorMessages {
		siteLogsConfig.DetailedErrorMessages = &web.EnabledConfig{
			Enabled: utils.Bool(logsConfig.DetailedErrorMessages),
		}
	}

	if logsConfig.FailedRequestTracing {
		siteLogsConfig.FailedRequestsTracing = &web.EnabledConfig{
			Enabled: utils.Bool(logsConfig.FailedRequestTracing),
		}
	}

	return siteLogsConfig
}

func expandBackupConfig(backupConfigs []Backup) *web.BackupRequest {
	if len(backupConfigs) == 0 {
		return nil
	}

	backupConfig := backupConfigs[0]
	backupSchedule := backupConfig.Schedule[0]
	backupRequest := &web.BackupRequest{
		BackupRequestProperties: &web.BackupRequestProperties{
			Enabled:           utils.Bool(backupConfig.Enabled),
			BackupName:        utils.String(backupConfig.Name),
			StorageAccountURL: utils.String(backupConfig.StorageAccountUrl),
			BackupSchedule: &web.BackupSchedule{
				FrequencyInterval:     utils.Int32(int32(backupSchedule.FrequencyInterval)),
				FrequencyUnit:         web.FrequencyUnit(backupSchedule.FrequencyUnit),
				KeepAtLeastOneBackup:  utils.Bool(backupSchedule.KeepAtLeastOneBackup),
				RetentionPeriodInDays: utils.Int32(int32(backupSchedule.RetentionPeriodDays)),
			},
		},
	}

	if backupSchedule.StartTime != "" {
		dateTimeToStart, _ := time.Parse(time.RFC3339, backupSchedule.StartTime)
		backupRequest.BackupRequestProperties.BackupSchedule.StartTime = &date.Time{Time: dateTimeToStart}
	}

	return backupRequest
}

func expandStorageConfig(storageConfigs []StorageAccount) *web.AzureStoragePropertyDictionaryResource {
	if len(storageConfigs) == 0 {
		return nil
	}
	storageAccounts := make(map[string]*web.AzureStorageInfoValue)
	for _, v := range storageConfigs {
		storageAccounts[v.Name] = &web.AzureStorageInfoValue{
			Type:        web.AzureStorageType(v.Type),
			AccountName: utils.String(v.AccountName),
			ShareName:   utils.String(v.ShareName),
			AccessKey:   utils.String(v.AccessKey),
			MountPath:   utils.String(v.MountPath),
		}
	}

	return &web.AzureStoragePropertyDictionaryResource{
		Properties: storageAccounts,
	}
}

func expandConnectionStrings(connectionStringsConfig []ConnectionString) *web.ConnectionStringDictionary {
	if len(connectionStringsConfig) == 0 {
		return nil
	}
	connectionStrings := make(map[string]*web.ConnStringValueTypePair)
	for _, v := range connectionStringsConfig {
		connectionStrings[v.Name] = &web.ConnStringValueTypePair{
			Value: utils.String(v.Value),
			Type:  web.ConnectionStringType(v.Type),
		}
	}

	return &web.ConnectionStringDictionary{
		Properties: connectionStrings,
	}
}

func flattenBackupConfig(backupRequest web.BackupRequest) []Backup {
	if backupRequest.BackupRequestProperties == nil {
		return nil
	}
	props := *backupRequest.BackupRequestProperties
	backup := Backup{}
	if props.BackupName != nil {
		backup.Name = *props.BackupName
	}

	if props.StorageAccountURL != nil {
		backup.StorageAccountUrl = *props.StorageAccountURL
	}

	if props.Enabled != nil {
		backup.Enabled = *props.Enabled
	}

	if props.BackupSchedule != nil {
		schedule := *props.BackupSchedule
		backupSchedule := BackupSchedule{
			FrequencyUnit: string(schedule.FrequencyUnit),
		}
		if schedule.FrequencyInterval != nil {
			backupSchedule.FrequencyInterval = int(*schedule.FrequencyInterval)
		}

		if schedule.KeepAtLeastOneBackup != nil {
			backupSchedule.KeepAtLeastOneBackup = *schedule.KeepAtLeastOneBackup
		}

		if schedule.RetentionPeriodInDays != nil {
			backupSchedule.RetentionPeriodDays = int(*schedule.RetentionPeriodInDays)
		}

		if schedule.StartTime != nil && !schedule.StartTime.IsZero() {
			backupSchedule.StartTime = schedule.StartTime.Format(time.RFC3339)
		}

		if schedule.LastExecutionTime != nil && !schedule.LastExecutionTime.IsZero() {
			backupSchedule.LastExecutionTime = schedule.LastExecutionTime.Format(time.RFC3339)
		}

		backup.Schedule = []BackupSchedule{backupSchedule}
	}

	return []Backup{backup}
}

func flattenLogsConfig(logsConfig web.SiteLogsConfig) []LogsConfig {
	if logsConfig.SiteLogsConfigProperties == nil {
		return nil
	}

	logs := LogsConfig{}
	props := *logsConfig.SiteLogsConfigProperties

	if props.ApplicationLogs != nil {
		applicationLog := ApplicationLog{}
		appLogs := *props.ApplicationLogs
		if appLogs.FileSystem != nil {
			applicationLog.FileSystemLevel = string(appLogs.FileSystem.Level)
		}

		if appLogs.AzureBlobStorage != nil {
			blobStorage := AzureBlobStorage{
				Level: string(appLogs.AzureBlobStorage.Level),
			}
			if appLogs.AzureBlobStorage.SasURL != nil {
				blobStorage.SasUrl = *appLogs.AzureBlobStorage.SasURL
			}
			if appLogs.AzureBlobStorage.RetentionInDays != nil {
				blobStorage.RetentionInDays = int(*appLogs.AzureBlobStorage.RetentionInDays)
			}
			applicationLog.AzureBlobStorage = []AzureBlobStorage{blobStorage}
		}
		logs.ApplicationLogs = []ApplicationLog{applicationLog}
	}

	if props.HTTPLogs != nil {
		httpLogs := *props.HTTPLogs
		httpLog := HttpLog{}

		if httpLogs.FileSystem != nil && *httpLogs.FileSystem.Enabled {
			fileSystem := FileSystem{}
			if httpLogs.FileSystem.RetentionInMb != nil {
				fileSystem.RetentionMB = int(*httpLogs.FileSystem.RetentionInMb)
			}

			if httpLogs.FileSystem.RetentionInDays != nil {
				fileSystem.RetentionDays = int(*httpLogs.FileSystem.RetentionInDays)
			}
			httpLog.FileSystems = []FileSystem{fileSystem}
		}

		if httpLogs.AzureBlobStorage != nil {
			blobStorage := AzureBlobStorageHttp{}
			if httpLogs.AzureBlobStorage.SasURL != nil {
				blobStorage.SasUrl = *httpLogs.AzureBlobStorage.SasURL
			}

			if httpLogs.AzureBlobStorage.RetentionInDays != nil {
				blobStorage.RetentionInDays = int(*httpLogs.AzureBlobStorage.RetentionInDays)
			}

			httpLog.AzureBlobStorage = []AzureBlobStorageHttp{blobStorage}
		}

		logs.HttpLogs = []HttpLog{httpLog}
	}

	if props.DetailedErrorMessages != nil && props.DetailedErrorMessages.Enabled != nil {
		logs.DetailedErrorMessages = *props.DetailedErrorMessages.Enabled
	}

	if props.FailedRequestsTracing != nil && props.FailedRequestsTracing.Enabled != nil {
		logs.FailedRequestTracing = *props.FailedRequestsTracing.Enabled
	}

	return []LogsConfig{logs}
}

func flattenSiteConfig(appSiteConfig *web.SiteConfig) []SiteConfig {
	if appSiteConfig == nil {
		return nil
	}

	siteConfig := SiteConfig{
		ManagedPipelineMode: string(appSiteConfig.ManagedPipelineMode),
		ScmType:             string(appSiteConfig.ScmType),
		FtpsState:           string(appSiteConfig.FtpsState),
		MinTlsVersion:       string(appSiteConfig.MinTLSVersion),
		ScmMinTlsVersion:    string(appSiteConfig.ScmMinTLSVersion),
	}

	if appSiteConfig.AlwaysOn != nil {
		siteConfig.AlwaysOn = *appSiteConfig.AlwaysOn
	}

	if appSiteConfig.APIManagementConfig != nil && appSiteConfig.APIManagementConfig.ID != nil {
		siteConfig.ApiManagementConfigId = *appSiteConfig.APIManagementConfig.ID
	}

	if appSiteConfig.AppCommandLine != nil {
		siteConfig.AppCommandLine = *appSiteConfig.AppCommandLine
	}

	if appSiteConfig.DefaultDocuments != nil {
		siteConfig.DefaultDocuments = *appSiteConfig.DefaultDocuments
	}

	if appSiteConfig.HTTP20Enabled != nil {
		siteConfig.Http2Enabled = *appSiteConfig.HTTP20Enabled
	}

	if appSiteConfig.IPSecurityRestrictions != nil {
		siteConfig.IpRestriction = helpers.FlattenIpRestrictions(appSiteConfig.IPSecurityRestrictions)
	}

	if appSiteConfig.ScmIPSecurityRestrictionsUseMain != nil {
		siteConfig.ScmUseMainIpRestriction = *appSiteConfig.ScmIPSecurityRestrictionsUseMain
	}

	if appSiteConfig.ScmIPSecurityRestrictions != nil {
		siteConfig.ScmIpRestriction = helpers.FlattenIpRestrictions(appSiteConfig.ScmIPSecurityRestrictions)
	}

	if appSiteConfig.LocalMySQLEnabled != nil {
		siteConfig.LocalMysql = *appSiteConfig.LocalMySQLEnabled
	}

	if appSiteConfig.RemoteDebuggingEnabled != nil {
		siteConfig.RemoteDebugging = *appSiteConfig.RemoteDebuggingEnabled
	}

	if appSiteConfig.RemoteDebuggingVersion != nil {
		siteConfig.RemoteDebuggingVersion = *appSiteConfig.RemoteDebuggingVersion
	}

	if appSiteConfig.Use32BitWorkerProcess != nil {
		siteConfig.Use32BitWorker = *appSiteConfig.Use32BitWorkerProcess
	}

	if appSiteConfig.WebSocketsEnabled != nil {
		siteConfig.WebSockets = *appSiteConfig.WebSocketsEnabled
	}

	if appSiteConfig.HealthCheckPath != nil {
		siteConfig.HealthCheckPath = *appSiteConfig.HealthCheckPath
	}

	if appSiteConfig.NumberOfWorkers != nil {
		siteConfig.NumberOfWorkers = int(*appSiteConfig.NumberOfWorkers)
	}

	var winAppStack WindowsApplicationStack
	if appSiteConfig.NetFrameworkVersion != nil {
		winAppStack.NetFrameworkVersion = *appSiteConfig.NetFrameworkVersion
	}

	if appSiteConfig.PhpVersion != nil {
		winAppStack.PhpVersion = *appSiteConfig.PhpVersion
	}

	if appSiteConfig.NodeVersion != nil {
		winAppStack.NodeVersion = *appSiteConfig.NodeVersion
	}

	if appSiteConfig.PythonVersion != nil {
		winAppStack.PythonVersion = *appSiteConfig.PythonVersion
	}

	if appSiteConfig.JavaVersion != nil {
		winAppStack.JavaVersion = *appSiteConfig.JavaVersion
	}

	if appSiteConfig.JavaContainer != nil {
		winAppStack.JavaContainer = *appSiteConfig.JavaContainer
	}

	if appSiteConfig.JavaContainerVersion != nil {
		winAppStack.JavaContainerVersion = *appSiteConfig.JavaContainerVersion
	}

	siteConfig.WindowsApplicationStack = []WindowsApplicationStack{winAppStack}

	if appSiteConfig.LinuxFxVersion != nil {
		siteConfig.LinuxFxVersion = *appSiteConfig.LinuxFxVersion
	}

	if appSiteConfig.WindowsFxVersion != nil {
		siteConfig.WindowsFxVersion = *appSiteConfig.WindowsFxVersion
	}

	if appSiteConfig.AutoSwapSlotName != nil {
		siteConfig.AutoSwapSlotName = *appSiteConfig.AutoSwapSlotName
	}

	if appSiteConfig.Cors != nil {
		corsSettings := appSiteConfig.Cors
		cors := helpers.CorsSetting{}
		if corsSettings.SupportCredentials != nil {
			cors.SupportCredentials = *corsSettings.SupportCredentials
		}

		if corsSettings.AllowedOrigins != nil {
			cors.AllowedOrigins = *corsSettings.AllowedOrigins
		}
		siteConfig.Cors = []helpers.CorsSetting{cors}
	}

	return []SiteConfig{siteConfig}
}

func flattenStorageAccounts(appStorageAccounts web.AzureStoragePropertyDictionaryResource) []StorageAccount {
	if len(appStorageAccounts.Properties) == 0 {
		return nil
	}
	var storageAccounts []StorageAccount
	for k, v := range appStorageAccounts.Properties {
		storageAccount := StorageAccount{
			Name: k,
			Type: string(v.Type),
		}
		if v.AccountName != nil {
			storageAccount.AccountName = *v.AccountName
		}

		if v.ShareName != nil {
			storageAccount.ShareName = *v.ShareName
		}

		if v.AccessKey != nil {
			storageAccount.AccessKey = *v.AccessKey
		}

		if v.MountPath != nil {
			storageAccount.MountPath = *v.MountPath
		}

		storageAccounts = append(storageAccounts, storageAccount)
	}

	return storageAccounts
}

func flattenConnectionStrings(appConnectionStrings web.ConnectionStringDictionary) []ConnectionString {
	if len(appConnectionStrings.Properties) == 0 {
		return nil
	}
	var connectionStrings []ConnectionString
	for k, v := range appConnectionStrings.Properties {
		connectionString := ConnectionString{
			Name: k,
			Type: string(v.Type),
		}
		if v.Value != nil {
			connectionString.Value = *v.Value
		}
		connectionStrings = append(connectionStrings, connectionString)
	}

	return connectionStrings
}

func expandAppSettings(settings map[string]string) *web.StringDictionary {
	appSettings := make(map[string]*string)
	for k, v := range settings {
		appSettings[k] = utils.String(v)
	}

	return &web.StringDictionary{
		Properties: appSettings,
	}
}

func flattenAppSettings(input web.StringDictionary) map[string]string {
	unmanagedSettings := []string{
		"DIAGNOSTICS_AZUREBLOBCONTAINERSASURL",
		"DIAGNOSTICS_AZUREBLOBRETENTIONINDAYS",
		"WEBSITE_HTTPLOGGING_CONTAINER_URL",
		"WEBSITE_HTTPLOGGING_RETENTION_DAYS",
	}

	appSettings := helpers.FlattenWebStringDictionary(input)

	// Remove the settings the service adds when logging settings are specified.
	for _, v := range unmanagedSettings {
		delete(appSettings, v)
	}

	return appSettings
}
