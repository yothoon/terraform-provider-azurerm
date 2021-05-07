package webapp

import (
	"fmt"
	"strings"
	"time"

	"github.com/terraform-providers/terraform-provider-azuread/azuread/helpers/validate"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/appservice/helpers"

	"github.com/Azure/azure-sdk-for-go/services/web/mgmt/2020-12-01/web"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	apimValidate "github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/apimanagement/validate"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tf/suppress"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tf/validation"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

const osTypeWindows = "Windows"
const osTypeLinux = "Linux"

type SiteConfigWindows struct {
	AlwaysOn                bool                    `tfschema:"always_on"`
	ApiManagementConfigId   string                  `tfschema:"api_management_config_id"`
	AppCommandLine          string                  `tfschema:"app_command_line"`
	DefaultDocuments        []string                `tfschema:"default_documents"`
	Http2Enabled            bool                    `tfschema:"http2_enabled"`
	IpRestriction           []helpers.IpRestriction `tfschema:"ip_restriction"`
	ScmUseMainIpRestriction bool                    `tfschema:"scm_use_main_ip_restriction"`
	ScmIpRestriction        []helpers.IpRestriction `tfschema:"scm_ip_restriction"`
	// LoadBalancing string `tfschema:"load_balancing_mode"` // TODO - New field to support, defaults to `LeastRequests`
	LocalMysql             bool                      `tfschema:"local_mysql"`
	ManagedPipelineMode    string                    `tfschema:"managed_pipeline_mode"`
	RemoteDebugging        bool                      `tfschema:"remote_debugging"`
	RemoteDebuggingVersion string                    `tfschema:"remote_debugging_version"`
	ScmType                string                    `tfschema:"scm_type"`
	Use32BitWorker         bool                      `tfschema:"use_32_bit_worker"`
	WebSockets             bool                      `tfschema:"websockets"`
	FtpsState              string                    `tfschema:"ftps_state"`
	HealthCheckPath        string                    `tfschema:"health_check_path"`
	NumberOfWorkers        int                       `tfschema:"number_of_workers"`
	ApplicationStack       []ApplicationStackWindows `tfschema:"application_stack"`
	MinTlsVersion          string                    `tfschema:"minimum_tls_version"`
	ScmMinTlsVersion       string                    `tfschema:"scm_minimum_tls_version"`
	AutoSwapSlotName       string                    `tfschema:"auto_swap_slot_name"`
	Cors                   []helpers.CorsSetting     `tfschema:"cors"`
	DetailedErrorLogging   bool                      `tfschema:"detailed_error_logging"`
	LinuxFxVersion         string                    `tfschema:"linux_fx_version"`
	WindowsFxVersion       string                    `tfschema:"windows_fx_version"`
	// Push  []PushSetting `tfschema:"push"` // TODO - new block to (possibly) support?
	// SiteLimits []SiteLimitsSettings `tfschema:"site_limits"` // TODO - New block to (possibly) support?
	// VirtualApplications []VirtualApplications //TODO - New (computed?) block to (possibly) support?
	// Stacks
	// TODO fields
	// AutoHeal bool
	// AutoHealRules []AutoHealRule
}

type SiteConfigLinux struct {
	AlwaysOn                bool                    `tfschema:"always_on"`
	ApiManagementConfigId   string                  `tfschema:"api_management_config_id"`
	AppCommandLine          string                  `tfschema:"app_command_line"`
	DefaultDocuments        []string                `tfschema:"default_documents"`
	Http2Enabled            bool                    `tfschema:"http2_enabled"`
	IpRestriction           []helpers.IpRestriction `tfschema:"ip_restriction"`
	ScmUseMainIpRestriction bool                    `tfschema:"scm_use_main_ip_restriction"`
	ScmIpRestriction        []helpers.IpRestriction `tfschema:"scm_ip_restriction"`
	// LoadBalancing string `tfschema:"load_balancing_mode"` // TODO - New field to support, defaults to `LeastRequests`
	LocalMysql             bool                    `tfschema:"local_mysql"`
	ManagedPipelineMode    string                  `tfschema:"managed_pipeline_mode"`
	RemoteDebugging        bool                    `tfschema:"remote_debugging"`
	RemoteDebuggingVersion string                  `tfschema:"remote_debugging_version"`
	ScmType                string                  `tfschema:"scm_type"`
	Use32BitWorker         bool                    `tfschema:"use_32_bit_worker"`
	WebSockets             bool                    `tfschema:"websockets"`
	FtpsState              string                  `tfschema:"ftps_state"`
	HealthCheckPath        string                  `tfschema:"health_check_path"`
	NumberOfWorkers        int                     `tfschema:"number_of_workers"`
	ApplicationStack       []ApplicationStackLinux `tfschema:"application_stack"`
	MinTlsVersion          string                  `tfschema:"minimum_tls_version"`
	ScmMinTlsVersion       string                  `tfschema:"scm_minimum_tls_version"`
	AutoSwapSlotName       string                  `tfschema:"auto_swap_slot_name"`
	Cors                   []helpers.CorsSetting   `tfschema:"cors"`
	DetailedErrorLogging   bool                    `tfschema:"detailed_error_logging"`
	LinuxFxVersion         string                  `tfschema:"linux_fx_version"`
	WindowsFxVersion       string                  `tfschema:"windows_fx_version"`
	// Push  []PushSetting `tfschema:"push"` // TODO - new block to (possibly) support?
	// SiteLimits []SiteLimitsSettings `tfschema:"site_limits"` // TODO - New block to (possibly) support?
	// VirtualApplications []VirtualApplications //TODO - New (computed?) block to (possibly) support?
	// Stacks
	// TODO fields
	// AutoHeal bool
	// AutoHealRules []AutoHealRule
}

func siteConfigSchema(osType string) *schema.Schema {
	siteConfigResource := &schema.Resource{
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

			"detailed_error_logging": {
				Type:     schema.TypeBool,
				Computed: true,
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
	}
	switch osType {
	case osTypeLinux:
		siteConfigResource.Schema["application_stack"] = linuxApplicationStackSchema()
	default:
		siteConfigResource.Schema["application_stack"] = windowsApplicationStackSchema()
	}

	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem:     siteConfigResource,
	}
}

type ApplicationStackWindows struct {
	NetFrameworkVersion     string `tfschema:"dotnet_framework_version"`
	PhpVersion              string `tfschema:"php_version"`
	JavaVersion             string `tfschema:"java_version"`
	PythonVersion           string `tfschema:"python_version"` // Linux Only?
	NodeVersion             string `tfschema:"node_version"`
	JavaContainer           string `tfschema:"java_container"`
	JavaContainerVersion    string `tfschema:"java_container_version"`
	DockerContainerName     string `tfschema:"docker_container_name"`
	DockerContainerRegistry string `tfschema:"docker_container_registry"`
	DockerContainerTag      string `tfschema:"docker_container_tag"`
	CurrentStack            string `tfschema:"current_stack"`
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
				},

				"python_version": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"2.7",
						"3.4.0",
					}, false),
				},

				"node_version": { // Discarded by service if JavaVersion is specified
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"10.1",   // Linux Only?
						"10.6",   // Linux Only?
						"10.10",  // Linux Only?
						"10.14",  // Linux Only?
						"10-LTS", // Linux Only?
						"12-LTS",
						"14-LTS",
					}, false),
					ConflictsWith: []string{
						"site_config.0.application_stack.0.java_version",
					},
				},

				"java_version": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						"1.7",
						"1.8",
						"11",
					}, false),
				},

				"java_container": {Type: schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						"JAVA",
						"JETTY",
						"TOMCAT",
					}, false),
					RequiredWith: []string{
						"site_config.0.application_stack.0.java_container_version",
					},
				},

				"java_container_version": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					RequiredWith: []string{
						"site_config.0.application_stack.0.java_container",
					},
				},

				"docker_container_name": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.StringIsNotEmpty,
					RequiredWith: []string{
						"site_config.0.application_stack.0.docker_container_registry",
						"site_config.0.application_stack.0.docker_container_tag",
					},
				},

				"docker_container_registry": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.StringIsNotEmpty,
					RequiredWith: []string{
						"site_config.0.application_stack.0.docker_container_name",
						"site_config.0.application_stack.0.docker_container_tag",
					},
				},

				"docker_container_tag": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.StringIsNotEmpty,
					RequiredWith: []string{
						"site_config.0.application_stack.0.docker_container_name",
						"site_config.0.application_stack.0.docker_container_registry",
					},
				},

				"current_stack": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"dotnet",
						"node",
						"python",
						"php",
						"java",
					}, false),
				},
			},
		},
	}
}

type ApplicationStackLinux struct {
	NetFrameworkVersion string `tfschema:"dotnet_framework_version"`
	PhpVersion          string `tfschema:"php_version"`
	PythonVersion       string `tfschema:"python_version"` // Linux Only?
	NodeVersion         string `tfschema:"node_version"`
	JavaVersion         string `tfschema:"java_version"`
	JavaServer          string `tfschema:"java_server"`
	JavaServerVersion   string `tfschema:"java_server_version"`
	DockerImageTag      string `tfschema:"docker_image_tag"`
	DockerImage         string `tfschema:"docker_image"`
	RubyVersion         string `tfschema:"ruby_version"`
}

// version information in the validation here was taken mostly from - `az webapp list-runtimes --linux`
func linuxApplicationStackSchema() *schema.Schema {
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
						"2.1",
						"3.1",
						"5.0",
					}, false),
				},

				"php_version": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						"5.6", // TODO - Remove? 5.6 is available, but deprecated in the service
						"7.2", // TODO - Remove? 7.2 is available, but deprecated in the service
						"7.3",
						"7.4",
					}, false),
				},

				"python_version": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"2.7", // TODO - Remove? 2.7 is available, but deprecated in the service
						"3.6",
						"3.7",
						"3.8",
					}, false),
				},

				"node_version": { // Discarded by service if JavaVersion is specified
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"10.1",   // TODO - Remove?  Deprecated
						"10.6",   // TODO - Remove?  Deprecated
						"10.14",  // TODO - Remove?  Deprecated
						"10-lts", // TODO - Remove?  Deprecated
						"12-lts",
						"14-lts",
					}, false),
					ConflictsWith: []string{
						"site_config.0.application_stack.0.java_version",
					},
				},

				"ruby_version": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"2.5",
						"2.6",
					}, false),
				},

				"java_version": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validate.NoEmptyStrings, // There a significant number of variables here, and the versions are not uniformly formatted.
					// TODO - Needs notes in the docs for this to help users navigate the inconsistencies in the service. e.g. jre8 va java8 etc
				},

				"java_server": {Type: schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"JAVA",
						"TOMCAT",
						"JBOSSEAP",
					}, false),
				},

				"java_server_version": {
					Type:     schema.TypeString,
					Optional: true,
				},

				"docker_image": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.StringIsNotEmpty,
					RequiredWith: []string{
						"site_config.0.application_stack.0.docker_image_tag",
					},
				},

				"docker_image_tag": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.StringIsNotEmpty,
					RequiredWith: []string{
						"site_config.0.application_stack.0.docker_image",
					},
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

func expandSiteConfigWindows(siteConfig []SiteConfigWindows) (*web.SiteConfig, *string, error) {
	if len(siteConfig) == 0 {
		return nil, nil, nil
	}
	expanded := &web.SiteConfig{}
	currentStack := ""

	winSiteConfig := siteConfig[0]
	expanded.AlwaysOn = utils.Bool(winSiteConfig.AlwaysOn)

	if winSiteConfig.ApiManagementConfigId != "" {
		expanded.APIManagementConfig = &web.APIManagementConfig{
			ID: utils.String(winSiteConfig.ApiManagementConfigId),
		}
	}

	if winSiteConfig.AppCommandLine != "" {
		expanded.AppCommandLine = utils.String(winSiteConfig.AppCommandLine)
	}

	if len(winSiteConfig.ApplicationStack) == 1 {
		winAppStack := winSiteConfig.ApplicationStack[0]
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

		if winAppStack.DockerContainerName != "" {
			expanded.WindowsFxVersion = utils.String(fmt.Sprintf("DOCKER|%s/%s:%s", winAppStack.DockerContainerRegistry, winAppStack.DockerContainerName, winAppStack.DockerContainerTag))
		}
		currentStack = winAppStack.CurrentStack
	}

	if len(winSiteConfig.DefaultDocuments) != 0 {
		expanded.DefaultDocuments = &winSiteConfig.DefaultDocuments
	}

	expanded.HTTP20Enabled = utils.Bool(winSiteConfig.Http2Enabled)

	if len(winSiteConfig.IpRestriction) != 0 {
		ipRestrictions, err := helpers.ExpandIpRestrictions(winSiteConfig.IpRestriction)
		if err != nil {
			return nil, nil, err
		}
		expanded.IPSecurityRestrictions = ipRestrictions
	}

	expanded.ScmIPSecurityRestrictionsUseMain = utils.Bool(winSiteConfig.ScmUseMainIpRestriction)

	if len(winSiteConfig.ScmIpRestriction) != 0 {
		scmIpRestrictions, err := helpers.ExpandIpRestrictions(winSiteConfig.ScmIpRestriction)
		if err != nil {
			return nil, nil, err
		}
		expanded.ScmIPSecurityRestrictions = scmIpRestrictions
	}

	expanded.LocalMySQLEnabled = utils.Bool(winSiteConfig.LocalMysql)

	if winSiteConfig.ManagedPipelineMode != "" {
		expanded.ManagedPipelineMode = web.ManagedPipelineMode(winSiteConfig.ManagedPipelineMode)
	}

	if winSiteConfig.RemoteDebugging {
		expanded.RemoteDebuggingEnabled = utils.Bool(winSiteConfig.RemoteDebugging)
	}

	if winSiteConfig.RemoteDebuggingVersion != "" {
		expanded.RemoteDebuggingVersion = utils.String(winSiteConfig.RemoteDebuggingVersion)
	}

	if winSiteConfig.ScmType != "" {
		expanded.ScmType = web.ScmType(winSiteConfig.ScmType)
	}

	expanded.Use32BitWorkerProcess = utils.Bool(winSiteConfig.Use32BitWorker)

	expanded.WebSocketsEnabled = utils.Bool(winSiteConfig.WebSockets)

	if winSiteConfig.FtpsState != "" {
		expanded.FtpsState = web.FtpsState(winSiteConfig.FtpsState)
	}

	if winSiteConfig.HealthCheckPath != "" {
		expanded.HealthCheckPath = utils.String(winSiteConfig.HealthCheckPath)
	}

	if winSiteConfig.NumberOfWorkers != 0 {
		expanded.NumberOfWorkers = utils.Int32(int32(winSiteConfig.NumberOfWorkers))
	}

	if winSiteConfig.MinTlsVersion != "" {
		expanded.MinTLSVersion = web.SupportedTLSVersions(winSiteConfig.MinTlsVersion)
	}

	if winSiteConfig.ScmMinTlsVersion != "" {
		expanded.ScmMinTLSVersion = web.SupportedTLSVersions(winSiteConfig.ScmMinTlsVersion)
	}

	if winSiteConfig.AutoSwapSlotName != "" {
		expanded.AutoSwapSlotName = utils.String(winSiteConfig.AutoSwapSlotName)
	}

	if len(winSiteConfig.Cors) != 0 {
		expanded.Cors = helpers.ExpandCorsSettings(winSiteConfig.Cors)
	}

	return expanded, &currentStack, nil
}

func expandSiteConfigLinux(siteConfig []SiteConfigLinux) (*web.SiteConfig, error) {
	if len(siteConfig) == 0 {
		return nil, nil
	}
	expanded := &web.SiteConfig{}

	linuxSiteConfig := siteConfig[0]
	expanded.AlwaysOn = utils.Bool(linuxSiteConfig.AlwaysOn)

	if linuxSiteConfig.ApiManagementConfigId != "" {
		expanded.APIManagementConfig = &web.APIManagementConfig{
			ID: utils.String(linuxSiteConfig.ApiManagementConfigId),
		}
	}

	if linuxSiteConfig.AppCommandLine != "" {
		expanded.AppCommandLine = utils.String(linuxSiteConfig.AppCommandLine)
	}

	if len(linuxSiteConfig.ApplicationStack) == 1 {
		linuxAppStack := linuxSiteConfig.ApplicationStack[0]
		if linuxAppStack.NetFrameworkVersion != "" {
			expanded.LinuxFxVersion = utils.String(fmt.Sprintf("DOTNETCORE|%s", linuxAppStack.NetFrameworkVersion))
		}

		if linuxAppStack.PhpVersion != "" {
			expanded.LinuxFxVersion = utils.String(fmt.Sprintf("PHP|%s", linuxAppStack.PhpVersion))
		}

		if linuxAppStack.NodeVersion != "" {
			expanded.LinuxFxVersion = utils.String(fmt.Sprintf("NODE|%s", linuxAppStack.NodeVersion))
		}

		if linuxAppStack.PythonVersion != "" {
			expanded.LinuxFxVersion = utils.String(fmt.Sprintf("PYTHON|%s", linuxAppStack.PythonVersion))
		}

		if linuxAppStack.JavaServer != "" {
			// (@jackofallops) - Java has some special cases for Java SE when using specific versions of the runtime, resulting in this string
			// being formatted in the form: `JAVA|u242` instead of the standard pattern of `JAVA|u242-java8` for example. This applies to jre8 and java11.
			if linuxAppStack.JavaServer == "JAVA" && linuxAppStack.JavaServerVersion == "" {
				expanded.LinuxFxVersion = utils.String(fmt.Sprintf("%s|%s", linuxAppStack.JavaServer, linuxAppStack.JavaVersion))
			} else {
				expanded.LinuxFxVersion = utils.String(fmt.Sprintf("%s|%s-%s", linuxAppStack.JavaServer, linuxAppStack.JavaServerVersion, linuxAppStack.JavaVersion))
			}
		}

		if linuxAppStack.DockerImage != "" {
			expanded.LinuxFxVersion = utils.String(fmt.Sprintf("DOCKER|%s:%s", linuxAppStack.DockerImage, linuxAppStack.DockerImageTag))
		}
	}

	if len(linuxSiteConfig.DefaultDocuments) != 0 {
		expanded.DefaultDocuments = &linuxSiteConfig.DefaultDocuments
	}

	expanded.HTTP20Enabled = utils.Bool(linuxSiteConfig.Http2Enabled)

	if len(linuxSiteConfig.IpRestriction) != 0 {
		ipRestrictions, err := helpers.ExpandIpRestrictions(linuxSiteConfig.IpRestriction)
		if err != nil {
			return nil, err
		}
		expanded.IPSecurityRestrictions = ipRestrictions
	}

	expanded.ScmIPSecurityRestrictionsUseMain = utils.Bool(linuxSiteConfig.ScmUseMainIpRestriction)

	if len(linuxSiteConfig.ScmIpRestriction) != 0 {
		scmIpRestrictions, err := helpers.ExpandIpRestrictions(linuxSiteConfig.ScmIpRestriction)
		if err != nil {
			return nil, err
		}
		expanded.ScmIPSecurityRestrictions = scmIpRestrictions
	}

	expanded.LocalMySQLEnabled = utils.Bool(linuxSiteConfig.LocalMysql)

	if linuxSiteConfig.ManagedPipelineMode != "" {
		expanded.ManagedPipelineMode = web.ManagedPipelineMode(linuxSiteConfig.ManagedPipelineMode)
	}

	if linuxSiteConfig.RemoteDebugging {
		expanded.RemoteDebuggingEnabled = utils.Bool(linuxSiteConfig.RemoteDebugging)
	}

	if linuxSiteConfig.RemoteDebuggingVersion != "" {
		expanded.RemoteDebuggingVersion = utils.String(linuxSiteConfig.RemoteDebuggingVersion)
	}

	if linuxSiteConfig.ScmType != "" {
		expanded.ScmType = web.ScmType(linuxSiteConfig.ScmType)
	}

	expanded.Use32BitWorkerProcess = utils.Bool(linuxSiteConfig.Use32BitWorker)

	expanded.WebSocketsEnabled = utils.Bool(linuxSiteConfig.WebSockets)

	if linuxSiteConfig.FtpsState != "" {
		expanded.FtpsState = web.FtpsState(linuxSiteConfig.FtpsState)
	}

	if linuxSiteConfig.HealthCheckPath != "" {
		expanded.HealthCheckPath = utils.String(linuxSiteConfig.HealthCheckPath)
	}

	if linuxSiteConfig.NumberOfWorkers != 0 {
		expanded.NumberOfWorkers = utils.Int32(int32(linuxSiteConfig.NumberOfWorkers))
	}

	if linuxSiteConfig.MinTlsVersion != "" {
		expanded.MinTLSVersion = web.SupportedTLSVersions(linuxSiteConfig.MinTlsVersion)
	}

	if linuxSiteConfig.ScmMinTlsVersion != "" {
		expanded.ScmMinTLSVersion = web.SupportedTLSVersions(linuxSiteConfig.ScmMinTlsVersion)
	}

	if linuxSiteConfig.AutoSwapSlotName != "" {
		expanded.AutoSwapSlotName = utils.String(linuxSiteConfig.AutoSwapSlotName)
	}

	if len(linuxSiteConfig.Cors) != 0 {
		expanded.Cors = helpers.ExpandCorsSettings(linuxSiteConfig.Cors)
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
				Enabled:         utils.Bool(httpLogsBlobStorage.SasUrl != ""),
				SasURL:          utils.String(httpLogsBlobStorage.SasUrl),
				RetentionInDays: utils.Int32(int32(httpLogsBlobStorage.RetentionInDays)),
			}
		}
	}

	siteLogsConfig.DetailedErrorMessages = &web.EnabledConfig{
		Enabled: utils.Bool(logsConfig.DetailedErrorMessages),
	}

	siteLogsConfig.FailedRequestsTracing = &web.EnabledConfig{
		Enabled: utils.Bool(logsConfig.FailedRequestTracing),
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

	if props.DetailedErrorMessages != nil {
		logs.DetailedErrorMessages = *props.DetailedErrorMessages.Enabled
	}

	if props.FailedRequestsTracing != nil {
		logs.FailedRequestTracing = *props.FailedRequestsTracing.Enabled
	}

	return []LogsConfig{logs}
}

func flattenSiteConfigWindows(appSiteConfig *web.SiteConfig) []SiteConfigWindows {
	if appSiteConfig == nil {
		return nil
	}

	siteConfig := SiteConfigWindows{
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

	siteConfig.DetailedErrorLogging = *appSiteConfig.DetailedErrorLoggingEnabled

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

	var winAppStack ApplicationStackWindows
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

	if appSiteConfig.WindowsFxVersion != nil {
		siteConfig.WindowsFxVersion = *appSiteConfig.WindowsFxVersion
		// Decode the string to docker values
		parts := strings.Split(strings.TrimPrefix(siteConfig.WindowsFxVersion, "DOCKER|"), ":")
		winAppStack.DockerContainerTag = parts[1]
		path := strings.Split(parts[0], "/")
		winAppStack.DockerContainerRegistry = path[0]
		winAppStack.DockerContainerName = strings.TrimPrefix(parts[0], fmt.Sprintf("%s/", path[0]))
	}

	siteConfig.ApplicationStack = []ApplicationStackWindows{winAppStack}

	if appSiteConfig.LinuxFxVersion != nil {
		siteConfig.LinuxFxVersion = *appSiteConfig.LinuxFxVersion
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

	return []SiteConfigWindows{siteConfig}
}

func flattenSiteConfigLinux(appSiteConfig *web.SiteConfig) []SiteConfigLinux {
	// TODO - Make this Linux flavoured...
	if appSiteConfig == nil {
		return nil
	}

	siteConfig := SiteConfigLinux{
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

	siteConfig.DetailedErrorLogging = *appSiteConfig.DetailedErrorLoggingEnabled

	if appSiteConfig.HTTP20Enabled != nil {
		siteConfig.Http2Enabled = *appSiteConfig.HTTP20Enabled
	}

	if appSiteConfig.IPSecurityRestrictions != nil {
		siteConfig.IpRestriction = helpers.FlattenIpRestrictions(appSiteConfig.IPSecurityRestrictions)
	}

	siteConfig.ScmUseMainIpRestriction = *appSiteConfig.ScmIPSecurityRestrictionsUseMain

	if appSiteConfig.ScmIPSecurityRestrictions != nil {
		siteConfig.ScmIpRestriction = helpers.FlattenIpRestrictions(appSiteConfig.ScmIPSecurityRestrictions)
	}

	siteConfig.LocalMysql = *appSiteConfig.LocalMySQLEnabled

	siteConfig.RemoteDebugging = *appSiteConfig.RemoteDebuggingEnabled

	if appSiteConfig.RemoteDebuggingVersion != nil {
		siteConfig.RemoteDebuggingVersion = *appSiteConfig.RemoteDebuggingVersion
	}

	if appSiteConfig.Use32BitWorkerProcess != nil {
		siteConfig.Use32BitWorker = *appSiteConfig.Use32BitWorkerProcess
	}

	siteConfig.WebSockets = *appSiteConfig.WebSocketsEnabled

	if appSiteConfig.HealthCheckPath != nil {
		siteConfig.HealthCheckPath = *appSiteConfig.HealthCheckPath
	}

	if appSiteConfig.NumberOfWorkers != nil {
		siteConfig.NumberOfWorkers = int(*appSiteConfig.NumberOfWorkers)
	}

	var linuxAppStack ApplicationStackLinux

	if appSiteConfig.LinuxFxVersion != nil {
		siteConfig.LinuxFxVersion = *appSiteConfig.LinuxFxVersion
		// Decode the string to docker values
		linuxAppStack = decodeApplicationStackLinux(siteConfig.LinuxFxVersion)
	}

	siteConfig.ApplicationStack = []ApplicationStackLinux{linuxAppStack}

	if appSiteConfig.LinuxFxVersion != nil {
		siteConfig.LinuxFxVersion = *appSiteConfig.LinuxFxVersion
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

	return []SiteConfigLinux{siteConfig}
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
