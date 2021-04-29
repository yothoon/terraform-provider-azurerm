package domainservices

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/locks"

	"github.com/Azure/azure-sdk-for-go/services/domainservices/mgmt/2020-01-01/aad"
	"github.com/hashicorp/go-azure-helpers/response"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/tf"
	azValidate "github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/validate"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/clients"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/location"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/domainservices/parse"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tags"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tf/pluginsdk"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/timeouts"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

const DomainServiceResourceName = "azurerm_active_directory_domain_service"

func resourceActiveDirectoryDomainService() *pluginsdk.Resource {
	return &schema.Resource{
		Create: resourceActiveDirectoryDomainServiceCreateUpdate,
		Read:   resourceActiveDirectoryDomainServiceRead,
		Update: resourceActiveDirectoryDomainServiceCreateUpdate,
		Delete: resourceActiveDirectoryDomainServiceDelete,

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(180 * time.Minute),
			Read:   schema.DefaultTimeout(5 * time.Minute),
			Update: schema.DefaultTimeout(120 * time.Minute),
			Delete: schema.DefaultTimeout(30 * time.Minute),
		},

		Importer: pluginsdk.ImporterValidatingResourceId(func(id string) error {
			_, err := parse.DomainServiceID(id)
			return err
		}),

		Schema: map[string]*schema.Schema{ // TODO: add computed attributes: deployment_id, sync_owner
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringIsNotEmpty, // TODO: proper validation
			},

			"location": azure.SchemaLocation(),

			"resource_group_name": azure.SchemaResourceGroupName(),

			"domain_name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringIsNotEmpty, // TODO: proper validation, first prefix must be 15 chars or less
			},

			"sku": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					"Standard",
					"Enterprise",
					"Premium",
				}, false),
			},

			"domain_configuration_type": {
				Type:     schema.TypeString,
				ForceNew: true,
				Optional: true,
				Default:  "",
				ValidateFunc: validation.StringInSlice([]string{
					"",
					"ResourceTrusting",
				}, false),
			},

			"filtered_sync_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			"notifications": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"additional_recipients": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Schema{
								Type:         schema.TypeString,
								ValidateFunc: validation.StringIsNotWhiteSpace,
							},
						},

						"notify_dc_admins": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},

						"notify_global_admins": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
					},
				},
			},

			"initial_replica_set": {
				Type:     schema.TypeList,
				Required: true,
				MinItems: 1,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						// TODO: add health-related attributes

						"domain_controller_ip_addresses": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},

						"external_access_ip_address": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"id": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"location": {
							Type:             schema.TypeString,
							Required:         true,
							ForceNew:         true,
							ValidateFunc:     location.EnhancedValidate,
							StateFunc:        location.StateFunc,
							DiffSuppressFunc: location.DiffSuppressFunc,
						},

						"service_status": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"subnet_id": {
							Type:         schema.TypeString,
							Required:     true,
							ForceNew:     true,
							ValidateFunc: azure.ValidateResourceID,
						},
					},
				},
			},

			"resource_forest": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"resource_forest": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringIsNotEmpty,
						},

						"forest_trust": {
							Type:     schema.TypeList,
							Optional: true,
							MinItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringIsNotEmpty,
									},

									"remote_dns_ips": {
										Type:     schema.TypeList,
										Required: true,
										MinItems: 1,
										Elem: &schema.Schema{
											Type:         schema.TypeString,
											ValidateFunc: validation.StringIsNotEmpty,
										},
									},

									"trust_direction": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringIsNotEmpty,
									},

									"trust_password": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringIsNotEmpty,
									},

									"trusted_domain_fqdn": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringIsNotEmpty,
									},
								},
							},
						},
					},
				},
			},

			"secure_ldap": {
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

						"external_access_enabled": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},

						"external_access_ip_address": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"pfx_certificate": {
							Type:         schema.TypeString,
							Required:     true,
							Sensitive:    true,
							ValidateFunc: azValidate.Base64EncodedString,
						},

						"pfx_certificate_password": {
							Type:      schema.TypeString,
							Required:  true,
							Sensitive: true,
						},
					},
				},
			},

			"security": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"ntlm_v1_enabled": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},

						"sync_kerberos_passwords": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},

						"sync_ntlm_passwords": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},

						"sync_on_prem_passwords": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},

						"tls_v1_enabled": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
					},
				},
			},

			"tags": tags.Schema(),

			"deployment_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceActiveDirectoryDomainServiceCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).DomainServices.DomainServicesClient
	ctx, cancel := timeouts.ForCreateUpdate(meta.(*clients.Client).StopContext, d)
	defer cancel()

	name := d.Get("name").(string)
	resourceGroup := d.Get("resource_group_name").(string)
	id := parse.NewDomainServiceID(client.SubscriptionID, resourceGroup, name)

	locks.ByName(id.Name, DomainServiceResourceName)
	defer locks.UnlockByName(id.Name, DomainServiceResourceName)

	if d.IsNewResource() {
		existing, err := client.Get(ctx, id.ResourceGroup, id.Name)
		if err != nil {
			if !utils.ResponseWasNotFound(existing.Response) {
				return fmt.Errorf("checking for presence of existing %s: %s", id, err)
			}
		}

		if existing.ID != nil && *existing.ID != "" {
			return tf.ImportAsExistsError(DomainServiceResourceName, id.ID())
		}
	}

	location := azure.NormalizeLocation(d.Get("location").(string))
	filteredSync := aad.FilteredSyncDisabled
	if d.Get("filtered_sync_enabled").(bool) {
		filteredSync = aad.FilteredSyncDisabled
	}

	domainService := aad.DomainService{
		DomainServiceProperties: &aad.DomainServiceProperties{
			DomainName:             utils.String(d.Get("domain_name").(string)),
			DomainSecuritySettings: expandDomainServiceSecurity(d.Get("security").([]interface{})),
			FilteredSync:           filteredSync,
			LdapsSettings:          expandDomainServiceLdaps(d.Get("secure_ldap").([]interface{})),
			NotificationSettings:   expandDomainServiceNotifications(d.Get("notifications").([]interface{})),
			ResourceForestSettings: expandDomainServiceResourceForest(d.Get("resource_forest").([]interface{})),
			Sku:                    utils.String(d.Get("sku").(string)),
		},
		Location: &location,
		Tags:     tags.Expand(d.Get("tags").(map[string]interface{})),
	}

	if v, ok := d.GetOk("domain_configuration_type"); ok && v != "" {
		domainService.DomainServiceProperties.DomainConfigurationType = utils.String(d.Get("domain_configuration_type").(string))
	}

	if d.IsNewResource() {
		// On resource creation, specify the initial replica set.
		// No provision is made for updating the initial replica set, since changing the location or subnet would cause a rebuild anyway
		domainService.DomainServiceProperties.ReplicaSets = expandDomainServiceReplicaSets(d.Get("initial_replica_set").([]interface{}))
	}

	future, err := client.CreateOrUpdate(ctx, id.ResourceGroup, id.Name, domainService)
	if err != nil {
		return fmt.Errorf("creating/updating %s: %+v", id, err)
	}
	if err = future.WaitForCompletionRef(ctx, client.Client); err != nil {
		return fmt.Errorf("waiting for %s: %+v", id, err)
	}

	// A fully deployed domain service has 2 domain controllers per replica set, but the create operation completes early before the DCs are online.
	// The domain service is still provisioning and further operations are blocked until both DCs are up and ready.
	timeout, _ := ctx.Deadline()
	stateConf := &resource.StateChangeConf{
		Pending:      []string{"pending"},
		Target:       []string{"available"},
		Refresh:      domainServiceControllerRefreshFunc(ctx, client, id, false),
		Delay:        1 * time.Minute,
		PollInterval: 1 * time.Minute,
		Timeout:      time.Until(timeout),
	}

	if _, err := stateConf.WaitForState(); err != nil {
		return fmt.Errorf("waiting for both domain controllers to become available in primary replica set for %s: %+v", id, err)
	}

	d.SetId(id.ID())

	return resourceActiveDirectoryDomainServiceRead(d, meta)
}

func resourceActiveDirectoryDomainServiceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).DomainServices.DomainServicesClient
	ctx, cancel := timeouts.ForRead(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := parse.DomainServiceID(d.Id())
	if err != nil {
		return err
	}

	resp, err := client.Get(ctx, id.ResourceGroup, id.Name)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			d.SetId("")
			return nil
		}
		return err
	}

	d.Set("name", id.Name)
	d.Set("resource_group_name", id.ResourceGroup)

	if location := resp.Location; location != nil {
		d.Set("location", azure.NormalizeLocation(*location))
	}

	if props := resp.DomainServiceProperties; props != nil {
		domainConfigType := ""
		if v := props.DomainConfigurationType; v != nil {
			domainConfigType = *v
		}
		d.Set("domain_configuration_type", domainConfigType)

		d.Set("domain_name", props.DomainName)

		d.Set("filtered_sync_enabled", false)
		if props.FilteredSync == aad.FilteredSyncEnabled {
			d.Set("filtered_sync_enabled", true)
		}

		d.Set("sku", props.Sku)

		if err := d.Set("notifications", flattenDomainServiceNotifications(props.NotificationSettings)); err != nil {
			return fmt.Errorf("setting `notifications`: %+v", err)
		}

		var initialReplicaSet []interface{}
		replicaSets := flattenDomainServiceReplicaSets(props.ReplicaSets)
		if len(replicaSets) > 0 {
			initialReplicaSet = []interface{}{replicaSets[0]}
		}
		if err := d.Set("initial_replica_set", initialReplicaSet); err != nil {
			return fmt.Errorf("setting `initial_replica_set`: %+v", err)
		}

		if err := d.Set("resource_forest", flattenDomainServiceResourceForest(props.ResourceForestSettings)); err != nil {
			return fmt.Errorf("setting `resource_forest`: %+v", err)
		}

		if err := d.Set("secure_ldap", flattenDomainServiceLdaps(props.LdapsSettings)); err != nil {
			return fmt.Errorf("setting `secure_ldap`: %+v", err)
		}

		if err := d.Set("security", flattenDomainServiceSecurity(props.DomainSecuritySettings)); err != nil {
			return fmt.Errorf("setting `security`: %+v", err)
		}
	}

	return tags.FlattenAndSet(d, resp.Tags)
}

func resourceActiveDirectoryDomainServiceDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).DomainServices.DomainServicesClient
	ctx, cancel := timeouts.ForDelete(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := parse.DomainServiceID(d.Id())
	if err != nil {
		return err
	}

	future, err := client.Delete(ctx, id.ResourceGroup, id.Name)
	if err != nil {
		if response.WasNotFound(future.Response()) {
			return nil
		}
		return fmt.Errorf("deleting %s: %+v", id, err)
	}

	if err = future.WaitForCompletionRef(ctx, client.Client); err != nil {
		if !response.WasNotFound(future.Response()) {
			return fmt.Errorf("waiting for deletion of %s: %+v", id, err)
		}
	}

	return nil
}

func domainServiceControllerRefreshFunc(ctx context.Context, client *aad.DomainServicesClient, id parse.DomainServiceId, deleting bool) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		log.Printf("[DEBUG] Waiting for domain controllers to deploy...")
		resp, err := client.Get(ctx, id.ResourceGroup, id.Name)
		if err != nil {
			return nil, "error", err
		}
		if resp.DomainServiceProperties == nil || resp.DomainServiceProperties.ReplicaSets == nil || len(*resp.DomainServiceProperties.ReplicaSets) == 0 {
			return nil, "error", fmt.Errorf("API error: `replicaSets` was not returned")
		}
		for _, repl := range *resp.DomainServiceProperties.ReplicaSets {
			if repl.ServiceStatus == nil {
				return resp, "pending", nil
			}
			if !deleting && strings.EqualFold(*repl.ServiceStatus, "TearingDown") {
				// sometimes a service error will cause the resource to self destruct
				return resp, "error", fmt.Errorf("service error: a replica set is unexpectedly tearing down")
			} else if !strings.EqualFold(*repl.ServiceStatus, "Running") {
				// if it's not yet running, it isn't ready
				return resp, "pending", nil
			}
			// when a domain controller is online, its IP address will be returned. look for 2 active domain controllers
			if repl.DomainControllerIPAddress == nil || len(*repl.DomainControllerIPAddress) < 2 {
				return resp, "pending", nil
			}
		}
		return resp, "available", nil
	}
}

func expandDomainServiceLdaps(input []interface{}) (ldaps *aad.LdapsSettings) {
	ldaps = &aad.LdapsSettings{
		Ldaps: aad.LdapsDisabled,
	}

	if len(input) > 0 {
		v := input[0].(map[string]interface{})
		if v["enabled"].(bool) {
			ldaps.Ldaps = aad.LdapsEnabled
		}
		ldaps.PfxCertificate = utils.String(v["pfx_certificate"].(string))
		ldaps.PfxCertificatePassword = utils.String(v["pfx_certificate_password"].(string))
		if v["external_access_enabled"].(bool) {
			ldaps.ExternalAccess = aad.Enabled
		} else {
			ldaps.ExternalAccess = aad.Disabled
		}
	}

	return
}

func expandDomainServiceNotifications(input []interface{}) *aad.NotificationSettings {
	if len(input) == 0 {
		return nil
	}

	v := input[0].(map[string]interface{})

	additionalRecipients := make([]string, 0)
	if ar, ok := v["additional_recipients"]; ok {
		for _, r := range ar.(*schema.Set).List() {
			additionalRecipients = append(additionalRecipients, r.(string))
		}
	}

	notifyDcAdmins := aad.NotifyDcAdminsDisabled
	if n, ok := v["notify_dc_admins"]; ok && n.(bool) {
		notifyDcAdmins = aad.NotifyDcAdminsEnabled
	}

	notifyGlobalAdmins := aad.NotifyGlobalAdminsDisabled
	if n, ok := v["notify_global_admins"]; ok && n.(bool) {
		notifyGlobalAdmins = aad.NotifyGlobalAdminsEnabled
	}

	return &aad.NotificationSettings{
		AdditionalRecipients: &additionalRecipients,
		NotifyDcAdmins:       notifyDcAdmins,
		NotifyGlobalAdmins:   notifyGlobalAdmins,
	}
}

func expandDomainServiceReplicaSets(input []interface{}) *[]aad.ReplicaSet {
	ret := make([]aad.ReplicaSet, 0)

	for _, replicaRaw := range input {
		replica := replicaRaw.(map[string]interface{})

		loc := ""
		if v, ok := replica["location"]; ok {
			loc = v.(string)
		}

		subnetId := ""
		if v, ok := replica["subnet_id"]; ok {
			subnetId = v.(string)
		}

		ret = append(ret, aad.ReplicaSet{
			Location: &loc,
			SubnetID: &subnetId,
		})
	}

	return &ret
}

func expandDomainServiceResourceForest(input []interface{}) *aad.ResourceForestSettings {
	if len(input) == 0 {
		return nil
	}

	in := input[0].(map[string]interface{})

	forestTrusts := make([]aad.ForestTrust, 0)

	for _, inTrust := range in["forest_trust"].([]map[string]interface{}) {
		remoteDnsIps := strings.Join(inTrust["remote_dns_ips"].([]string), ",")
		forestTrusts = append(forestTrusts, aad.ForestTrust{
			TrustedDomainFqdn: utils.String(inTrust["trusted_domain_fqdn"].(string)),
			TrustDirection:    utils.String(inTrust["trust_direction"].(string)),
			FriendlyName:      utils.String(inTrust["name"].(string)),
			RemoteDNSIps:      utils.String(remoteDnsIps),
			TrustPassword:     utils.String(inTrust["trust_password"].(string)),
		})
	}

	return &aad.ResourceForestSettings{
		ResourceForest: utils.String(in["resource_forest"].(string)),
		Settings:       &forestTrusts,
	}
}

func expandDomainServiceSecurity(input []interface{}) *aad.DomainSecuritySettings {
	if len(input) == 0 {
		return nil
	}
	v := input[0].(map[string]interface{})

	ntlmV1 := aad.NtlmV1Disabled
	syncKerberosPasswords := aad.SyncKerberosPasswordsDisabled
	syncNtlmPasswords := aad.SyncNtlmPasswordsDisabled
	syncOnPremPasswords := aad.SyncOnPremPasswordsDisabled
	tlsV1 := aad.TLSV1Disabled

	if v["ntlm_v1_enabled"].(bool) {
		ntlmV1 = aad.NtlmV1Enabled
	}
	if v["sync_kerberos_passwords"].(bool) {
		syncKerberosPasswords = aad.SyncKerberosPasswordsEnabled
	}
	if v["sync_ntlm_passwords"].(bool) {
		syncNtlmPasswords = aad.SyncNtlmPasswordsEnabled
	}
	if v["sync_on_prem_passwords"].(bool) {
		syncOnPremPasswords = aad.SyncOnPremPasswordsEnabled
	}
	if v["tls_v1_enabled"].(bool) {
		tlsV1 = aad.TLSV1Enabled
	}

	return &aad.DomainSecuritySettings{
		NtlmV1:                ntlmV1,
		SyncKerberosPasswords: syncKerberosPasswords,
		SyncNtlmPasswords:     syncNtlmPasswords,
		SyncOnPremPasswords:   syncOnPremPasswords,
		TLSV1:                 tlsV1,
	}
}

func flattenDomainServiceLdaps(input *aad.LdapsSettings) []interface{} {
	result := map[string]interface{}{
		"enabled":                  false,
		"external_access_enabled":  false,
		"pfx_certificate":          "",
		"pfx_certificate_password": "",
	}

	if input != nil {
		if input.ExternalAccess == aad.Enabled {
			result["external_access_enabled"] = true
		}
		if input.Ldaps == aad.LdapsEnabled {
			result["enabled"] = true
		}
		if input.PfxCertificate != nil {
			result["pfx_certificate"] = *input.PfxCertificate
		}
		if input.PfxCertificatePassword != nil {
			result["pfx_certificate_password"] = *input.PfxCertificatePassword
		}
	}

	return []interface{}{result}
}

func flattenDomainServiceNotifications(input *aad.NotificationSettings) []interface{} {
	if input == nil {
		return make([]interface{}, 0)
	}

	result := map[string]interface{}{
		"additional_recipients": make([]string, 0),
		"notify_dc_admins":      false,
		"notify_global_admins":  false,
	}
	if input.AdditionalRecipients != nil {
		result["additional_recipients"] = *input.AdditionalRecipients
	}
	if input.NotifyDcAdmins == aad.NotifyDcAdminsEnabled {
		result["notify_dc_admins"] = true
	}
	if input.NotifyGlobalAdmins == aad.NotifyGlobalAdminsEnabled {
		result["notify_global_admins"] = true
	}

	return []interface{}{result}
}

func flattenDomainServiceReplicaSets(input *[]aad.ReplicaSet) (ret []interface{}) {
	if input == nil {
		return
	}

	for _, in := range *input {
		repl := map[string]interface{}{
			"domain_controller_ip_addresses": "",
			"external_access_ip_address":     "",
			"location":                       "",
			"id":                             "",
			"service_status":                 "",
			"subnet_id":                      "",
		}
		if in.DomainControllerIPAddress != nil {
			repl["domain_controller_ip_addresses"] = *in.DomainControllerIPAddress
		}
		if in.ExternalAccessIPAddress != nil {
			repl["external_access_ip_address"] = in.ExternalAccessIPAddress
		}
		if in.Location != nil {
			repl["location"] = azure.NormalizeLocation(*in.Location)
		}
		if in.ReplicaSetID != nil {
			repl["id"] = in.ReplicaSetID
		}
		if in.ServiceStatus != nil {
			repl["service_status"] = in.ServiceStatus
		}
		if in.SubnetID != nil {
			repl["subnet_id"] = in.SubnetID
		}
		ret = append(ret, repl)
	}

	return
}

func flattenDomainServiceResourceForest(input *aad.ResourceForestSettings) []interface{} {
	if input == nil {
		return make([]interface{}, 0)
	}

	forestTrust := make([]map[string]interface{}, 0)
	if input.Settings != nil {
		for _, rf := range *input.Settings {
			ft := map[string]interface{}{
				"name":                "",
				"remote_dns_ips":      []string{},
				"trust_direction":     "",
				"trust_password":      "",
				"trusted_domain_fqdn": "",
			}

			if rf.FriendlyName != nil {
				ft["name"] = *rf.FriendlyName
			}
			if rf.RemoteDNSIps != nil {
				remoteDnsIps := make([]string, 0)
				r := strings.Split(*rf.RemoteDNSIps, ",")
				for _, i := range r {
					remoteDnsIps = append(remoteDnsIps, strings.TrimSpace(i))
				}
				ft["remote_dns_ips"] = remoteDnsIps
			}
			if rf.TrustDirection != nil {
				ft["trust_direction"] = *rf.TrustDirection
			}
			if rf.TrustPassword != nil {
				ft["trust_password"] = rf.TrustPassword
			}
			if rf.TrustedDomainFqdn != nil {
				ft["trusted_domain_fqdn"] = *rf.TrustedDomainFqdn
			}

			forestTrust = append(forestTrust, ft)
		}
	}

	result := map[string]interface{}{
		"resource_forest": "",
		"forest_trust":    forestTrust,
	}
	if input.ResourceForest != nil {
		result["resource_forest"] = *input.ResourceForest
	}

	if result["resource_forest"].(string) == "" && len(result["forest_trust"].([]map[string]interface{})) == 0 {
		return make([]interface{}, 0)
	}

	return []interface{}{result}
}

func flattenDomainServiceSecurity(input *aad.DomainSecuritySettings) []interface{} {
	if input == nil {
		return make([]interface{}, 0)
	}

	result := map[string]bool{
		"ntlm_v1_enabled":         false,
		"sync_kerberos_passwords": false,
		"sync_ntlm_passwords":     false,
		"sync_on_prem_passwords":  false,
		"tls_v1_enabled":          false,
	}
	if input.NtlmV1 == aad.NtlmV1Enabled {
		result["ntlm_v1_enabled"] = true
	}
	if input.SyncKerberosPasswords == aad.SyncKerberosPasswordsEnabled {
		result["sync_kerberos_passwords"] = true
	}
	if input.SyncNtlmPasswords == aad.SyncNtlmPasswordsEnabled {
		result["sync_ntlm_passwords"] = true
	}
	if input.SyncOnPremPasswords == aad.SyncOnPremPasswordsEnabled {
		result["sync_on_prem_passwords"] = true
	}
	if input.TLSV1 == aad.TLSV1Enabled {
		result["tls_v1_enabled"] = true
	}

	return []interface{}{result}
}
