package domainservices

import (
	"fmt"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/timeouts"

	"github.com/Azure/azure-sdk-for-go/services/domainservices/mgmt/2020-01-01/aad"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/clients"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tags"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

func dataSourceActiveDirectoryDomainService() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceActiveDirectoryDomainServiceRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringIsNotWhiteSpace,
			},

			"resource_group_name": azure.SchemaResourceGroupNameForDataSource(),

			"domain_configuration_type": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"domain_name": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"filtered_sync_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},

			"location": azure.SchemaLocationForDataSource(),

			"notifications": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"additional_recipients": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"notify_dc_admins": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"notify_global_admins": {
							Type:     schema.TypeBool,
							Computed: true,
						},
					},
				},
			},

			"initial_replica_set": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: dataSourceActiveDirectoryDomainServiceReplicaSetSchema(),
				},
			},

			"additional_replica_sets": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: dataSourceActiveDirectoryDomainServiceReplicaSetSchema(),
				},
			},

			"resource_forest": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"resource_forest": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"forest_trust": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Computed: true,
									},

									"remote_dns_ips": {
										Type:     schema.TypeList,
										Computed: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},

									"trust_direction": {
										Type:     schema.TypeString,
										Computed: true,
									},

									"trust_password": {
										Type:     schema.TypeString,
										Computed: true,
									},

									"trusted_domain_fqdn": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
							},
						},
					},
				},
			},

			"secure_ldap": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},

						"external_access_enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},

						"external_access_ip_address": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"pfx_certificate": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"pfx_certificate_password": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},

			"security": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"ntlm_v1_enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},

						"sync_kerberos_passwords": {
							Type:     schema.TypeBool,
							Computed: true,
						},

						"sync_ntlm_passwords": {
							Type:     schema.TypeBool,
							Computed: true,
						},

						"sync_on_prem_passwords": {
							Type:     schema.TypeBool,
							Computed: true,
						},

						"tls_v1_enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},
					},
				},
			},

			"sku": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"tags": tags.SchemaDataSource(),
		},
	}
}

func dataSourceActiveDirectoryDomainServiceReplicaSetSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
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
			Type:     schema.TypeString,
			Computed: true,
		},

		"service_status": {
			Type:     schema.TypeString,
			Computed: true,
		},

		"subnet_id": {
			Type:     schema.TypeString,
			Computed: true,
		},
	}
}

func dataSourceActiveDirectoryDomainServiceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).DomainServices.DomainServicesClient
	ctx, cancel := timeouts.ForRead(meta.(*clients.Client).StopContext, d)
	defer cancel()

	name := d.Get("name").(string)
	resourceGroup := d.Get("resource_group_name").(string)

	resp, err := client.Get(ctx, resourceGroup, name)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			return nil
		}
		return err
	}

	if resp.ID == nil {
		return fmt.Errorf("reading Domain Service: ID was returned nil")
	}
	d.SetId(*resp.ID)

	d.Set("name", name)
	d.Set("resource_group_name", resourceGroup)

	if resp.Location == nil {
		return fmt.Errorf("reading Domain Service %q: location was returned nil", d.Id())
	}
	d.Set("location", azure.NormalizeLocation(*resp.Location))

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

		if err := d.Set("resource_forest", flattenDomainServiceResourceForest(props.ResourceForestSettings)); err != nil {
			return fmt.Errorf("setting `resource_forest`: %+v", err)
		}

		if err := d.Set("secure_ldap", flattenDomainServiceLdaps(props.LdapsSettings)); err != nil {
			return fmt.Errorf("setting `secure_ldap`: %+v", err)
		}

		if err := d.Set("security", flattenDomainServiceSecurity(props.DomainSecuritySettings)); err != nil {
			return fmt.Errorf("setting `security`: %+v", err)
		}

		if replicaSets := flattenDomainServiceReplicaSets(props.ReplicaSets); len(replicaSets) > 0 {
			var initialReplicaSets, additionalReplicaSets []interface{}
			for _, replicaSetRaw := range replicaSets {
				replicaSet := replicaSetRaw.(map[string]interface{})
				location, hasLocation := replicaSet["location"]
				if !hasLocation {
					continue
				}
				if azure.NormalizeLocation(location) == azure.NormalizeLocation(*resp.Location) && len(initialReplicaSets) == 0 {
					initialReplicaSets = append(initialReplicaSets, replicaSet)
				} else {
					additionalReplicaSets = append(additionalReplicaSets, replicaSet)
				}
			}

			if err := d.Set("initial_replica_set", initialReplicaSets); err != nil {
				return fmt.Errorf("setting `initial_replica_sets`: %+v", err)
			}

			if err := d.Set("additional_replica_sets", additionalReplicaSets); err != nil {
				return fmt.Errorf("setting `additional_replica_sets`: %+v", err)
			}
		}
	}

	return tags.FlattenAndSet(d, resp.Tags)
}
