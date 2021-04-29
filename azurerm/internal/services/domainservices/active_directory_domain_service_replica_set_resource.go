package domainservices

import (
	"fmt"
	"time"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/location"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/tf"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/locks"

	"github.com/Azure/azure-sdk-for-go/services/domainservices/mgmt/2020-01-01/aad"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/domainservices/validate"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/clients"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/domainservices/parse"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/timeouts"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

func resourceActiveDirectoryDomainServiceReplicaSet() *schema.Resource {
	return &schema.Resource{
		Create: resourceActiveDirectoryDomainServiceReplicaSetCreate,
		Read:   resourceActiveDirectoryDomainServiceReplicaSetRead,
		Delete: resourceActiveDirectoryDomainServiceReplicaSetDelete,

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(180 * time.Minute),
			Read:   schema.DefaultTimeout(5 * time.Minute),
			Update: schema.DefaultTimeout(120 * time.Minute),
			Delete: schema.DefaultTimeout(30 * time.Minute),
		},

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			// TODO: add computed attributes: deployment_id, sync_owner
			// TODO: add health-related attributes
			"domain_service_id": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validate.DomainServiceID,
			},

			"location": azure.SchemaLocation(),

			"subnet_id": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: azure.ValidateResourceID,
			},

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

			"service_status": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceActiveDirectoryDomainServiceReplicaSetCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).DomainServices.DomainServicesClient
	ctx, cancel := timeouts.ForCreateUpdate(meta.(*clients.Client).StopContext, d)
	defer cancel()

	domainServiceId, err := parse.DomainServiceID(d.Get("domain_service_id").(string))
	if err != nil {
		return err
	}
	if domainServiceId == nil {
		return fmt.Errorf("parsing ID for Domain Service Replica Set")
	}

	// this is the location of the replica set, not to be confused with the location of the domain service parent resource
	loc := location.Normalize(d.Get("location").(string))

	locks.ByName(domainServiceId.Name, DomainServiceResourceName)
	defer locks.UnlockByName(domainServiceId.Name, DomainServiceResourceName)

	domainService, err := client.Get(ctx, domainServiceId.ResourceGroup, domainServiceId.Name)
	if err != nil {
		if utils.ResponseWasNotFound(domainService.Response) {
			return fmt.Errorf("could not find %s: %s", domainServiceId, err)
		}
		return fmt.Errorf("reading %s: %s", domainServiceId, err)
	}

	if domainService.DomainServiceProperties.ReplicaSets == nil || len(*domainService.DomainServiceProperties.ReplicaSets) == 0 {
		return fmt.Errorf("reading %s: returned with missing replica set information, expected at least 1 replica set: %s", domainServiceId, err)
	}

	replicaSets := *domainService.DomainServiceProperties.ReplicaSets

	for _, r := range replicaSets {
		if r.ReplicaSetID == nil {
			return fmt.Errorf("reading %s: a replica set was returned with a missing replicaSetId", domainServiceId)
		}
		if r.Location == nil {
			return fmt.Errorf("reading %s: a replica set was returned with missing location", domainServiceId)
		}

		if location.Normalize(*r.Location) == loc {
			// generate an ID here since we only know it once we know the ReplicaSetId
			id := parse.NewDomainServiceReplicaSetID(domainServiceId.SubscriptionId, domainServiceId.ResourceGroup, domainServiceId.Name, *r.ReplicaSetID)
			return tf.ImportAsExistsError("azurerm_active_directory_domain_service_replica_set", id.ID())
		}
	}

	replicaSets = append(replicaSets, aad.ReplicaSet{
		Location: &loc,
		SubnetID: utils.String(d.Get("subnet_id").(string)),
	})

	domainService.DomainServiceProperties.ReplicaSets = &replicaSets

	future, err := client.CreateOrUpdate(ctx, domainServiceId.ResourceGroup, domainServiceId.Name, domainService)
	if err != nil {
		return fmt.Errorf("creating/updating Replica Sets for %s: %+v", domainServiceId, err)
	}
	if err = future.WaitForCompletionRef(ctx, client.Client); err != nil {
		return fmt.Errorf("waiting for Replica Sets for %s: %+v", domainServiceId, err)
	}

	// we need to retrieve the domain service again to find our the replica set ID
	domainService, err = client.Get(ctx, domainServiceId.ResourceGroup, domainServiceId.Name)
	if err != nil {
		if utils.ResponseWasNotFound(domainService.Response) {
			return fmt.Errorf("could not find %s: %s", domainServiceId, err)
		}
		return fmt.Errorf("reading %s: %s", domainServiceId, err)
	}

	if domainService.DomainServiceProperties.ReplicaSets == nil || len(*domainService.DomainServiceProperties.ReplicaSets) == 0 {
		return fmt.Errorf("reading %s: returned with missing replica set information, expected at least 1 replica set: %s", domainServiceId, err)
	}

	var id parse.DomainServiceReplicaSetId
	for _, r := range *domainService.DomainServiceProperties.ReplicaSets {
		if r.ReplicaSetID == nil {
			return fmt.Errorf("reading %s: a replica set was returned with a missing replicaSetId", domainServiceId)
		}
		if r.Location == nil {
			return fmt.Errorf("reading %s: a replica set was returned with missing location", domainServiceId)
		}

		if location.Normalize(*r.Location) == loc {
			// we found it!
			id = parse.NewDomainServiceReplicaSetID(domainServiceId.SubscriptionId, domainServiceId.ResourceGroup, domainServiceId.Name, *r.ReplicaSetID)
		}
	}

	// Wait for all replica sets to become available with two domain controllers each before proceeding
	timeout, _ := ctx.Deadline()
	stateConf := &resource.StateChangeConf{
		Pending:      []string{"pending"},
		Target:       []string{"available"},
		Refresh:      domainServiceControllerRefreshFunc(ctx, client, *domainServiceId, false),
		Delay:        1 * time.Minute,
		PollInterval: 1 * time.Minute,
		Timeout:      time.Until(timeout),
	}

	if _, err := stateConf.WaitForState(); err != nil {
		return fmt.Errorf("waiting for both domain controllers to become available in all replica sets for %s: %+v", domainServiceId, err)
	}

	d.SetId(id.ID())

	return resourceActiveDirectoryDomainServiceReplicaSetRead(d, meta)
}

func resourceActiveDirectoryDomainServiceReplicaSetRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).DomainServices.DomainServicesClient
	ctx, cancel := timeouts.ForRead(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := parse.DomainServiceReplicaSetID(d.Id())
	if err != nil {
		return err
	}

	domainService, err := client.Get(ctx, id.ResourceGroup, id.DomainServiceName)
	if err != nil {
		if utils.ResponseWasNotFound(domainService.Response) {
			d.SetId("")
			return nil
		}
		return err
	}

	if domainService.DomainServiceProperties.ReplicaSets == nil || len(*domainService.DomainServiceProperties.ReplicaSets) == 0 {
		return fmt.Errorf("reading %s: domain service returned with missing replica set information, expected at least 1 replica set: %s", id, err)
	}

	replicaSets := *domainService.DomainServiceProperties.ReplicaSets

	for _, r := range replicaSets {
		if r.ReplicaSetID == nil {
			return fmt.Errorf("reading %s: a replica set was returned with a missing replicaSetId", id)
		}

		if *r.ReplicaSetID == id.ReplicaSetName {
			d.Set("domain_controller_ip_addresses", r.DomainControllerIPAddress)
			d.Set("external_access_ip_address", r.ExternalAccessIPAddress)
			d.Set("location", location.NormalizeNilable(r.Location))
			d.Set("service_status", r.ServiceStatus)
			d.Set("subnet_id", r.SubnetID)
		}
	}

	return nil
}

func resourceActiveDirectoryDomainServiceReplicaSetDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).DomainServices.DomainServicesClient
	ctx, cancel := timeouts.ForDelete(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := parse.DomainServiceReplicaSetID(d.Id())
	if err != nil {
		return err
	}

	domainService, err := client.Get(ctx, id.ResourceGroup, id.DomainServiceName)
	if err != nil {
		if utils.ResponseWasNotFound(domainService.Response) {
			return fmt.Errorf("deleting %s: domain service was not found: %s", id, err)
		}
		return err
	}

	if domainService.DomainServiceProperties.ReplicaSets == nil || len(*domainService.DomainServiceProperties.ReplicaSets) == 0 {
		return fmt.Errorf("deleting %s: domain service returned with missing replica set information, expected at least 1 replica set: %s", id, err)
	}

	replicaSets := *domainService.DomainServiceProperties.ReplicaSets

	newReplicaSets := make([]aad.ReplicaSet, 0)
	for _, r := range replicaSets {
		if r.ReplicaSetID == nil {
			return fmt.Errorf("deleting %s: a replica set was returned with a missing replicaSetId", id)
		}

		if *r.ReplicaSetID == id.ReplicaSetName {
			continue
		}

		newReplicaSets = append(newReplicaSets, r)
	}

	properties := aad.DomainService{
		DomainServiceProperties: &aad.DomainServiceProperties{
			ReplicaSets: &replicaSets,
		},
	}

	future, err := client.CreateOrUpdate(ctx, id.ResourceGroup, id.DomainServiceName, properties)
	if err != nil {
		return fmt.Errorf("deleting %s: %+v", id, err)
	}
	if err = future.WaitForCompletionRef(ctx, client.Client); err != nil {
		return fmt.Errorf("waiting for deletion of %s: %+v", id, err)
	}

	// Wait for all replica sets to become available with two domain controllers each before proceeding
	domainServiceId := parse.NewDomainServiceID(id.SubscriptionId, id.ResourceGroup, id.DomainServiceName)
	timeout, _ := ctx.Deadline()
	stateConf := &resource.StateChangeConf{
		Pending:      []string{"pending"},
		Target:       []string{"available"},
		Refresh:      domainServiceControllerRefreshFunc(ctx, client, domainServiceId, true),
		Delay:        1 * time.Minute,
		PollInterval: 1 * time.Minute,
		Timeout:      time.Until(timeout),
	}

	if _, err := stateConf.WaitForState(); err != nil {
		return fmt.Errorf("waiting for replica sets to finish updating for %s: %+v", domainServiceId, err)
	}

	return nil
}
