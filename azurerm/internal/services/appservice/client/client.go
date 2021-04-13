package client

import (
	"github.com/Azure/azure-sdk-for-go/services/web/mgmt/2020-06-01/web"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/common"
)

type Client struct {
	WebAppsClient     *web.AppsClient
	ServicePlanClient *web.AppServicePlansClient
}

func NewClient(o *common.ClientOptions) *Client {
	appServiceClient := web.NewAppsClientWithBaseURI(o.ResourceManagerEndpoint, o.SubscriptionId)
	o.ConfigureClient(&appServiceClient.Client, o.ResourceManagerAuthorizer)

	servicePlanClient := web.NewAppServicePlansClientWithBaseURI(o.ResourceManagerEndpoint, o.SubscriptionId)
	o.ConfigureClient(&servicePlanClient.Client, o.ResourceManagerAuthorizer)

	return &Client{
		WebAppsClient:     &appServiceClient,
		ServicePlanClient: &servicePlanClient,
	}
}
