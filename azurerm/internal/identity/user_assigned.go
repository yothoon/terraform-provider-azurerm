package identity

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	msiParse "github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/msi/parse"
)

var _ Identity = UserAssigned{}

type UserAssigned struct{}

func (u UserAssigned) Expand(input []interface{}) (*ExpandedConfig, error) {
	if len(input) == 0 || input[0] == nil {
		return &ExpandedConfig{
			Type: none,
		}, nil
	}

	item := input[0].(map[string]interface{})

	identityIds := make([]string, 0)
	for _, id := range item["identity_ids"].([]string) {
		identityIds = append(identityIds, id)
	}

	return &ExpandedConfig{
		Type:                    userAssigned,
		UserAssignedIdentityIds: &identityIds,
	}, nil
}

func (u UserAssigned) Flatten(input *ExpandedConfig) (*[]interface{}, error) {
	if input == nil || input.Type == none {
		return &[]interface{}{}, nil
	}

	identityIds := make([]string, 0)
	if input.UserAssignedIdentityIds != nil {
		for _, key := range *input.UserAssignedIdentityIds {
			parsedId, err := msiParse.UserAssignedIdentityID(key)
			if err != nil {
				return nil, err
			}
			identityIds = append(identityIds, parsedId.ID())
		}
	}

	return &[]interface{}{
		map[string]interface{}{
			"type":         input.Type,
			"identity_ids": identityIds,
		},
	}, nil
}

func (u UserAssigned) Schema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"type": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.StringInSlice([]string{
						userAssigned,
					}, false),
				},
				"identity_ids": {
					Type:     schema.TypeList,
					Required: true,
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: validation.NoZeroValues,
					},
				},
			},
		},
	}
}

func (u UserAssigned) SchemaDataSource() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"type": {
					Type:     schema.TypeString,
					Computed: true,
				},
				"identity_ids": {
					Type:     schema.TypeList,
					Computed: true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
			},
		},
	}
}
