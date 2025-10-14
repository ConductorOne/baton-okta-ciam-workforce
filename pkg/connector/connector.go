package connector

import (
	"context"
	"fmt"
	"net/http"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	oktav5 "github.com/okta/okta-sdk-golang/v5/okta"
)

type Connector struct {
	client          *oktav5.APIClient
	config          *oktav5.Configuration
	domain          string
	apiToken        string
	emailDomains    []string
	groupNameFilter string
}

// New creates a new Okta CIAM v2 connector instance.
func New(ctx context.Context, domain, apiToken string, emailDomains []string, groupNameFilter string) (*Connector, error) {
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(false, nil))
	if err != nil {
		return nil, fmt.Errorf("okta-ciam-v2: failed to create HTTP client: %w", err)
	}

	if apiToken == "" || domain == "" {
		return nil, fmt.Errorf("okta-ciam-v2: API token and domain are required")
	}

	if len(emailDomains) == 0 {
		return nil, fmt.Errorf("okta-ciam-v2: at least one email domain is required")
	}

	oktaConfig, err := oktav5.NewConfiguration(
		oktav5.WithOrgUrl(fmt.Sprintf("https://%s", domain)),
		oktav5.WithToken(apiToken),
		oktav5.WithHttpClientPtr(httpClient),
		oktav5.WithCache(true),
		oktav5.WithCacheTti(300),  // 5 minutes
		oktav5.WithCacheTtl(3600), // 1 hour
		oktav5.WithRateLimitMaxRetries(3),
	)
	if err != nil {
		return nil, fmt.Errorf("okta-ciam-v2: failed to create Okta configuration: %w", err)
	}

	client := oktav5.NewAPIClient(oktaConfig)

	return &Connector{
		client:          client,
		config:          oktaConfig,
		domain:          domain,
		apiToken:        apiToken,
		emailDomains:    emailDomains,
		groupNameFilter: groupNameFilter,
	}, nil
}

// Metadata returns metadata about the connector.
func (c *Connector) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "Okta CIAM v2",
		Description: "The Okta CIAM v2 connector syncs users, groups, and roles from Okta with email domain and group name filtering support",
	}, nil
}

// Validate validates the connector configuration by making a test API call.
func (c *Connector) Validate(ctx context.Context) (annotations.Annotations, error) {
	// Test the API token by fetching org settings
	_, resp, err := c.client.OrgSettingAPI.GetOrgSettings(ctx).Execute()
	if err != nil {
		return nil, wrapError(handleOktaError(resp, err), "okta-ciam-v2: failed to validate API token")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("okta-ciam-v2: validation returned non-200 status: %d", resp.StatusCode)
	}

	return nil, nil
}

// ResourceSyncers returns the list of resource syncers for this connector.
func (c *Connector) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		newUserBuilder(c),
		newRoleBuilder(c),
		newCustomRoleBuilder(c),
		newGroupBuilder(c),
	}
}

// parsePageToken parses a page token into a pagination bag and page string.
func parsePageToken(pToken *pagination.Token, resourceID *v2.ResourceId) (*pagination.Bag, string, error) {
	bag := &pagination.Bag{}

	// Check if pToken is nil or has an empty token
	if pToken != nil && pToken.Token != "" {
		err := bag.Unmarshal(pToken.Token)
		if err != nil {
			return nil, "", err
		}
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceID.ResourceType,
			ResourceID:     resourceID.Resource,
		})
	}

	return bag, bag.PageToken(), nil
}

// getPageSize safely extracts the page size from a pagination token, returning a default if nil or 0.
func getPageSize(pToken *pagination.Token, defaultSize int) int {
	if pToken == nil {
		return defaultSize
	}
	if pToken.Size == 0 {
		return defaultSize
	}
	return pToken.Size
}
