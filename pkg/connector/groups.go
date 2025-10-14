package connector

import (
	"context"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	oktav5 "github.com/okta/okta-sdk-golang/v5/okta"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
)

const groupMembership = "member"

type groupBuilder struct {
	connector *Connector
}

// newGroupBuilder creates a new group builder.
func newGroupBuilder(connector *Connector) *groupBuilder {
	return &groupBuilder{
		connector: connector,
	}
}

// ResourceType returns the group resource type.
func (g *groupBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return groupResourceType
}

// List returns all groups filtered by name.
func (g *groupBuilder) List(
	ctx context.Context,
	parentResourceID *v2.ResourceId,
	pToken *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, pageToken, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: groupResourceType.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource

	// Default page size if not specified
	pageSize := pToken.Size
	if pageSize == 0 {
		pageSize = 50
	}

	// List groups
	req := g.connector.client.GroupAPI.ListGroups(ctx).
		Limit(toInt32(pageSize))

	if pageToken != "" {
		req = req.After(pageToken)
	}

	groups, resp, err := req.Execute()
	if err != nil {
		return nil, "", nil, wrapError(handleOktaError(resp, err), "okta-ciam-v2: failed to list groups")
	}
	defer func() { _ = resp.Body.Close() }()

	// Extract rate limit annotations from the response
	annos := extractRateLimitAnnotations(resp)

	// Get next page token using SDK's built-in pagination helper
	nextPage := resp.NextPage()

	for _, group := range groups {
		// Apply group name filter
		if !g.shouldIncludeGroup(group) {
			continue
		}

		groupResource, err := g.groupResource(ctx, &group)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to create group resource: %w", err)
		}

		rv = append(rv, groupResource)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to set next page: %w", err)
	}

	bagToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to marshal page token: %w", err)
	}

	return rv, bagToken, annos, nil
}

// Entitlements returns the "member" entitlement for a group.
func (g *groupBuilder) Entitlements(
	ctx context.Context,
	res *v2.Resource,
	_ *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	en := entitlement.NewAssignmentEntitlement(
		res,
		groupMembership,
		entitlement.WithGrantableTo(userResourceType),
		entitlement.WithDisplayName(fmt.Sprintf("%s Group Member", res.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Member of %s group in Okta", res.DisplayName)),
	)

	rv = append(rv, en)
	return rv, "", nil, nil
}

// Grants returns all users who are members of this group.
func (g *groupBuilder) Grants(
	ctx context.Context,
	res *v2.Resource,
	pToken *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	bag, pageToken, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: groupResourceType.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to parse page token: %w", err)
	}

	var rv []*v2.Grant
	groupID := res.Id.GetResource()

	// Default page size if not specified
	pageSize := pToken.Size
	if pageSize == 0 {
		pageSize = 50
	}

	// List group members
	req := g.connector.client.GroupAPI.ListGroupUsers(ctx, groupID).
		Limit(toInt32(pageSize))

	if pageToken != "" {
		req = req.After(pageToken)
	}

	users, resp, err := req.Execute()
	if err != nil {
		return nil, "", nil, wrapError(handleOktaError(resp, err), "okta-ciam-v2: failed to list group users")
	}
	defer func() { _ = resp.Body.Close() }()

	// Extract rate limit annotations from the response
	annos := extractRateLimitAnnotations(resp)

	// Get next page token using SDK's built-in pagination helper
	nextPage := resp.NextPage()

	// Filter users by email domain
	for _, user := range users {
		// Check if user should be included based on email filtering
		// GroupMember has all the same fields as User, so we can check directly
		if !g.shouldIncludeGroupMember(user) {
			continue
		}

		userID := ""
		if user.Id != nil {
			userID = *user.Id
		}

		rv = append(rv, g.groupGrant(res, userID))
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to set next page: %w", err)
	}

	bagToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to marshal page token: %w", err)
	}

	return rv, bagToken, annos, nil
}

// shouldIncludeGroupMember checks if a group member should be included based on email filtering.
func (g *groupBuilder) shouldIncludeGroupMember(member oktav5.GroupMember) bool {
	// If no email filtering is configured, include all users
	if len(g.connector.emailDomains) == 0 {
		return true
	}

	// Extract emails from the GroupMember
	var userEmails []string

	if member.Profile != nil {
		// Primary email
		if member.Profile.Email != nil {
			userEmails = append(userEmails, *member.Profile.Email)
		}

		// Secondary email
		if secondEmail := member.Profile.SecondEmail.Get(); secondEmail != nil {
			userEmails = append(userEmails, *secondEmail)
		}

		// Login field
		if member.Profile.Login != nil {
			userEmails = append(userEmails, *member.Profile.Login)
		}
	}

	// Check if any email matches the domain filter
	for _, filter := range g.connector.emailDomains {
		for _, email := range userEmails {
			if strings.HasSuffix(strings.ToLower(email), "@"+filter) {
				return true
			}
		}
	}

	return false
}

// shouldIncludeGroup determines if a group should be included based on the group name filter.
func (g *groupBuilder) shouldIncludeGroup(group oktav5.Group) bool {
	// If no filter is configured, include all groups
	if g.connector.groupNameFilter == "" {
		return true
	}

	// Get the group name using the proper v5 SDK method
	groupName := ""
	if group.Profile != nil {
		if group.Profile.Name != nil {
			groupName = strings.ToLower(*group.Profile.Name)
		}
	}

	// Check if the group name contains the filter string (case-insensitive)
	return strings.Contains(groupName, g.connector.groupNameFilter)
}

// groupResource converts an Okta group to a Baton resource.
func (g *groupBuilder) groupResource(ctx context.Context, group *oktav5.Group) (*v2.Resource, error) {
	groupName := ""
	groupDescription := ""

	if group.Profile != nil {
		if group.Profile.Name != nil {
			groupName = *group.Profile.Name
		}
		if group.Profile.Description != nil {
			groupDescription = *group.Profile.Description
		}
	}

	groupID := ""
	if group.Id != nil {
		groupID = *group.Id
	}

	profileMap := map[string]interface{}{
		"name":        groupName,
		"description": groupDescription,
	}

	profile, err := structpb.NewStruct(profileMap)
	if err != nil {
		return nil, fmt.Errorf("okta-ciam-v2: failed to construct group profile: %w", err)
	}

	groupTrait := &v2.GroupTrait{
		Profile: profile,
	}

	var annos annotations.Annotations
	annos.Update(groupTrait)

	return &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: groupResourceType.Id,
			Resource:     groupID,
		},
		DisplayName: groupName,
		Annotations: annos,
	}, nil
}

// groupGrant creates a grant for a user being a member of a group.
func (g *groupBuilder) groupGrant(groupResource *v2.Resource, userID string) *v2.Grant {
	userRes := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     userID,
		},
	}

	return grant.NewGrant(groupResource, groupMembership, userRes)
}

// Grant adds a user to a group.
func (g *groupBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"okta-ciam-v2: only users can be granted group membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-ciam-v2: only users can be granted group membership")
	}

	groupID := entitlement.Resource.Id.Resource
	userID := principal.Id.Resource

	resp, err := g.connector.client.GroupAPI.AssignUserToGroup(ctx, groupID, userID).Execute()
	if err != nil {
		return nil, wrapError(handleOktaError(resp, err), "okta-ciam-v2: failed to add user to group")
	}
	defer func() { _ = resp.Body.Close() }()

	return nil, nil
}

// Revoke removes a user from a group.
func (g *groupBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	entitlement := grant.Entitlement
	principal := grant.Principal

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"okta-ciam-v2: only users can have group membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-ciam-v2: only users can have group membership revoked")
	}

	groupID := entitlement.Resource.Id.Resource
	userID := principal.Id.Resource

	resp, err := g.connector.client.GroupAPI.UnassignUserFromGroup(ctx, groupID, userID).Execute()
	if err != nil {
		return nil, wrapError(handleOktaError(resp, err), "okta-ciam-v2: failed to remove user from group")
	}
	defer func() { _ = resp.Body.Close() }()

	return nil, nil
}
