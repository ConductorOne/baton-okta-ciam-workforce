package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	oktav5 "github.com/okta/okta-sdk-golang/v5/okta"
	"go.uber.org/zap"
)

const roleMembership = "assigned"

// StandardRole represents a standard Okta role type.
type StandardRole struct {
	Type  string
	Label string
}

// Standard roles that can be assigned at the org-wide scope
// See: https://developer.okta.com/docs/reference/api/roles/#role-types
var standardRoleTypes = []StandardRole{
	{Type: "API_ACCESS_MANAGEMENT_ADMIN", Label: "API Access Management Administrator"},
	{Type: "MOBILE_ADMIN", Label: "Mobile Administrator"},
	{Type: "ORG_ADMIN", Label: "Organizational Administrator"},
	{Type: "READ_ONLY_ADMIN", Label: "Read-Only Administrator"},
	{Type: "REPORT_ADMIN", Label: "Report Administrator"},
	{Type: "SUPER_ADMIN", Label: "Super Administrator"},
	{Type: "USER_ADMIN", Label: "Group Administrator"},
	{Type: "HELP_DESK_ADMIN", Label: "Help Desk Administrator"},
	{Type: "APP_ADMIN", Label: "Application Administrator"},
	{Type: "GROUP_MEMBERSHIP_ADMIN", Label: "Group Membership Administrator"},
}

type roleBuilder struct {
	connector *Connector
}

// newRoleBuilder creates a new role builder.
func newRoleBuilder(connector *Connector) *roleBuilder {
	return &roleBuilder{
		connector: connector,
	}
}

// ResourceType returns the role resource type.
func (r *roleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return roleResourceType
}

// List returns all standard roles using the IAM API.
func (r *roleBuilder) List(
	ctx context.Context,
	parentResourceID *v2.ResourceId,
	pToken *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	var rv []*v2.Resource

	// Return all standard role types
	for _, role := range standardRoleTypes {
		roleResource, err := r.roleResource(ctx, &role)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to create role resource: %w", err)
		}
		rv = append(rv, roleResource)
	}

	return rv, "", nil, nil
}

// Entitlements returns the "assigned" entitlement for a role.
func (r *roleBuilder) Entitlements(
	ctx context.Context,
	res *v2.Resource,
	_ *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	role := r.findRoleByType(res.Id.GetResource())
	roleLabel := res.DisplayName
	if role != nil {
		roleLabel = role.Label
	}

	en := entitlement.NewAssignmentEntitlement(
		res,
		roleMembership,
		entitlement.WithDisplayName(fmt.Sprintf("%s Role Member", roleLabel)),
		entitlement.WithDescription(fmt.Sprintf("Has the %s role in Okta", roleLabel)),
		entitlement.WithGrantableTo(userResourceType),
	)

	rv = append(rv, en)
	return rv, "", nil, nil
}

// Grants returns all users who have been assigned this role using the IAM API.
func (r *roleBuilder) Grants(
	ctx context.Context,
	res *v2.Resource,
	pToken *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	bag, pageToken, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: roleResourceType.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to parse page token: %w", err)
	}

	var rv []*v2.Grant

	// Default page size if not specified
	pageSize := pToken.Size
	if pageSize == 0 {
		pageSize = 50
	}

	// List all users with role assignments using the IAM API
	req := r.connector.client.RoleAssignmentAPI.ListUsersWithRoleAssignments(ctx).
		Limit(toInt32(pageSize))

	if pageToken != "" {
		req = req.After(pageToken)
	}

	usersWithRoles, resp, err := req.Execute()
	if err != nil {
		return nil, "", nil, wrapError(handleOktaError(resp, err), "okta-ciam-v2: failed to list users with role assignments")
	}
	defer func() { _ = resp.Body.Close() }()

	// Extract rate limit annotations from the response
	annos := extractRateLimitAnnotations(resp)

	// Get next page token using SDK's built-in pagination helper
	nextPage := resp.NextPage()

	roleType := res.Id.GetResource()

	// usersWithRoles is a pointer to RoleAssignedUsers with a Value field
	if usersWithRoles == nil || usersWithRoles.Value == nil {
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

	for _, userAssignment := range usersWithRoles.Value {
		if userAssignment.Id == nil {
			continue
		}

		userID := *userAssignment.Id

		// Check if this user has the specific role we're looking for
		userRoles, roleResp, err := r.connector.client.RoleAssignmentAPI.ListAssignedRolesForUser(ctx, userID).Execute()
		if err != nil {
			// Log warning but continue processing other users
			l.Warn("okta-ciam-v2: failed to list roles for user", zap.String("user_id", userID), zap.Error(handleOktaError(roleResp, err)))
			continue
		}
		_ = roleResp.Body.Close()

		// Check if this user has the role we're interested in
		// userRoles is []Role, not a struct with a Roles field
		hasRole := false
		for _, userRole := range userRoles {
			if userRole.Type != nil && *userRole.Type == roleType {
				hasRole = true
				break
			}
		}

		if hasRole {
			rv = append(rv, r.roleGrant(userID, res))
		}
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

// roleResource converts a StandardRole to a Baton resource.
func (r *roleBuilder) roleResource(ctx context.Context, role *StandardRole) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"id":    role.Type,
		"label": role.Label,
		"type":  role.Type,
	}

	return resource.NewRoleResource(
		role.Label,
		roleResourceType,
		role.Type, // Use type as the resource ID for standard roles
		[]resource.RoleTraitOption{resource.WithRoleProfile(profile)},
	)
}

// roleGrant creates a grant for a user having a role.
func (r *roleBuilder) roleGrant(userID string, roleResource *v2.Resource) *v2.Grant {
	userRes := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     userID,
		},
	}

	return grant.NewGrant(roleResource, roleMembership, userRes)
}

// findRoleByType finds a standard role by its type.
func (r *roleBuilder) findRoleByType(roleType string) *StandardRole {
	for i, role := range standardRoleTypes {
		if role.Type == roleType {
			return &standardRoleTypes[i]
		}
	}
	return nil
}

// Grant assigns a role to a user.
func (r *roleBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"okta-ciam-v2: only users can be granted role membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-ciam-v2: only users can be granted role membership")
	}

	roleType := entitlement.Resource.Id.Resource
	userID := principal.Id.Resource

	// Create the role assignment request
	assignRoleRequest := oktav5.NewAssignRoleRequest()
	assignRoleRequest.SetType(roleType)

	_, resp, err := r.connector.client.RoleAssignmentAPI.AssignRoleToUser(ctx, userID).AssignRoleRequest(*assignRoleRequest).Execute()
	if err != nil {
		return nil, wrapError(handleOktaError(resp, err), "okta-ciam-v2: failed to assign role to user")
	}
	defer func() { _ = resp.Body.Close() }()

	return nil, nil
}

// Revoke unassigns a role from a user.
func (r *roleBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	entitlement := grant.Entitlement
	principal := grant.Principal

	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"okta-ciam-v2: only users can have role membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-ciam-v2: only users can have role membership revoked")
	}

	roleType := entitlement.Resource.Id.Resource
	userID := principal.Id.Resource

	// Get the user's assigned roles to find the role ID
	userRoles, roleResp, err := r.connector.client.RoleAssignmentAPI.ListAssignedRolesForUser(ctx, userID).Execute()
	if err != nil {
		return nil, wrapError(handleOktaError(roleResp, err), "okta-ciam-v2: failed to list roles for user")
	}
	_ = roleResp.Body.Close()

	// Find the role ID for this role type
	var roleID string
	for _, userRole := range userRoles {
		if userRole.Type != nil && *userRole.Type == roleType {
			if userRole.Id != nil {
				roleID = *userRole.Id
				break
			}
		}
	}

	if roleID == "" {
		l.Warn("okta-ciam-v2: role not found for user",
			zap.String("user_id", userID),
			zap.String("role_type", roleType),
		)
		return nil, fmt.Errorf("okta-ciam-v2: role not found for user")
	}

	resp, err := r.connector.client.RoleAssignmentAPI.UnassignRoleFromUser(ctx, userID, roleID).Execute()
	if err != nil {
		return nil, wrapError(handleOktaError(resp, err), "okta-ciam-v2: failed to unassign role from user")
	}
	defer func() { _ = resp.Body.Close() }()

	return nil, nil
}
