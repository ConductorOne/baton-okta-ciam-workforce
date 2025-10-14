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
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	oktav5 "github.com/okta/okta-sdk-golang/v5/okta"
	"go.uber.org/zap"
)

const customRoleMembership = "assigned"

type customRoleBuilder struct {
	connector *Connector
}

// newCustomRoleBuilder creates a new custom role builder.
func newCustomRoleBuilder(connector *Connector) *customRoleBuilder {
	return &customRoleBuilder{
		connector: connector,
	}
}

// ResourceType returns the custom role resource type.
func (r *customRoleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return customRoleResourceType
}

// List returns all custom roles using the IAM API.
func (r *customRoleBuilder) List(
	ctx context.Context,
	parentResourceID *v2.ResourceId,
	pToken *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	logger := ctxzap.Extract(ctx)
	logger.Debug("okta-ciam-v2: listing custom roles")

	bag, pageToken, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: customRoleResourceType.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource

	// Query the IAM API to list all roles
	req := r.connector.client.RoleAPI.ListRoles(ctx)
	if pageToken != "" {
		req = req.After(pageToken)
	}

	iamRoles, resp, err := req.Execute()
	if err != nil {
		return nil, "", nil, wrapError(handleOktaError(resp, err), "okta-ciam-v2: failed to list IAM roles")
	}
	defer func() { _ = resp.Body.Close() }()

	// Extract rate limit annotations from the response
	annos := extractRateLimitAnnotations(resp)

	// Get next page token from Links
	nextPage := ""
	if iamRoles.Links != nil && iamRoles.Links.Next != nil {
		nextPageURL := iamRoles.Links.Next.Href
		if nextPageURL != "" {
			// Extract the "after" parameter from the URL
			nextPage = extractAfterParam(nextPageURL)
		}
	}

	// Filter for custom roles (roles that are not in the standard list)
	standardRoleTypeSet := make(map[string]bool)
	for _, stdRole := range standardRoleTypes {
		standardRoleTypeSet[stdRole.Type] = true
	}

	if iamRoles.Roles != nil {
		for _, role := range iamRoles.Roles {
			// Skip standard roles
			if role.Id != nil {
				roleID := *role.Id
				// Custom roles have IDs that start with "cr" or are not in the standard list
				if !standardRoleTypeSet[roleID] {
					roleResource, err := r.customRoleResource(ctx, &role)
					if err != nil {
						return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to create custom role resource: %w", err)
					}
					rv = append(rv, roleResource)
				}
			}
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

// extractAfterParam extracts the "after" parameter from a URL.
func extractAfterParam(url string) string {
	parts := strings.Split(url, "after=")
	if len(parts) > 1 {
		return strings.Split(parts[1], "&")[0]
	}
	return ""
}

// Entitlements returns the "assigned" entitlement for a custom role.
func (r *customRoleBuilder) Entitlements(
	ctx context.Context,
	res *v2.Resource,
	_ *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	roleLabel := res.DisplayName

	en := entitlement.NewAssignmentEntitlement(
		res,
		customRoleMembership,
		entitlement.WithDisplayName(fmt.Sprintf("%s Custom Role Member", roleLabel)),
		entitlement.WithDescription(fmt.Sprintf("Has the %s custom role in Okta", roleLabel)),
		entitlement.WithGrantableTo(userResourceType),
	)

	rv = append(rv, en)
	return rv, "", nil, nil
}

// Grants returns all users who have been assigned this custom role using the IAM API.
func (r *customRoleBuilder) Grants(
	ctx context.Context,
	res *v2.Resource,
	pToken *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	logger := ctxzap.Extract(ctx)
	logger.Debug("okta-ciam-v2: listing custom role grants", zap.String("role_id", res.Id.Resource))

	bag, pageToken, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: customRoleResourceType.Id})
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

	customRoleID := res.Id.GetResource()

	// usersWithRoles is a pointer to RoleAssignedUsers with a Value field
	if usersWithRoles == nil || usersWithRoles.Value == nil {
		logger.Debug("okta-ciam-v2: no users with role assignments found")
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

	logger.Debug("okta-ciam-v2: found users with role assignments", zap.Int("count", len(usersWithRoles.Value)))

	for _, userAssignment := range usersWithRoles.Value {
		if userAssignment.Id == nil {
			continue
		}

		userID := *userAssignment.Id

		// Check if this user has the specific custom role we're looking for
		userRoles, roleResp, err := r.connector.client.RoleAssignmentAPI.ListAssignedRolesForUser(ctx, userID).Execute()
		if err != nil {
			// Log warning but continue processing other users
			logger.Warn("okta-ciam-v2: failed to list roles for user", zap.String("user_id", userID), zap.Error(handleOktaError(roleResp, err)))
			continue
		}
		_ = roleResp.Body.Close()

		logger.Debug("okta-ciam-v2: found roles for user",
			zap.String("user_id", userID),
			zap.Int("role_count", len(userRoles)),
			zap.String("looking_for_role_id", customRoleID))

		// Check if this user has the custom role we're interested in
		hasRole := false
		for _, userRole := range userRoles {
			roleID := "nil"
			roleType := "nil"
			if userRole.Id != nil {
				roleID = *userRole.Id
			}
			if userRole.Type != nil {
				roleType = *userRole.Type
			}
			logger.Debug("okta-ciam-v2: checking user role",
				zap.String("user_id", userID),
				zap.String("role_id", roleID),
				zap.String("role_type", roleType))

			// For custom roles, match on Type field (not Id which is the assignment ID)
			if userRole.Type != nil && *userRole.Type == customRoleID {
				hasRole = true
				break
			}
		}

		if hasRole {
			logger.Debug("okta-ciam-v2: user has custom role, adding grant",
				zap.String("user_id", userID),
				zap.String("custom_role_id", customRoleID))
			rv = append(rv, r.customRoleGrant(userID, res))
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

// customRoleResource converts an IamRole to a Baton custom role resource.
func (r *customRoleBuilder) customRoleResource(ctx context.Context, role *oktav5.IamRole) (*v2.Resource, error) {
	roleID := ""
	if role.Id != nil {
		roleID = *role.Id
	}

	roleLabel := role.Label
	roleDescription := role.Description

	profile := map[string]interface{}{
		"id":          roleID,
		"label":       roleLabel,
		"description": roleDescription,
	}

	return resource.NewRoleResource(
		roleLabel,
		customRoleResourceType,
		roleID,
		[]resource.RoleTraitOption{resource.WithRoleProfile(profile)},
	)
}

// customRoleGrant creates a grant for a user having a custom role.
func (r *customRoleBuilder) customRoleGrant(userID string, roleResource *v2.Resource) *v2.Grant {
	userRes := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     userID,
		},
	}

	return grant.NewGrant(roleResource, customRoleMembership, userRes)
}

// Grant assigns a custom role to a user.
func (r *customRoleBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	logger := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != userResourceType.Id {
		logger.Warn(
			"okta-ciam-v2: only users can be granted custom role membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-ciam-v2: only users can be granted custom role membership")
	}

	customRoleID := entitlement.Resource.Id.Resource
	userID := principal.Id.Resource

	// Create the role assignment request for a custom role
	assignRoleRequest := oktav5.NewAssignRoleRequest()
	assignRoleRequest.SetType(customRoleID)

	_, resp, err := r.connector.client.RoleAssignmentAPI.AssignRoleToUser(ctx, userID).AssignRoleRequest(*assignRoleRequest).Execute()
	if err != nil {
		return nil, wrapError(handleOktaError(resp, err), "okta-ciam-v2: failed to assign custom role to user")
	}
	defer func() { _ = resp.Body.Close() }()

	logger.Info("okta-ciam-v2: custom role assigned to user",
		zap.String("user_id", userID),
		zap.String("custom_role_id", customRoleID),
		zap.String("status", resp.Status),
	)

	return nil, nil
}

// Revoke unassigns a custom role from a user.
func (r *customRoleBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	logger := ctxzap.Extract(ctx)

	entitlement := grant.Entitlement
	principal := grant.Principal

	if principal.Id.ResourceType != userResourceType.Id {
		logger.Warn(
			"okta-ciam-v2: only users can have custom role membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-ciam-v2: only users can have custom role membership revoked")
	}

	customRoleID := entitlement.Resource.Id.Resource
	userID := principal.Id.Resource

	// Get the user's assigned roles to find the role ID
	userRoles, roleResp, err := r.connector.client.RoleAssignmentAPI.ListAssignedRolesForUser(ctx, userID).Execute()
	if err != nil {
		return nil, wrapError(handleOktaError(roleResp, err), "okta-ciam-v2: failed to list roles for user")
	}
	_ = roleResp.Body.Close()

	// Find the role assignment ID for this custom role
	var roleAssignmentID string
	for _, userRole := range userRoles {
		// Match on Type field (role ID), but use Id field (assignment ID) to revoke
		if userRole.Type != nil && *userRole.Type == customRoleID {
			if userRole.Id != nil {
				roleAssignmentID = *userRole.Id
			}
			break
		}
	}

	if roleAssignmentID == "" {
		logger.Warn("okta-ciam-v2: custom role not found for user",
			zap.String("user_id", userID),
			zap.String("custom_role_id", customRoleID),
		)
		return nil, fmt.Errorf("okta-ciam-v2: custom role not found for user")
	}

	resp, err := r.connector.client.RoleAssignmentAPI.UnassignRoleFromUser(ctx, userID, roleAssignmentID).Execute()
	if err != nil {
		return nil, wrapError(handleOktaError(resp, err), "okta-ciam-v2: failed to unassign custom role from user")
	}
	defer func() { _ = resp.Body.Close() }()

	logger.Info("okta-ciam-v2: custom role unassigned from user",
		zap.String("user_id", userID),
		zap.String("custom_role_id", customRoleID),
		zap.String("role_assignment_id", roleAssignmentID),
		zap.String("status", resp.Status),
	)

	return nil, nil
}
