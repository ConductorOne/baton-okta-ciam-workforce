package connector

import (
	"context"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	oktav5 "github.com/okta/okta-sdk-golang/v5/okta"
)

const (
	unknownProfileValue       = "unknown"
	userStatusSuspended       = "SUSPENDED"
	userStatusDeprovisioned   = "DEPROVISIONED"
	userStatusActive          = "ACTIVE"
	userStatusLockedOut       = "LOCKED_OUT"
	userStatusPasswordExpired = "PASSWORD_EXPIRED"
	userStatusProvisioned     = "PROVISIONED"
	userStatusRecovery        = "RECOVERY"
	userStatusStaged          = "STAGED"
)

type userBuilder struct {
	connector *Connector
}

// newUserBuilder creates a new user builder.
func newUserBuilder(connector *Connector) *userBuilder {
	return &userBuilder{
		connector: connector,
	}
}

// ResourceType returns the user resource type.
func (u *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return userResourceType
}

// List returns all users filtered by email domain.
func (u *userBuilder) List(
	ctx context.Context,
	parentResourceID *v2.ResourceId,
	pToken *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, pageToken, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: userResourceType.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource

	// Default page size if not specified
	pageSize := pToken.Size
	if pageSize == 0 {
		pageSize = 50
	}

	// List users with the search query "status pr" to get all users including deactivated ones
	req := u.connector.client.UserAPI.ListUsers(ctx).
		Limit(int32(pageSize)).
		Search("status pr")

	if pageToken != "" {
		req = req.After(pageToken)
	}

	users, resp, err := req.Execute()
	if err != nil {
		return nil, "", nil, wrapError(handleOktaError(resp, err), "okta-ciam-v2: failed to list users")
	}
	defer func() { _ = resp.Body.Close() }()

	// Extract rate limit annotations from the response
	annos := extractRateLimitAnnotations(resp)

	// Get next page token using SDK's built-in pagination helper
	nextPage := resp.NextPage()

	for _, user := range users {
		if !u.shouldIncludeUser(user) {
			continue
		}

		userResource, err := u.userResource(ctx, &user)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-ciam-v2: failed to create user resource: %w", err)
		}

		rv = append(rv, userResource)
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

// Entitlements always returns an empty slice for users (users don't have entitlements).
func (u *userBuilder) Entitlements(
	_ context.Context,
	resource *v2.Resource,
	_ *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants always returns an empty slice for users (users don't grant anything).
func (u *userBuilder) Grants(
	ctx context.Context,
	resource *v2.Resource,
	pToken *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// shouldIncludeUser determines if a user should be included based on email domain filtering.
func (u *userBuilder) shouldIncludeUser(user oktav5.User) bool {
	var userEmails []string

	if user.Profile != nil {
		// Extract email from profile using v5 SDK struct fields
		if user.Profile.Email != nil && *user.Profile.Email != "" {
			userEmails = append(userEmails, *user.Profile.Email)
		}

		// Extract secondEmail from profile
		if secondEmail := user.Profile.SecondEmail.Get(); secondEmail != nil && *secondEmail != "" {
			userEmails = append(userEmails, *secondEmail)
		}

		// Extract login if it's an email
		if user.Profile.Login != nil && *user.Profile.Login != "" {
			if strings.Contains(*user.Profile.Login, "@") {
				userEmails = append(userEmails, *user.Profile.Login)
			}
		}
	}

	return u.shouldIncludeUserByEmails(userEmails)
}

// shouldIncludeUserByEmails checks if any of the user's emails match the configured email domains.
func (u *userBuilder) shouldIncludeUserByEmails(userEmails []string) bool {
	for _, filter := range u.connector.emailDomains {
		for _, email := range userEmails {
			if strings.HasSuffix(strings.ToLower(email), "@"+filter) {
				return true
			}
		}
	}
	return false
}

// userResource converts an Okta user to a Baton resource.
func (u *userBuilder) userResource(ctx context.Context, user *oktav5.User) (*v2.Resource, error) {
	// Build a profile map from the UserProfile struct
	profile := map[string]interface{}{}
	if user.Profile != nil {
		// Add all standard fields
		if user.Profile.Email != nil {
			profile["email"] = *user.Profile.Email
		}
		if user.Profile.Login != nil {
			profile["login"] = *user.Profile.Login
		}
		if user.Profile.FirstName.Get() != nil {
			profile["firstName"] = *user.Profile.FirstName.Get()
		}
		if user.Profile.LastName.Get() != nil {
			profile["lastName"] = *user.Profile.LastName.Get()
		}
		if user.Profile.DisplayName.Get() != nil {
			profile["displayName"] = *user.Profile.DisplayName.Get()
		}
		if user.Profile.SecondEmail.Get() != nil {
			profile["secondEmail"] = *user.Profile.SecondEmail.Get()
		}
		if user.Profile.EmployeeNumber != nil {
			profile["employeeNumber"] = *user.Profile.EmployeeNumber
		}
		// Add AdditionalProperties if they exist
		if user.Profile.AdditionalProperties != nil {
			for k, v := range user.Profile.AdditionalProperties {
				profile[k] = v
			}
		}
	}

	firstName, lastName := u.userName(user)

	// Add raw user status to profile
	if user.Status != nil {
		profile["c1_okta_raw_user_status"] = *user.Status
	}

	options := []resource.UserTraitOption{
		resource.WithUserProfile(profile),
	}

	// Set display name
	displayName := ""
	if user.Profile != nil && user.Profile.DisplayName.Get() != nil {
		displayName = *user.Profile.DisplayName.Get()
	}
	if displayName == "" {
		displayName = fmt.Sprintf("%s %s", firstName, lastName)
	}

	// Add created timestamp
	if user.Created != nil {
		options = append(options, resource.WithCreatedAt(*user.Created))
	}

	// Add last login timestamp - using Get() for NullableTime
	if user.LastLogin.Get() != nil {
		options = append(options, resource.WithLastLogin(*user.LastLogin.Get()))
	}

	// Add email addresses
	if user.Profile != nil {
		if user.Profile.Email != nil && *user.Profile.Email != "" {
			options = append(options, resource.WithEmail(*user.Profile.Email, true))
		}
		if secondEmail := user.Profile.SecondEmail.Get(); secondEmail != nil && *secondEmail != "" && !u.connector.skipSecondaryEmails {
			options = append(options, resource.WithEmail(*secondEmail, false))
		}
	}

	if u.connector.skipSecondaryEmails {
		profile["secondEmail"] = nil
	}

	// Extract employee IDs from standard field and additional properties
	employeeIDs := mapset.NewSet[string]()

	// Check standard EmployeeNumber field
	if user.Profile != nil && user.Profile.EmployeeNumber != nil && *user.Profile.EmployeeNumber != "" {
		employeeIDs.Add(*user.Profile.EmployeeNumber)
	}

	// Check additional properties for employee ID variations
	for profileKey, profileValue := range profile {
		switch strings.ToLower(profileKey) {
		case "employeenumber", "employeeid", "employeeidnumber", "employee_number", "employee_id", "employee_idnumber":
			if id, ok := profileValue.(string); ok && id != "" {
				employeeIDs.Add(id)
			}
		case "login":
			if login, ok := profileValue.(string); ok && login != "" {
				// Calculate shortname alias from login if it's an email
				splitLogin := strings.Split(login, "@")
				if len(splitLogin) == 2 {
					options = append(options, resource.WithUserLogin(login, splitLogin[0]))
				} else {
					options = append(options, resource.WithUserLogin(login))
				}
			}
		}
	}

	if employeeIDs.Cardinality() > 0 {
		options = append(options, resource.WithEmployeeID(employeeIDs.ToSlice()...))
	}

	// Set user status
	if user.Status != nil {
		switch *user.Status {
		case userStatusSuspended, userStatusDeprovisioned:
			options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_DISABLED, *user.Status))
		case userStatusActive, userStatusProvisioned, userStatusStaged, userStatusPasswordExpired, userStatusRecovery, userStatusLockedOut:
			options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_ENABLED, *user.Status))
		default:
			options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_UNSPECIFIED, *user.Status))
		}
	}

	userID := ""
	if user.Id != nil {
		userID = *user.Id
	}

	return resource.NewUserResource(
		displayName,
		userResourceType,
		userID,
		options,
	)
}

// userName extracts the first and last name from a user's profile.
func (u *userBuilder) userName(user *oktav5.User) (string, string) {
	firstName := unknownProfileValue
	lastName := unknownProfileValue

	if user.Profile != nil {
		if fn := user.Profile.FirstName.Get(); fn != nil {
			firstName = *fn
		}
		if ln := user.Profile.LastName.Get(); ln != nil {
			lastName = *ln
		}
	}

	return firstName, lastName
}
