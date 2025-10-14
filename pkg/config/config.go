package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	DomainField = field.StringField(
		"domain",
		field.WithDisplayName("Domain"),
		field.WithDescription("Okta domain (e.g., company.okta.com)"),
		field.WithRequired(true),
	)
	ApiTokenField = field.StringField(
		"api-token",
		field.WithDisplayName("API Token"),
		field.WithIsSecret(true),
		field.WithDescription("Okta API token"),
		field.WithRequired(true),
	)
	EmailDomainsField = field.StringSliceField(
		"email-domains",
		field.WithDisplayName("Email Domains"),
		field.WithDescription("Comma-separated list of email domains to filter users (e.g., example.com,company.com)"),
		field.WithRequired(true),
	)
	GroupNameFilterField = field.StringField(
		"group-name-filter",
		field.WithDisplayName("Group Name Filter"),
		field.WithDescription("String to filter group names (only groups containing this string will be synced)"),
		field.WithRequired(false),
	)

	// ConfigurationFields defines the external configuration required for the
	// connector to run.
	ConfigurationFields = []field.SchemaField{
		DomainField,
		ApiTokenField,
		EmailDomainsField,
		GroupNameFilterField,
	}
)

//go:generate go run ./gen
var ConfigurationSchema = field.NewConfiguration(
	ConfigurationFields,
	field.WithConnectorDisplayName("Okta CIAM Workforce"),
	field.WithHelpUrl("/docs/baton/okta-ciam-workforce"),
	field.WithIconUrl("/static/app-icons/okta.svg"),
)
