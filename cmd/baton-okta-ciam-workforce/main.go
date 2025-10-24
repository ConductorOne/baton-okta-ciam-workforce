package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	cfg "github.com/conductorone/baton-okta-ciam-workforce/pkg/config"
	"github.com/conductorone/baton-okta-ciam-workforce/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

var version = "dev"

func main() {
	ctx := context.Background()

	_, cmd, err := config.DefineConfiguration(
		ctx,
		"baton-okta-ciam-workforce",
		getConnector,
		cfg.ConfigurationSchema,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version

	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, oktaCfg *cfg.OktaCiamWorkforce) (types.ConnectorServer, error) {
	if err := field.Validate(cfg.ConfigurationSchema, oktaCfg); err != nil {
		return nil, err
	}

	l := ctxzap.Extract(ctx)

	// Normalize email domains to lowercase
	var normalizedEmailDomains []string
	for _, domain := range oktaCfg.EmailDomains {
		normalizedEmailDomains = append(normalizedEmailDomains, strings.TrimSpace(strings.ToLower(domain)))
	}

	// Normalize group name filter to lowercase
	groupNameFilter := strings.TrimSpace(strings.ToLower(oktaCfg.GroupNameFilter))

	// Create connector
	c, err := connector.New(ctx, oktaCfg.Domain, oktaCfg.ApiToken, normalizedEmailDomains, groupNameFilter)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	// Build and return connector server
	connectorServer, err := connectorbuilder.NewConnector(ctx, c)
	if err != nil {
		l.Error("error building connector server", zap.Error(err))
		return nil, err
	}

	return connectorServer, nil
}
