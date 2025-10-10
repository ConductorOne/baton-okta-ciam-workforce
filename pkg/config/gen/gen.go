package main

import (
	cfg "github.com/conductorone/baton-okta-ciam-workforce/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("okta-ciam-workforce", cfg.Config)
}
