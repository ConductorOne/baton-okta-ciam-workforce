package config

import (
	"testing"

	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/stretchr/testify/assert"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *OktaCiamWorkforce
		wantErr bool
	}{
		{
			name:   "valid config",
			config: &OktaCiamWorkforce{
				// TODO: Add minimal valid configuration here once Config type is generated
			},
			wantErr: false,
		},
		{
			name:   "invalid config - missing required fields",
			config: &OktaCiamWorkforce{
				// TODO: Add configuration with missing required fields once Config type is generated
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := field.Validate(Config, tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
