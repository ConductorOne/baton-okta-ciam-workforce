package connector

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	oktav5 "github.com/okta/okta-sdk-golang/v5/okta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestHandleOktaError_NonNilWrapperNilResponse is the regression test for
// CXP-889: APIResponse embeds *http.Response, so a non-nil *APIResponse
// wrapping a nil *http.Response used to panic on the promoted-field access
// rather than falling through to the nil-response handling.
func TestHandleOktaError_NonNilWrapperNilResponse(t *testing.T) {
	resp := &oktav5.APIResponse{}
	err := errors.New("transport failure")

	var got error
	require.NotPanics(t, func() {
		got = handleOktaError(resp, err)
	})

	st, ok := status.FromError(got)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestHandleOktaError_NilWrapper(t *testing.T) {
	err := errors.New("transport failure")

	var got error
	require.NotPanics(t, func() {
		got = handleOktaError(nil, err)
	})

	st, ok := status.FromError(got)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestHandleOktaError_NilError(t *testing.T) {
	assert.NoError(t, handleOktaError(nil, nil))
	assert.NoError(t, handleOktaError(&oktav5.APIResponse{}, nil))
}

func TestHandleOktaError_StatusMapping(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantCode   codes.Code
	}{
		{"too many requests", http.StatusTooManyRequests, codes.Unavailable},
		{"server error", http.StatusInternalServerError, codes.Unavailable},
		{"not found", http.StatusNotFound, codes.NotFound},
		{"forbidden", http.StatusForbidden, codes.PermissionDenied},
		{"unauthorized", http.StatusUnauthorized, codes.Unauthenticated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &oktav5.APIResponse{Response: &http.Response{StatusCode: tt.statusCode}}
			err := errors.New("http error")

			got := handleOktaError(resp, err)

			st, ok := status.FromError(got)
			require.True(t, ok)
			assert.Equal(t, tt.wantCode, st.Code())
		})
	}
}

func TestHandleOktaError_DeadlineExceededPrecedesStatusCode(t *testing.T) {
	resp := &oktav5.APIResponse{Response: &http.Response{StatusCode: http.StatusInternalServerError}}
	err := context.DeadlineExceeded

	got := handleOktaError(resp, err)

	st, ok := status.FromError(got)
	require.True(t, ok)
	assert.Equal(t, codes.DeadlineExceeded, st.Code())
}

func TestExtractOktaError_NilEmbeddedResponse(t *testing.T) {
	resp := &oktav5.APIResponse{}

	var got *oktav5.Error
	require.NotPanics(t, func() {
		got = extractOktaError(resp, errors.New("transport failure"))
	})
	assert.Nil(t, got)
}

func TestExtractRateLimitAnnotations_NilEmbeddedResponse(t *testing.T) {
	resp := &oktav5.APIResponse{}

	var got annotations.Annotations
	require.NotPanics(t, func() {
		got = extractRateLimitAnnotations(resp)
	})
	assert.Empty(t, got)
}

func TestExtractRateLimitAnnotations_NilWrapper(t *testing.T) {
	got := extractRateLimitAnnotations(nil)
	assert.Empty(t, got)
}
