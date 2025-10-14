package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	oktav5 "github.com/okta/okta-sdk-golang/v5/okta"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Okta error codes
// https://developer.okta.com/docs/reference/error-codes/
const (
	// E0000006 - Access denied
	ErrorCodeAccessDenied = "E0000006"
	// E0000007 - Not found
	ErrorCodeNotFound = "E0000007"
	// E0000008 - Resource not found
	ErrorCodeResourceNotFound = "E0000008"
	// E0000011 - Invalid token
	ErrorCodeInvalidToken = "E0000011"
	// E0000047 - API call exceeded rate limit
	ErrorCodeRateLimitExceeded = "E0000047"
)

// oktaNotFoundErrors contains error codes that indicate a resource was not found
var oktaNotFoundErrors = map[string]struct{}{
	ErrorCodeNotFound:         {},
	ErrorCodeResourceNotFound: {},
}

// handleOktaError handles errors from Okta API calls and converts them to appropriate gRPC status codes.
// This allows C1 to handle errors and alerts correctly.
func handleOktaError(resp *oktav5.APIResponse, err error) error {
	if err == nil {
		return nil
	}

	// Handle context timeout errors
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "request timeout")
	}

	// Handle URL timeout errors
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return status.Error(codes.DeadlineExceeded, fmt.Sprintf("request timeout: %v", urlErr.URL))
		}
	}

	// Handle HTTP response errors
	if resp != nil {
		statusCode := resp.StatusCode

		// Handle rate limiting (429)
		if statusCode == http.StatusTooManyRequests {
			return status.Error(codes.Unavailable, "rate limit exceeded")
		}

		// Handle server errors (500+)
		if statusCode >= 500 {
			return status.Error(codes.Unavailable, fmt.Sprintf("server error: status %d", statusCode))
		}

		// Handle not found (404)
		if statusCode == http.StatusNotFound {
			return status.Error(codes.NotFound, "resource not found")
		}

		// Handle forbidden (403)
		if statusCode == http.StatusForbidden {
			return status.Error(codes.PermissionDenied, "permission denied")
		}

		// Handle unauthorized (401)
		if statusCode == http.StatusUnauthorized {
			return status.Error(codes.Unauthenticated, "authentication required")
		}
	}

	// Try to extract Okta error from the response
	oktaErr := extractOktaError(resp, err)
	if oktaErr != nil {
		return convertOktaErrorToGRPC(oktaErr)
	}

	// Return the original error if we couldn't convert it
	return err
}

// extractOktaError attempts to extract an Okta Error from the response body
func extractOktaError(resp *oktav5.APIResponse, originalErr error) *oktav5.Error {
	// First try to cast the error directly
	var genericErr *oktav5.GenericOpenAPIError
	if errors.As(originalErr, &genericErr) {
		// Try to unmarshal the body into an Okta Error
		var oktaErr oktav5.Error
		if err := json.Unmarshal(genericErr.Body(), &oktaErr); err == nil {
			return &oktaErr
		}
	}

	// If we have a response, try to read the body
	if resp != nil && resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			var oktaErr oktav5.Error
			if err := json.Unmarshal(bodyBytes, &oktaErr); err == nil {
				return &oktaErr
			}
		}
	}

	return nil
}

// convertOktaErrorToGRPC converts an Okta error to a gRPC status error
func convertOktaErrorToGRPC(oktaErr *oktav5.Error) error {
	if oktaErr == nil {
		return nil
	}

	// Get error code
	errorCode := ""
	if oktaErr.ErrorCode != nil {
		errorCode = *oktaErr.ErrorCode
	}

	// Get error message
	errorMsg := "unknown error"
	if oktaErr.ErrorSummary != nil {
		errorMsg = *oktaErr.ErrorSummary
	}

	// Convert based on error code
	switch errorCode {
	case ErrorCodeAccessDenied:
		return status.Error(codes.PermissionDenied, fmt.Sprintf("access denied: %s", errorMsg))

	case ErrorCodeNotFound, ErrorCodeResourceNotFound:
		return status.Error(codes.NotFound, fmt.Sprintf("resource not found: %s", errorMsg))

	case ErrorCodeInvalidToken:
		return status.Error(codes.Unauthenticated, fmt.Sprintf("invalid token: %s", errorMsg))

	case ErrorCodeRateLimitExceeded:
		return status.Error(codes.Unavailable, fmt.Sprintf("rate limit exceeded: %s", errorMsg))

	default:
		// For unknown error codes, check if it's in the not found list
		if _, ok := oktaNotFoundErrors[errorCode]; ok {
			return status.Error(codes.NotFound, fmt.Sprintf("resource not found: %s", errorMsg))
		}

		// Return as generic error with the error code
		return status.Error(codes.Unknown, fmt.Sprintf("okta error %s: %s", errorCode, errorMsg))
	}
}

// wrapError wraps an error with a context message and proper gRPC status code if applicable
func wrapError(err error, message string) error {
	if err == nil {
		return nil
	}

	// If it's already a gRPC status error, preserve it
	if _, ok := status.FromError(err); ok {
		return err
	}

	// Otherwise wrap with the message
	return fmt.Errorf("%s: %w", message, err)
}

// extractRateLimitAnnotations extracts rate limit data from an Okta API response
// and returns it as annotations. This allows the Baton SDK to track rate limits
// and handle 429 responses appropriately.
func extractRateLimitAnnotations(resp *oktav5.APIResponse) annotations.Annotations {
	var annos annotations.Annotations

	if resp == nil {
		return annos
	}

	// Extract rate limit data from response headers
	// Okta uses X-Rate-Limit-* headers which are handled by the baton-sdk's ratelimit package
	if desc, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil {
		annos.WithRateLimiting(desc)
	}

	return annos
}
