package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123xyz"},
			},
			expectedKey:   "abc123xyz",
			expectedError: nil,
		},
		{
			name: "Missing Authorization Header",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Empty Authorization Header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Header - No Space",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Header - Wrong Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123xyz"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Header - Multiple Spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey  abc123xyz"},
			},
			expectedKey:   "abc123xyz",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			// Check if error matches expected error
			if err != nil && tt.expectedError == nil {
				t.Errorf("Expected no error, but got: %v", err)
			}
			if err == nil && tt.expectedError != nil {
				t.Errorf("Expected error '%v', but got none", tt.expectedError)
			}
			if err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error() {
				t.Errorf("Expected error '%v', but got '%v'", tt.expectedError, err)
			}

			// Check if API key matches expected key
			if apiKey != tt.expectedKey {
				t.Errorf("Expected API key '%s', but got '%s'", tt.expectedKey, apiKey)
			}
		})
	}
}
