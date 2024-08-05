package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedAPIKey string
		expectedError  error
	}{
		{
			name:           "No Authorization Header",
			headers:        http.Header{},
			expectedAPIKey: "",
			expectedError:  ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - Missing ApiKey Prefix",
			headers: http.Header{
				"Authorization": {"Bearer somekey"},
			},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Missing Key",
			headers: http.Header{
				"Authorization": {"ApiKey"},
			},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": {"ApiKey mysecretapikey"},
			},
			expectedAPIKey: "mysecretapikey",
			expectedError:  nil,
		},
		{
			name: "Empty API Key in Authorization Header",
			headers: http.Header{
				"Authorization": {"ApiKey "},
			},
			expectedAPIKey: "",
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)
			if apiKey != tt.expectedAPIKey {
				t.Errorf("expected API key %q, got %q", tt.expectedAPIKey, apiKey)
			}
			if (err != nil && tt.expectedError == nil) || (err == nil && tt.expectedError != nil) || (err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}
