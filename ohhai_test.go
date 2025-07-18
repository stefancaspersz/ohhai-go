package main

import (
	"context" // *** NEW: Import the context package
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPerformDNSQuery tests the DNS lookup logic using a table-driven test.
// This is a great way to test many cases for a single function.
func TestPerformDNSQuery(t *testing.T) {
	// We can't do real lookups in a test easily, so we focus on input validation.
	// Testing the actual net.Lookup* functions is the job of the Go standard library authors.
	testCases := []struct {
		name          string
		query         string
		expectError   bool
		errorContains string
	}{
		{
			name:          "Valid A record query format",
			query:         "example.com.A",
			expectError:   false, // It will fail the lookup, but the format is valid.
			errorContains: "",
		},
		{
			name:          "Unsupported record type",
			query:         "example.com.SRV",
			expectError:   true,
			errorContains: "unsupported record type: SRV",
		},
		{
			name:          "Invalid query format - no dot",
			query:         "examplecomA",
			expectError:   true,
			errorContains: "Invalid query format",
		},
		{
			name:          "Invalid query format - empty type",
			query:         "example.com.",
			expectError:   true,
			errorContains: "Invalid query format",
		},
		{
			name:          "Empty query string",
			query:         "",
			expectError:   false, // Function should handle this gracefully by returning nil
			errorContains: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := performDNSQuery(tc.query)

			if tc.query == "" {
				if result != nil {
					t.Errorf("Expected nil result for empty query, but got %v", result)
				}
				return // Test case finished
			}

			if tc.expectError {
				if result.Error == "" {
					t.Errorf("Expected an error, but got none")
				} else if !strings.Contains(result.Error, tc.errorContains) {
					t.Errorf("Expected error to contain '%s', but got '%s'", tc.errorContains, result.Error)
				}
			} else {
				// We don't check for a positive result here, just that our own logic didn't fail.
				// The underlying net.Lookup will fail, which is expected.
				if result.Error != "" && !strings.Contains(result.Error, "no such host") {
					// Check for unexpected errors (not a simple lookup failure)
					t.Errorf("Got unexpected error: %s", result.Error)
				}
			}
		})
	}
}

// TestFetchExternalURL tests fetching a URL, including redirect handling.
// It uses httptest.NewServer to create a fake external server.
func TestFetchExternalURL(t *testing.T) {
	const successPath = "/success" // Defined constant for the success path

	// Create a mock server that simulates different responses.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", successPath)
			w.WriteHeader(http.StatusFound) // 302
			return
		}
		if r.URL.Path == successPath {
			w.WriteHeader(http.StatusOK)
			// *** MODIFIED: Handle the error return from Fprintln.
			if _, err := fmt.Fprintln(w, "Hello, client"); err != nil {
				// A panic in a test server handler will cause the test to fail.
				panic(fmt.Sprintf("failed to write to httptest recorder: %v", err))
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	// Case 1: Test a successful redirect
	t.Run("handles redirect", func(t *testing.T) {
		result := fetchExternalURL(context.TODO(), server.URL+"/redirect")

		if result.Error != "" {
			t.Fatalf("Expected no error, got: %s", result.Error)
		}
		if result.StatusCode != http.StatusFound {
			t.Errorf("Expected status code %d, got %d", http.StatusFound, result.StatusCode)
		}
		expectedLocation := successPath
		if result.RedirectLocation != expectedLocation {
			t.Errorf("Expected redirect location '%s', got '%s'", expectedLocation, result.RedirectLocation)
		}
	})

	// Case 2: Test a direct successful fetch
	t.Run("handles success", func(t *testing.T) {
		result := fetchExternalURL(context.TODO(), server.URL+successPath)

		if result.Error != "" {
			t.Fatalf("Expected no error, got: %s", result.Error)
		}
		if result.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, result.StatusCode)
		}
		if !strings.Contains(result.Body, "Hello, client") {
			t.Errorf("Expected body to contain 'Hello, client', got '%s'", result.Body)
		}
	})
}

// TestHeadersHandler tests the main HTTP handler.
func TestHeadersHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/foo?fetch_url=http://google.com", nil)
	w := httptest.NewRecorder() // httptest.NewRecorder implements http.ResponseWriter

	headersHandler(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	// Check status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.Status)
	}

	// Check content type
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Expected content-type application/json, got %s", resp.Header.Get("Content-Type"))
	}

	// Check if the response body is valid JSON and contains expected fields
	var responseInfo RequestInfo
	err := json.Unmarshal(body, &responseInfo)
	if err != nil {
		t.Fatalf("Could not unmarshal response JSON: %s", err)
	}

	if responseInfo.Path != "/foo" {
		t.Errorf("Expected path '/foo', got '%s'", responseInfo.Path)
	}

	// Because fetch_url was passed, we expect ExternalFetchResult to be populated
	if responseInfo.ExternalFetchResult == nil {
		t.Error("Expected ExternalFetchResult to be populated, but it was nil")
	} else if responseInfo.ExternalFetchResult.URL != "http://google.com" {
		t.Errorf("Expected ExternalFetchResult.URL to be 'http://google.com', got '%s'", responseInfo.ExternalFetchResult.URL)
	}
}
