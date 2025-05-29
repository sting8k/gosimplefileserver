// main_test.go
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Helper function to set up the server for each test (or group of tests)
func setupTestServer(t *testing.T, rootDir string, password string) *httptest.Server {
	// Store old config and restore after test if needed
	originalPassword := config.Password
	originalRootDir := config.RootDir

	config.Password = password
	config.RootDir = rootDir
	var err error
	config.AbsRootDir, err = filepath.Abs(rootDir)
	if err != nil {
		t.Fatalf("Failed to get absolute root dir for test: %v", err)
	}

	// Ensure templates are loaded for each test server instance
	if err := initTemplates(); err != nil {
		t.Fatalf("Failed to init templates for test: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/upload", authMiddleware(http.HandlerFunc(handleUpload)))
	mux.Handle("/", authMiddleware(http.HandlerFunc(fileDirectoryHandler)))

	// Restore original config after test finishes
	t.Cleanup(func() {
		config.Password = originalPassword
		config.RootDir = originalRootDir
	})

	return httptest.NewServer(mux)
}

func TestAuthMiddleware(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testserver_authmiddleware")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testPassword := "testpass"
	ts := setupTestServer(t, tmpDir, testPassword)
	defer ts.Close()

	tests := []struct {
		name           string
		url            string
		expectedStatus int
		expectBody     string
	}{
		{
			name:           "valid password in query param",
			url:            "/?pw=" + testPassword,
			expectedStatus: http.StatusOK,
			expectBody:     "Directory Listing",
		},
		{
			name:           "missing password",
			url:            "/",
			expectedStatus: http.StatusUnauthorized,
			expectBody:     "Access Denied",
		},
		{
			name:           "wrong password",
			url:            "/?pw=wrongpass",
			expectedStatus: http.StatusUnauthorized,
			expectBody:     "Access Denied",
		},
		{
			name:           "empty password",
			url:            "/?pw=",
			expectedStatus: http.StatusUnauthorized,
			expectBody:     "Access Denied",
		},
		{
			name:           "password in nested path",
			url:            "/subdir?pw=" + testPassword,
			expectedStatus: http.StatusNotFound, // Since directory doesn't exist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ts.Client().Get(ts.URL + tt.url)
			if err != nil {
				t.Fatalf("HTTP request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			if tt.expectBody != "" {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}
				if !strings.Contains(string(body), tt.expectBody) {
					t.Errorf("Expected body to contain '%s', got: %s", tt.expectBody, string(body))
				}
			}
		})
	}
}

func TestAuthentication_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testserver_authsuccess")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testPassword := "testpass"
	ts := setupTestServer(t, tmpDir, testPassword)
	defer ts.Close()

	// Test direct access with password in URL
	resp, err := ts.Client().Get(ts.URL + "/?pw=" + testPassword)
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d for successful access, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestDirectAccess_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testserver_directaccess")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testPassword := "testpass"
	ts := setupTestServer(t, tmpDir, testPassword)
	defer ts.Close()

	// Access with correct password in URL
	resp, err := ts.Client().Get(ts.URL + "/?pw=" + testPassword)
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d for successful access, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestDirectAccess_Failure(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testserver_directaccessfail")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testPassword := "testpass"
	ts := setupTestServer(t, tmpDir, testPassword)
	defer ts.Close()

	// Test cases for failed access
	failureCases := []struct {
		url  string
		desc string
	}{
		{ts.URL + "/", "no password"},
		{ts.URL + "/?pw=wrongpass", "wrong password"},
		{ts.URL + "/?pw=", "empty password"},
	}

	for _, tc := range failureCases {
		resp, err := ts.Client().Get(tc.url)
		if err != nil {
			t.Fatalf("GET / failed for %s: %v", tc.desc, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status %d for %s, got %d",
				http.StatusUnauthorized, tc.desc, resp.StatusCode)
		}

		// Check for unauthorized message in response
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "Access Denied") {
			t.Errorf("Expected 'Access Denied' message for %s", tc.desc)
		}
	}
}

func TestFileDirectoryHandler_PathTraversal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testserver_pathtraversal")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testPassword := "testpass"
	ts := setupTestServer(t, tmpDir, testPassword)
	defer ts.Close()

	traversalAttempts := []string{
		"/../../../../etc/passwd",
		"/../" + filepath.Base(os.Args[0]),
		"/dir/../../file_outside_dir_but_inside_root",
		"/dir/../../../file_definitely_outside_root",
	}

	for _, attempt := range traversalAttempts {
		url := ts.URL + attempt + "?pw=" + testPassword
		resp, err := ts.Client().Get(url)
		if err != nil {
			t.Errorf("Request for traversal path '%s' failed: %v", attempt, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Errorf("Path traversal attempt '%s' succeeded with status OK, should have failed", attempt)
			body, _ := io.ReadAll(resp.Body)
			t.Logf("Response body: %s", string(body))
		} else if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
			t.Errorf("Path traversal attempt '%s' returned status %d, expected Forbidden (403) or Not Found (404)",
				attempt, resp.StatusCode)
		}
	}
}
