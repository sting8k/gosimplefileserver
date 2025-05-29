// main_test.go
package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Helper function to set up the server for each test (or group of tests)
func setupTestServer(t *testing.T, rootDir string, password string) *httptest.Server {
	// Store old config and restore after test if needed,
	// or set config directly for the test.
	originalPassword := config.Password
	originalHmacSecret := config.HmacSecret
	originalRootDir := config.RootDir
	originalAbsRootDir := config.AbsRootDir

	config.Password = password
	config.HmacSecret = []byte(password)
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
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.Handle("/upload", authMiddleware(http.HandlerFunc(handleUpload)))
	mux.Handle("/", authMiddleware(http.HandlerFunc(fileDirectoryHandler)))

	// Restore original config after test finishes
	t.Cleanup(func() {
		config.Password = originalPassword
		config.HmacSecret = originalHmacSecret
		config.RootDir = originalRootDir
		config.AbsRootDir = originalAbsRootDir
	})
	
	return httptest.NewServer(requestLogger(mux))
}


func TestLoginHandler_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testserver_loginsuccess")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testPassword := "testpass"
	ts := setupTestServer(t, tmpDir, testPassword)
	defer ts.Close()

	// Create a client that does not follow redirects automatically
	client := ts.Client() 
    client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
        return http.ErrUseLastResponse // Prevent client from auto-following redirects
    }

	// 1. POST to /login with correct password
	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"password": {testPassword},
	})
	if err != nil {
		t.Fatalf("POST /login failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected status %d for successful login, got %d", http.StatusFound, resp.StatusCode)
	}

	location, err := resp.Location()
	if err != nil {
		t.Errorf("Expected Location header for redirect, got error: %v", err)
	} else if location.Path != "/" { // Assuming default redirect is to root
		t.Errorf("Expected redirect to '/', got '%s'", location.Path)
	}
	
	foundCookie := false
	var sessionCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == sessionCookieName {
			foundCookie = true
			sessionCookie = cookie
			if !cookie.HttpOnly {
				t.Errorf("Session cookie should be HttpOnly")
			}
			break
		}
	}
	if !foundCookie {
		t.Errorf("Session cookie '%s' not found after successful login", sessionCookieName)
	}

	// 2. Access a protected page with the new session cookie, should be allowed
	reqProtected, _ := http.NewRequest("GET", ts.URL+"/", nil)
	if sessionCookie != nil {
		reqProtected.AddCookie(sessionCookie) // Add the session cookie from login response
	} else {
		t.Fatal("Session cookie was nil, cannot proceed to test protected page.")
	}
	
	// Use a new client for this request to ensure cookies are handled explicitly by the test
	freshClient := &http.Client{} 
	respProtected, err := freshClient.Do(reqProtected)
	if err != nil {
		t.Fatalf("GET / (protected) failed: %v", err)
	}
	defer respProtected.Body.Close()

	if respProtected.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d for accessing protected page with session, got %d", http.StatusOK, respProtected.StatusCode)
	}
}

func TestLoginHandler_Failure(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testserver_loginfailure")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testPassword := "testpass"
	ts := setupTestServer(t, tmpDir, testPassword)
	defer ts.Close()
	
	client := ts.Client() // Default client follows redirects, which is fine here as it re-renders the login page.

	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"password": {"wrongpassword"},
	})
	if err != nil {
		t.Fatalf("POST /login failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK { // Expect 200 OK because it re-renders the login page with an error
		t.Errorf("Expected status %d for failed login (re-render), got %d", http.StatusOK, resp.StatusCode)
	}

	// Check if the response body contains the error message
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	expectedErrorMsg := "Incorrect password."
	if !strings.Contains(bodyString, expectedErrorMsg) {
		t.Errorf("Expected error message '%s' in response body, got: %s", expectedErrorMsg, bodyString)
	}

	// Check that no session cookie was set
	for _, cookie := range resp.Cookies() { // This checks cookies set in this specific response
		if cookie.Name == sessionCookieName {
			t.Errorf("Session cookie should not be set on failed login")
			break
		}
	}
}

// Add more test cases for upload, download, listing, path traversal, logout etc.

func TestFileDirectoryHandler_PathTraversal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testserver_pathtraversal")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a dummy file outside the intended root, but this test primarily checks URL handling
	// The actual file system check is handled by the server's logic based on AbsRootDir.
	
	testPassword := "testpass"
	ts := setupTestServer(t, tmpDir, testPassword) // Server rooted at tmpDir
	defer ts.Close()

	// First, log in to get a session cookie
	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse } 
	loginResp, err := client.PostForm(ts.URL+"/login", url.Values{"password": {testPassword}})
	if err != nil {
		t.Fatalf("Login failed for path traversal test: %v", err)
	}
	var sessionCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("Failed to get session cookie for path traversal test")
	}
	loginResp.Body.Close()


	// Test cases for path traversal attempts
	traversalAttempts := []string{
		"/../../../../etc/passwd",
		"/../" + filepath.Base(os.Args[0]), // Try to access the test binary itself if it were outside root
		"/dir/../../file_outside_dir_but_inside_root", // This might be valid if 'file_outside_dir_but_inside_root' is in root
		"/dir/../../../file_definitely_outside_root",
	}

	// Create a file inside the root for a controlled "valid" escape that should still be contained
	// For example, if tmpDir is /tmp/test123, and we request /sub/../../testfile.txt
	// this should resolve to /tmp/test123/testfile.txt
	// If we request /sub/../../../testfile.txt, it would try /tmp/testfile.txt (outside root)
	
	// Create a dummy file in the root for one of the tests
	// The path traversal protection should prevent accessing anything not *under* AbsRootDir
	// even if it resolves to a valid path on the system that is outside AbsRootDir.

	for _, attempt := range traversalAttempts {
		req, _ := http.NewRequest("GET", ts.URL+attempt, nil)
		req.AddCookie(sessionCookie)
		
		// Create a client that follows redirects
        followClient := ts.Client()
        // Add redirect policy to follow redirects and capture the final response
        followClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
            // Copy the session cookie to redirected requests
            for _, cookie := range via[0].Cookies() {
                req.AddCookie(cookie)
            }
            return nil // Allow following redirects
        }
        
        resp, err := followClient.Do(req)
        if err != nil {
            t.Errorf("Request for traversal path '%s' failed: %v", attempt, err)
            continue
        }
        defer resp.Body.Close()

        // Expect Forbidden or Not Found for the final destination
        if resp.StatusCode == http.StatusOK {
            t.Errorf("Path traversal attempt '%s' succeeded with status OK, should have failed", attempt)
            body, _ := io.ReadAll(resp.Body)
            t.Logf("Response body: %s", string(body))
        } else if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
            t.Errorf("Path traversal attempt '%s' returned final status %d, expected Forbidden (403) or Not Found (404)", 
                     attempt, resp.StatusCode)
        }
        log.Printf("Path traversal attempt '%s' got final status: %d (expected non-200)", attempt, resp.StatusCode)
	}
}