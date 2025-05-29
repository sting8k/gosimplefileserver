package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Server configuration, read from command-line arguments
var config struct {
	Host           string
	Port           string
	Password       string // Password to access the server
	MaxUploadSizeMB int64  // Maximum upload size (MB)
	RootDir        string // Root directory to serve files from
	AbsRootDir     string // Absolute path of RootDir
	HmacSecret     []byte // Secret key for HMAC (derived from password)
}

const (
	sessionCookieName = "gofileserver_session"
	// Session duration. In this version, the session is valid
	// until the cookie is deleted or the server restarts.
	sessionDuration = 24 * time.Hour
)

// HTML Templates
var (
	loginTemplate    *template.Template
	listingTemplate  *template.Template
)

// Data structure for the file listing page
type ListingData struct {
	CurrentPath string      // Current path (relative to RootDir)
	ParentPath  string      // Parent directory path (if any)
	Entries     []DirEntry  // List of files and directories
	Message     string      // Message (e.g., upload successful)
	Error       string      // Error message
}

// Structure for a directory entry (file or subdirectory)
type DirEntry struct {
	Name         string    // File/directory name
	Path         string    // Full relative path for links
	IsDir        bool      // Is it a directory?
	Size         int64     // Size (for files)
	ModTime      time.Time // Last modification time
	DisplaySize  string    // Display size (KB, MB, GB)
}

func main() {
	// Parse command-line arguments
	flag.StringVar(&config.Host, "H", "0.0.0.0", "IP address for the server to listen on")
	flag.StringVar(&config.Host, "host", "0.0.0.0", "IP address for the server to listen on (alias for -H)")
	flag.StringVar(&config.Port, "p", "8080", "HTTP port for the server to listen on")
	flag.StringVar(&config.Port, "port", "8080", "HTTP port for the server to listen on (alias for -p)")
	flag.StringVar(&config.Password, "pw", "", "Password to access the server (required)")
	flag.StringVar(&config.Password, "password", "", "Password to access the server (required, alias for -pw)")
	flag.Int64Var(&config.MaxUploadSizeMB, "max-upload-size", 100, "Maximum allowed upload file size (MB)")
	flag.StringVar(&config.RootDir, "dir", ".", "Root directory to serve files from")
	flag.Parse()

	if config.Password == "" {
		log.Fatal("Error: Password (-pw or --password) is required.")
	}
	config.HmacSecret = []byte(config.Password) // Use password as HMAC secret key

	// Normalize RootDir to an absolute path
	var err error
	config.AbsRootDir, err = filepath.Abs(config.RootDir)
	if err != nil {
		log.Fatalf("Error: Could not get absolute path for root directory '%s': %v", config.RootDir, err)
	}
	fi, err := os.Stat(config.AbsRootDir)
	if err != nil {
		log.Fatalf("Error: Could not access root directory '%s': %v", config.AbsRootDir, err)
	}
	if !fi.IsDir() {
		log.Fatalf("Error: Root path '%s' is not a directory.", config.AbsRootDir)
	}

	log.Printf("Serving root directory: %s", config.AbsRootDir)

	// Initialize templates
	if err := initTemplates(); err != nil {
		log.Fatalf("Error initializing templates: %v", err)
	}

	// Setup router
	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.Handle("/upload", authMiddleware(http.HandlerFunc(handleUpload))) // Corrected line
	mux.Handle("/", authMiddleware(http.HandlerFunc(fileDirectoryHandler)))

	// Start server
	serverAddr := fmt.Sprintf("%s:%s", config.Host, config.Port)
	log.Printf("Server listening on http://%s", serverAddr)
	if err := http.ListenAndServe(serverAddr, requestLogger(mux)); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

// Initialize HTML templates
func initTemplates() error {
	var err error
	loginTemplate, err = template.New("login").Parse(loginPageHTML)
	if err != nil {
		return fmt.Errorf("error parsing login template: %w", err)
	}

	listingTemplate, err = template.New("listing").Funcs(template.FuncMap{
		"formatFileSize": formatFileSize,
	}).Parse(listingPageHTML)
	if err != nil {
		return fmt.Errorf("error parsing listing template: %w", err)
	}
	return nil
}

// Middleware to log each request
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf(
			"%s %s %s %s",
			r.Method,
			r.RequestURI,
			r.RemoteAddr,
			time.Since(start),
		)
	})
}

// Middleware to check authentication
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAuthenticated(r) {
			// Save current URL to redirect after successful login
			http.SetCookie(w, &http.Cookie{
				Name:     "redirect_url",
				Value:    r.URL.RequestURI(),
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Check if the user is authenticated
func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false // No cookie
	}

	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 2 {
		return false // Invalid cookie format
	}
	timestampHex, macHex := parts[0], parts[1]

	// Recreate MAC for comparison
	mac := hmac.New(sha256.New, config.HmacSecret)
	mac.Write([]byte(timestampHex))
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(macHex), []byte(expectedMAC))
}

// Handler for login page (GET) and login processing (POST)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		password := r.FormValue("password")
		if password == config.Password {
			// Create session cookie
			timestamp := strconv.FormatInt(time.Now().Unix(), 10)
			mac := hmac.New(sha256.New, config.HmacSecret)
			mac.Write([]byte(timestamp))
			sessionValue := fmt.Sprintf("%s|%s", timestamp, hex.EncodeToString(mac.Sum(nil)))

			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    sessionValue,
				Path:     "/",
				HttpOnly: true, // Important to prevent XSS
				SameSite: http.SameSiteLaxMode, // Helps prevent CSRF
				// Secure: true, // Only set true if using HTTPS
			})

			// Redirect to saved URL or homepage
			redirectURL := "/"
			if redirectCookie, err := r.Cookie("redirect_url"); err == nil {
				redirectURL = redirectCookie.Value
				// Delete redirect_url cookie
				http.SetCookie(w, &http.Cookie{
					Name:   "redirect_url",
					Value:  "",
					Path:   "/",
					MaxAge: -1, // Delete cookie
				})
			}
			http.Redirect(w, r, redirectURL, http.StatusFound)
			log.Printf("Login successful from %s", r.RemoteAddr)
		} else {
			log.Printf("Login failed from %s (incorrect password)", r.RemoteAddr)
			loginTemplate.Execute(w, map[string]string{"Error": "Incorrect password."})
		}
		return
	}

	// GET request: Display login page
	if isAuthenticated(r) { // If already logged in, redirect to homepage
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	loginTemplate.Execute(w, nil)
}

// Handler for logout
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Delete session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Instructs browser to delete cookie
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Main handler for serving files and listing directories
func fileDirectoryHandler(w http.ResponseWriter, r *http.Request) {
	// Get messages from query params (after upload/delete)
	message := r.URL.Query().Get("message")
	errorMsg := r.URL.Query().Get("error")

	// Requested path from URL, already cleaned by Go HTTP server
	// but we need to clean it further and check within RootDir scope
	urlPath := r.URL.Path

	// Convert to absolute path on the file system
	// and ensure it's within config.AbsRootDir
	requestedPath := filepath.Join(config.AbsRootDir, urlPath)
	cleanedPath := filepath.Clean(requestedPath)

	// Path Traversal check
	if !strings.HasPrefix(cleanedPath, config.AbsRootDir) {
		log.Printf("Path Traversal Warning: Request '%s' (cleaned to '%s') is outside root directory '%s'", urlPath, cleanedPath, config.AbsRootDir)
		http.Error(w, "Access Denied (Path Traversal)", http.StatusForbidden)
		return
	}

	// Check if path exists and is a file or directory
	fi, err := os.Stat(cleanedPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			log.Printf("Error accessing '%s': %v", cleanedPath, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	if fi.IsDir() {
		serveDirectoryListing(w, r, cleanedPath, urlPath, message, errorMsg)
	} else {
		// It's a file, serve it
		// http.ServeFile automatically handles Range requests, Content-Type, etc.
		http.ServeFile(w, r, cleanedPath)
	}
}

// Serve directory listing page
func serveDirectoryListing(w http.ResponseWriter, r *http.Request, absDirPath string, displayPath string, message string, errorMsg string) {
	dirEntries, err := os.ReadDir(absDirPath)
	if err != nil {
		log.Printf("Error reading directory '%s': %v", absDirPath, err)
		http.Error(w, "Cannot read directory", http.StatusInternalServerError)
		return
	}

	data := ListingData{
		CurrentPath: displayPath,
		Message:     message,
		Error:       errorMsg,
	}

	// Handle parent directory link
	if absDirPath != config.AbsRootDir {
		// Ensure displayPath always starts with /
		if !strings.HasPrefix(displayPath, "/") {
			displayPath = "/" + displayPath
		}
		parentDisplayPath := filepath.Dir(displayPath)
		// filepath.Dir of "/" is ".", of "/foo" is "/"
		// We want "/" for the root directory
		if parentDisplayPath == "." {
			parentDisplayPath = "/"
		}
		// Ensure parentDisplayPath is always canonical, e.g., no //
		parentDisplayPath = filepath.Clean(parentDisplayPath)
		// If displayPath is /foo, parentDisplayPath is /
		// If displayPath is /, parentDisplayPath is / (due to filepath.Clean)
		// We need to handle this case to not create a ../ link for the root directory
		if displayPath != "/" { // Only add parent link if not in root directory
			data.ParentPath = parentDisplayPath
		}
	}

	for _, entry := range dirEntries {
		info, err := entry.Info()
		if err != nil {
			log.Printf("Error getting info for '%s': %v", entry.Name(), err)
			continue // Skip this entry if info cannot be retrieved
		}
		entryPath := filepath.Join(displayPath, entry.Name())
		// Ensure path always starts with / for URL
		if !strings.HasPrefix(entryPath, "/") {
			entryPath = "/" + entryPath
		}

		data.Entries = append(data.Entries, DirEntry{
			Name:        entry.Name(),
			Path:        entryPath,
			IsDir:       info.IsDir(),
			Size:        info.Size(),
			ModTime:     info.ModTime(),
			DisplaySize: formatFileSize(info.Size()),
		})
	}

	// Sort: directories first, then files, then by name
	sort.Slice(data.Entries, func(i, j int) bool {
		if data.Entries[i].IsDir != data.Entries[j].IsDir {
			return data.Entries[i].IsDir // true (directory) < false (file) -> directories first
		}
		return strings.ToLower(data.Entries[i].Name) < strings.ToLower(data.Entries[j].Name)
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = listingTemplate.Execute(w, data)
	if err != nil {
		log.Printf("Error executing listing template: %v", err)
		http.Error(w, "Internal server error rendering page", http.StatusInternalServerError)
	}
}

// Handler for file uploads
func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is accepted", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body size (includes file and other form fields)
	maxUploadBytes := config.MaxUploadSizeMB * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)

	// Parse multipart form (limit form data size in memory)
	// 32 << 20 = 32MB for form data in memory, file data is streamed
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		if err.Error() == "http: request body too large" {
			log.Printf("Upload Error: File too large (exceeds %d MB)", config.MaxUploadSizeMB)
			redirectWithError(w, r, "Uploaded file is too large. Maximum size: "+strconv.FormatInt(config.MaxUploadSizeMB, 10)+" MB.")
			return
		}
		log.Printf("Error parsing multipart form: %v", err)
		redirectWithError(w, r, "Error processing upload form: "+err.Error())
		return
	}

	file, handler, err := r.FormFile("uploaded_file")
	if err != nil {
		log.Printf("Error retrieving file from form: %v", err)
		redirectWithError(w, r, "Error retrieving file from form: "+err.Error())
		return
	}
	defer file.Close()

	// Get current directory for upload from hidden field
	currentRelativeDir := r.FormValue("current_dir")
	if currentRelativeDir == "" {
		currentRelativeDir = "/" // Default to root directory if not provided
	}
	// Clean and check currentRelativeDir
	currentRelativeDir = filepath.Clean(currentRelativeDir)
	// If currentRelativeDir starts with /, it's an absolute path from the URL's root
	// We want it as a relative subdirectory, e.g., "folder1" not "/folder1"
	currentRelativeDir = strings.TrimPrefix(currentRelativeDir, "/")

	// Determine target directory to save the file
	targetUploadDir := filepath.Join(config.AbsRootDir, currentRelativeDir)
	// Path Traversal check for targetUploadDir
	if !strings.HasPrefix(filepath.Clean(targetUploadDir), config.AbsRootDir) {
		log.Printf("Path Traversal Warning during upload: Target directory '%s' (from current_dir '%s') is outside root directory.", targetUploadDir, currentRelativeDir)
		redirectWithError(w, r, "Error: Invalid upload directory.")
		return
	}
	// Ensure target directory exists and is a directory
	fi, err := os.Stat(targetUploadDir)
	if os.IsNotExist(err) {
		log.Printf("Upload Error: Target directory '%s' does not exist.", targetUploadDir)
		redirectWithError(w, r, "Error: Upload directory does not exist.")
		return
	}
	if !fi.IsDir() {
		log.Printf("Upload Error: Target path '%s' is not a directory.", targetUploadDir)
		redirectWithError(w, r, "Error: Upload path must be a directory.")
		return
	}

	// Sanitize filename from client (prevent Path Traversal)
	sanitizedFileName := filepath.Base(handler.Filename)
	if sanitizedFileName == "." || sanitizedFileName == ".." || sanitizedFileName == "" {
		log.Printf("Warning: Invalid filename from client: %s", handler.Filename)
		redirectWithError(w, r, "Invalid filename.")
		return
	}

	// Handle duplicate filenames
	finalFileName := sanitizedFileName
	counter := 1
	for {
		filePath := filepath.Join(targetUploadDir, finalFileName)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			break // Filename does not exist, can use
		}
		// Filename exists, try a new name
		extension := filepath.Ext(sanitizedFileName)
		nameWithoutExt := strings.TrimSuffix(sanitizedFileName, extension)
		finalFileName = fmt.Sprintf("%s_%d%s", nameWithoutExt, counter, extension)
		counter++
	}

	// Create file on server
	dstPath := filepath.Join(targetUploadDir, finalFileName)
	dst, err := os.Create(dstPath)
	if err != nil {
		log.Printf("Error creating file '%s': %v", dstPath, err)
		redirectWithError(w, r, "Server error creating file: "+err.Error())
		return
	}
	defer dst.Close()

	// Copy uploaded file content to server file
	if _, err := io.Copy(dst, file); err != nil {
		log.Printf("Error copying file '%s': %v", dstPath, err)
		// Attempt to remove partially created file if copy fails
		os.Remove(dstPath)
		redirectWithError(w, r, "Server error copying file: "+err.Error())
		return
	}

	log.Printf("File '%s' (size %d bytes) uploaded successfully to '%s' by %s", finalFileName, handler.Size, targetUploadDir, r.RemoteAddr)

	// Redirect to current directory with success message
	// currentRelativeDir has been cleaned, ensure it's a valid URL path
	redirectPath := "/" + strings.TrimPrefix(currentRelativeDir, "/") // Ensure starts with /
	if redirectPath != "/" && strings.HasSuffix(redirectPath, "/") { // Remove trailing / if present (except for root)
		redirectPath = strings.TrimSuffix(redirectPath, "/")
	}
	if redirectPath == "" {
		redirectPath = "/"
	} // Ensure not empty if currentRelativeDir was "" or "."

	http.Redirect(w, r, redirectPath+"?message="+template.URLQueryEscaper("File '"+finalFileName+"' uploaded successfully."), http.StatusFound)
}

// Utility function to redirect with an error message
func redirectWithError(w http.ResponseWriter, r *http.Request, errorMsg string) {
	// Get current_dir from form to know where to redirect
	currentRelativeDir := r.FormValue("current_dir")
	if currentRelativeDir == "" {
		currentRelativeDir = "/"
	}
	currentRelativeDir = filepath.Clean(currentRelativeDir)
	currentRelativeDir = strings.TrimPrefix(currentRelativeDir, "/")

	redirectPath := "/" + currentRelativeDir
	if redirectPath != "/" && strings.HasSuffix(redirectPath, "/") {
		redirectPath = strings.TrimSuffix(redirectPath, "/")
	}
	if redirectPath == "" {
		redirectPath = "/"
	}

	http.Redirect(w, r, redirectPath+"?error="+template.URLQueryEscaper(errorMsg), http.StatusFound)
}

// Format file size for readability
func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

// --- HTML Templates ---
const loginPageHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; min-height: 90vh; background-color: #f4f4f4; margin: 0; }
        .container { background-color: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; }
        h2 { text-align: center; color: #333; margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #555; }
        input[type="password"] { width: calc(100% - 20px); padding: 10px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 4px; }
        button { width: 100%; padding: 10px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background-color: #0056b3; }
        .error { color: red; text-align: center; margin-bottom: 10px; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Server Login</h2>
        {{if .Error}}
            <p class="error">{{.Error}}</p>
        {{end}}
        <form method="POST" action="/login">
            <div>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
`

const listingPageHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Directory Listing: {{.CurrentPath}}</title>
    <style>
        body { font-family: sans-serif; margin: 20px; background-color: #f9f9f9; color: #333; }
        .container { max-width: 900px; margin: auto; background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        h1, h2 { color: #0056b3; }
		h1 { font-size: 1.5em; margin-bottom: 5px; }
		.current-path-display { font-size: 1.2em; color: #555; margin-bottom: 20px; word-break: break-all; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #eee; }
        th { background-color: #f0f0f0; font-weight: bold; }
        tr:hover { background-color: #f5f5f5; }
        .upload-form { margin-top: 30px; padding: 20px; background-color: #f0f8ff; border: 1px solid #cce5ff; border-radius: 5px; }
        .upload-form h2 { margin-top: 0; font-size: 1.2em; }
        .upload-form input[type="file"] { display: block; margin-bottom: 10px; }
        .upload-form button { padding: 8px 15px; background-color: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .upload-form button:hover { background-color: #218838; }
        .message { padding: 10px; margin-bottom: 15px; border-radius: 4px; }
        .message.success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .message.error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
		.icon { display: inline-block; width: 20px; text-align: center; margin-right: 5px;}
		.logout-link { float: right; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
		<a href="/logout" class="logout-link">Logout</a>
        <h1>Simple File Server</h1>
		<div class="current-path-display">Current directory: <strong>{{.CurrentPath}}</strong></div>

        {{if .Message}}
            <p class="message success">{{.Message}}</p>
        {{end}}
        {{if .Error}}
            <p class="message error">{{.Error}}</p>
        {{end}}

        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Last Modified</th>
                </tr>
            </thead>
            <tbody>
                {{if .ParentPath}}
                <tr>
                    <td colspan="3"><span class="icon">⤴️</span><a href="{{.ParentPath}}">Parent Directory (..)</a></td>
                </tr>
                {{end}}
                {{range .Entries}}
                <tr>
                    <td>
						{{if .IsDir}}
							<span class="icon">📁</span>
						{{else}}
							<span class="icon">📄</span>
						{{end}}
						<a href="{{.Path}}">{{.Name}}</a>
						{{if .IsDir}}/{{end}}
					</td>
                    <td>{{if not .IsDir}}{{.DisplaySize}}{{end}}</td>
                    <td>{{.ModTime.Format "02-Jan-2006 15:04:05"}}</td>
                </tr>
                {{else}}
                <tr>
                    <td colspan="3"><em>This directory is empty.</em></td>
                </tr>
                {{end}}
            </tbody>
        </table>

        <div class="upload-form">
            <h2>Upload File</h2>
            <form action="/upload" method="POST" enctype="multipart/form-data">
                <input type="hidden" name="current_dir" value="{{.CurrentPath}}">
                <input type="file" name="uploaded_file" required>
                <button type="submit">Upload</button>
            </form>
        </div>
    </div>
</body>
</html>
`

