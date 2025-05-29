package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
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
	Host            string
	Port            string
	Password        string // Password to access the server
	MaxUploadSizeMB int64  // Maximum upload size (MB)
	RootDir         string // Root directory to serve files from
	AbsRootDir      string // Absolute path of RootDir
}

const (
	passwordLength = 8
	version        = "1.0.1" // Add version constant for the application
)

// HTML Templates
var (
	// loginTemplate   *template.Template // Login page might be removed or simplified
	listingTemplate *template.Template
	// A simple info/error page might be useful if login page is removed
	infoPageTemplate *template.Template
)

// Data structure for the file listing page
type ListingData struct {
	CurrentPath    string     // Current path (relative to RootDir)
	ParentPath     string     // Parent directory path (if any)
	Entries        []DirEntry // List of files and directories
	Message        string     // Message (e.g., upload successful)
	Error          string     // Error message
	PasswordForURL string     // Password to be embedded in form actions
	Version        string     // App Version

}

// Structure for a directory entry (file or subdirectory)
type DirEntry struct {
	Name        string    // File/directory name
	Path        string    // Full relative path for links (will need ?pw=... appended)
	IsDir       bool      // Is it a directory?
	Size        int64     // Size (for files)
	ModTime     time.Time // Last modification time
	DisplaySize string    // Display size (KB, MB, GB)
}

// Data structure for the info page
type InfoPageData struct {
	Title   string
	Message string
}

func generateRandomPassword(length int) (string, error) {
	const lettersAndDigits = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(lettersAndDigits))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		ret[i] = lettersAndDigits[num.Int64()]
	}
	return string(ret), nil
}

func main() {
	// Add version flag
	showVersion := flag.Bool("version", false, "Show version information")

	// Parse command-line arguments
	flag.StringVar(&config.Host, "H", "0.0.0.0", "IP address for the server to listen on")
	flag.StringVar(&config.Host, "host", "0.0.0.0", "IP address for the server to listen on (alias for -H)")
	flag.StringVar(&config.Port, "p", "8080", "HTTP port for the server to listen on")
	flag.StringVar(&config.Port, "port", "8080", "HTTP port for the server to listen on (alias for -p)")
	flag.StringVar(&config.Password, "pw", "", "Password to access the server (auto-generates if not set)")
	flag.StringVar(&config.Password, "password", "", "Password to access the server (auto-generates if not set, alias for -pw)")
	flag.Int64Var(&config.MaxUploadSizeMB, "max-upload-size", 100, "Maximum allowed upload file size (MB)")
	flag.StringVar(&config.RootDir, "dir", ".", "Root directory to serve files from")
	flag.Parse()

	// Handle version flag
	if *showVersion {
		fmt.Printf("Go Simple File Server v%s\n", version)
		os.Exit(0)
	}

	if config.Password == "" {
		generatedPassword, err := generateRandomPassword(passwordLength)
		if err != nil {
			log.Fatalf("Error: Could not generate random password: %v", err)
		}
		config.Password = generatedPassword
		log.Printf("Password not provided. Auto-generated password: %s", config.Password)
		log.Println("Please use this password by appending '?pw=<password>' to the URL.")
		log.Println("You can set your own password using -pw or --password flag.")
	}

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
	log.Printf("IMPORTANT: Authentication is via URL query parameter '?pw=%s'. This is insecure over HTTP.", config.Password)

	// Initialize templates
	if err := initTemplates(); err != nil {
		log.Fatalf("Error initializing templates: %v", err)
	}

	// Setup router
	mux := http.NewServeMux()
	mux.Handle("/upload", authMiddleware(http.HandlerFunc(handleUpload)))
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

	infoPageTemplate, err = template.New("info").Parse(infoPageHTML)
	if err != nil {
		return fmt.Errorf("error parsing info template: %w", err)
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

// Middleware to check authentication via query parameter
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryPassword := r.URL.Query().Get("pw")

		if queryPassword == config.Password {
			next.ServeHTTP(w, r) // Password matches, proceed
			return
		}

		// Password incorrect or missing
		log.Printf("Auth failed for %s from %s: Password query parameter 'pw' missing or incorrect.", r.RequestURI, r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		infoPageTemplate.Execute(w, InfoPageData{
			Title:   "Unauthorized",
			Message: "Access Denied. Please provide the correct password via the '?pw=<password>' query parameter in the URL.",
		})
	})
}

// Main handler for serving files and listing directories
func fileDirectoryHandler(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("message")
	errorMsg := r.URL.Query().Get("error")
	urlPath := r.URL.Path

	requestedPath := filepath.Join(config.AbsRootDir, urlPath)
	cleanedPath := filepath.Clean(requestedPath)

	if !strings.HasPrefix(cleanedPath, config.AbsRootDir) {
		log.Printf("Path Traversal Warning: Request '%s' (cleaned to '%s') is outside root directory '%s'", urlPath, cleanedPath, config.AbsRootDir)
		http.Error(w, "Access Denied (Path Traversal)", http.StatusForbidden)
		return
	}

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
		CurrentPath:    displayPath,
		Message:        message,
		Error:          errorMsg,
		PasswordForURL: config.Password, // Pass password for form actions
		Version:        version,         // Pass version to template
	}

	if absDirPath != config.AbsRootDir {
		if !strings.HasPrefix(displayPath, "/") {
			displayPath = "/" + displayPath
		}
		parentDisplayPath := filepath.Dir(displayPath)
		if parentDisplayPath == "." {
			parentDisplayPath = "/"
		}
		parentDisplayPath = filepath.Clean(parentDisplayPath)
		if displayPath != "/" {
			data.ParentPath = parentDisplayPath + "?pw=" + config.Password // Append pw to parent link
		}
	}

	for _, entry := range dirEntries {
		info, err := entry.Info()
		if err != nil {
			log.Printf("Error getting info for '%s': %v", entry.Name(), err)
			continue
		}
		entryPath := filepath.Join(displayPath, entry.Name())
		if !strings.HasPrefix(entryPath, "/") {
			entryPath = "/" + entryPath
		}

		// Append ?pw= to all entry paths for navigation
		entryPathWithPw := entryPath + "?pw=" + config.Password

		data.Entries = append(data.Entries, DirEntry{
			Name:        entry.Name(),
			Path:        entryPathWithPw, // Use path with password
			IsDir:       info.IsDir(),
			Size:        info.Size(),
			ModTime:     info.ModTime(),
			DisplaySize: formatFileSize(info.Size()),
		})
	}

	sort.Slice(data.Entries, func(i, j int) bool {
		if data.Entries[i].IsDir != data.Entries[j].IsDir {
			return data.Entries[i].IsDir
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

	maxUploadBytes := config.MaxUploadSizeMB * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)

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

	currentRelativeDir := r.FormValue("current_dir")
	if currentRelativeDir == "" {
		currentRelativeDir = "/"
	}
	currentRelativeDir = filepath.Clean(currentRelativeDir)
	currentRelativeDir = strings.TrimPrefix(currentRelativeDir, "/")

	targetUploadDir := filepath.Join(config.AbsRootDir, currentRelativeDir)
	if !strings.HasPrefix(filepath.Clean(targetUploadDir), config.AbsRootDir) {
		log.Printf("Path Traversal Warning during upload: Target directory '%s' (from current_dir '%s') is outside root directory.", targetUploadDir, currentRelativeDir)
		redirectWithError(w, r, "Error: Invalid upload directory.")
		return
	}
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

	sanitizedFileName := filepath.Base(handler.Filename)
	if sanitizedFileName == "." || sanitizedFileName == ".." || sanitizedFileName == "" {
		log.Printf("Warning: Invalid filename from client: %s", handler.Filename)
		redirectWithError(w, r, "Invalid filename.")
		return
	}

	finalFileName := sanitizedFileName
	counter := 1
	for {
		filePath := filepath.Join(targetUploadDir, finalFileName)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			break
		}
		extension := filepath.Ext(sanitizedFileName)
		nameWithoutExt := strings.TrimSuffix(sanitizedFileName, extension)
		finalFileName = fmt.Sprintf("%s_%d%s", nameWithoutExt, counter, extension)
		counter++
	}

	dstPath := filepath.Join(targetUploadDir, finalFileName)
	dst, err := os.Create(dstPath)
	if err != nil {
		log.Printf("Error creating file '%s': %v", dstPath, err)
		redirectWithError(w, r, "Server error creating file: "+err.Error())
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		log.Printf("Error copying file '%s': %v", dstPath, err)
		os.Remove(dstPath)
		redirectWithError(w, r, "Server error copying file: "+err.Error())
		return
	}

	log.Printf("File '%s' (size %d bytes) uploaded successfully to '%s' by %s", finalFileName, handler.Size, targetUploadDir, r.RemoteAddr)

	redirectPath := "/" + strings.TrimPrefix(currentRelativeDir, "/")
	if redirectPath != "/" && strings.HasSuffix(redirectPath, "/") {
		redirectPath = strings.TrimSuffix(redirectPath, "/")
	}
	if redirectPath == "" {
		redirectPath = "/"
	}
	// Append pw to redirect URL
	http.Redirect(w, r, redirectPath+"?pw="+config.Password+"&message="+template.URLQueryEscaper("File '"+finalFileName+"' uploaded successfully."), http.StatusFound)
}

// Utility function to redirect with an error message
func redirectWithError(w http.ResponseWriter, r *http.Request, errorMsg string) {
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
	// Append pw to redirect URL
	http.Redirect(w, r, redirectPath+"?pw="+config.Password+"&error="+template.URLQueryEscaper(errorMsg), http.StatusFound)
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
// loginPageHTML is no longer used as primary login mechanism
/*
const loginPageHTML = `...`
*/

const infoPageHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: sans-serif; display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 90vh; background-color: #f4f4f4; margin: 20px; text-align: center; }
        .container { background-color: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 600px; }
        h1 { color: #333; margin-bottom: 20px; }
        p { color: #555; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{.Title}}</h1>
        <p>{{.Message}}</p>
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
		/* .logout-link { float: right; font-size: 0.9em; } // Logout link no longer applicable */
    </style>
</head>
<body>
    <div class="container">
		<h1>Simple File Server</h1>
		<div class="version">v{{.Version}}</div>
		<div class="current-path-display">Current directory: <strong>{{.CurrentPath}}</strong></div>
        <p style="font-size:0.8em; color: #666;">(Authenticated with password in URL)</p>


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
            <form action="/upload?pw={{.PasswordForURL}}" method="POST" enctype="multipart/form-data">
                <input type="hidden" name="current_dir" value="{{.CurrentPath}}">
                <input type="file" name="uploaded_file" required>
                <button type="submit">Upload</button>
            </form>
        </div>
    </div>
</body>
</html>
`
