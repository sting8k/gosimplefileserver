# Go Simple File Server

A secure and user-friendly HTTP file server written in Go that provides password protection, file upload capabilities, and directory browsing.

## Features

- 🔒 Password-protected access
- 📁 Directory browsing with clean UI
- ⬆️ File upload support
- 🔐 Session-based authentication
- 🛡️ Path traversal protection
- 📦 No external dependencies
- 📱 Mobile-friendly interface

## Installation

```bash
git clone https://github.com/yourusername/gosimplefileserver.git
cd gosimplefileserver
go build
```

## Usage

```bash
# Basic usage with required password
./gosimplefileserver -password yourpassword

# Full options example
./gosimplefileserver \
  -host 0.0.0.0 \
  -port 8080 \
  -password yourpassword \
  -dir /path/to/serve \
  -max-upload-size 100
```

### Command Line Options

- `-host`, `-H`: IP address to listen on (default: "0.0.0.0")
- `-port`, `-p`: HTTP port (default: "8080")
- `-password`, `-pw`: Access password (required)
- `-dir`: Root directory to serve (default: current directory)
- `-max-upload-size`: Maximum upload file size in MB (default: 100)

## Security Features

- Session-based authentication using HMAC
- Protection against path traversal attacks
- Secure cookie handling with HttpOnly flag
- Input sanitization for uploaded filenames
- Maximum upload size limit

## Browser Support

The web interface is compatible with all modern browsers and is responsive for mobile devices.

## Development

### Requirements

- Go 1.24.3 or higher

### Running Tests

```bash
go test -v
```

## License

MIT License - feel free to use this project as you wish.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Disclaimer

This server is intended for private networks and development purposes. For production environments, consider adding HTTPS support and additional security measures.