# Go Simple File Server

A secure and user-friendly HTTP file server written in Go that provides password protection, file upload capabilities, and directory browsing.

## Features

- 🔒 Password-protected access
- 📁 Directory browsing with clean UI
- ⬆️ File upload support
- 🛡️ Path traversal protection
- 📦 No external dependencies
- 📱 Mobile-friendly interface

## Installation

```bash
git clone https://github.com/sting8k/gosimplefileserver.git
cd gosimplefileserver
go build
```

## Usage

```bash
# Basic usage (password will be auto-generated if not provided)
./gosimplefileserver

# With specific password
./gosimplefileserver -password yourpassword

# Full options example
./gosimplefileserver \
  -host 0.0.0.0 \
  -port 8080 \
  -password yourpassword \
  -max-upload-size 100 \
  -dir /path/to/serve
```

### Command Line Options

- `-host`, `-H`: IP address to listen on (default: "0.0.0.0")
- `-port`, `-p`: HTTP port (default: "8080") 
- `-password`, `-pw`: Access password (auto-generates if not set)
- `-max-upload-size`: Maximum upload file size in MB (default: 100)
- `-dir`: Directory to serve files from (default: current directory)
- `-version`: Show version information

## Security Features

- URL-based password authentication
- Protection against path traversal attacks
- Input validation for uploaded files
- Maximum upload size limit

## Development

### Requirements

- Go 1.20 or higher

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