# Corrssy - CORS Vulnerability Scanner

A fast and efficient CORS (Cross-Origin Resource Sharing) vulnerability scanner written in Rust.

## Features

- 🔍 Scans for CORS misconfigurations
- ⚡ Parallel request processing
- 🔒 SSL/TLS support with invalid certificate handling
- 📝 Detailed verbose output mode
- ⏱️ Configurable timeout
- 📋 Support for URL lists from file
- 🎨 Colored output for better readability

## Installation

### From Source

1. Clone the repository:
```bash
git clone https://github.com/MorphyKutay/corrssy.git
cd corrssy
```

2. Build the project:
```bash
cargo build --release
```

3. The binary will be available at `target/release/corrssy`

## Usage

### Basic Usage

Scan a single URL:
```bash
corrssy -u https://example.com
```

Scan URLs from a file:
```bash
corrssy -r urls.txt
```

### Options

- `-u, --url <URL>`        Target URL to scan
- `-r, --file <file>`      File containing list of URLs
- `-v, --verbose`          Verbose output mode
- `-t, --timeout <sec>`    Timeout in seconds (default: 5)
- `-h, --help`             Show help message

### Examples

Verbose mode with custom timeout:
```bash
corrssy -u https://example.com -v -t 10
```

Scan multiple URLs from file:
```bash
corrssy --file urls.txt -v
```

## What it Checks

- Access-Control-Allow-Origin header
- Access-Control-Allow-Credentials header
- Access-Control-Allow-Methods header
- Wildcard (*) CORS policies
- Origin validation

## Output Example

```
Scanning URL: https://example.com
Origin: https://evil.com
Access-Control-Allow-Origin found:
  Value: https://evil.com
✅ Origin is properly validated.
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Author

- MorphyKutay

## Acknowledgments

- Thanks to all contributors
- Inspired by various CORS security tools


## Screenshot


![alt text](https://github.com/MorphyKutay/Corrssy/blob/main/corrssy.png)
