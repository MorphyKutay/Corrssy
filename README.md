# Corrssy - CORS Vulnerability Scanner

A fast and efficient CORS (Cross-Origin Resource Sharing) vulnerability scanner written in Rust.

## Features

- 🔍 Scans for CORS misconfigurations
- 🌐 Web crawling capability
- ⚡ Parallel request processing
- 🔒 SSL/TLS support with rustls
- 📝 Detailed verbose output mode
- ⏱️ Configurable timeout
- 📋 Support for URL lists from file
- 🎨 Colored output for better readability
- 🔗 Multiple link type detection (a, link, script, img, form)

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

### Crawl Mode

Crawl a website and check all found links for CORS vulnerabilities:
```bash
corrssy -c -u https://example.com
```

Crawl with verbose output:
```bash
corrssy -c -u https://example.com -v
```

### Options

- `-u, --url <URL>`        Target URL to scan
- `-r, --file <file>`      File containing list of URLs
- `-v, --verbose`          Verbose output mode
- `-t, --timeout <sec>`    Timeout in seconds (default: 5)
- `-c, --crawl`            Crawl mode
- `-h, --help`             Show help message

### Examples

Verbose mode with custom timeout:
```bash
corrssy -u https://example.com -v -t 10
```

Crawl mode with verbose output:
```bash
corrssy -c -u https://example.com -v
```

Scan multiple URLs from file with crawl mode:
```bash
corrssy -c -r urls.txt -v
```

## What it Checks

- Access-Control-Allow-Origin header
- Access-Control-Allow-Credentials header
- Access-Control-Allow-Methods header
- Wildcard (*) CORS policies
- Origin validation

## Link Detection

The crawler can detect links from various HTML elements:
- `<a>` tags (href attribute)
- `<link>` tags (CSS, favicon, etc.)
- `<script>` tags (JavaScript files)
- `<img>` tags (Images)
- `<form>` tags (Form actions)

## Output Example

```
Crawling URL: https://example.com
Found 5 unique links to check

Origin: https://evil.com
Access-Control-Allow-Origin found:
  Value: https://evil.com
✅ Origin is properly validated.
```

## Troubleshooting

If you encounter SSL/TLS issues:
1. Try using verbose mode (`-v`) to see detailed error messages
2. Increase the timeout value (`-t`) if the site is slow to respond
3. Try a different URL if the site has bot protection

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
