# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2025-05-25

### Added
- Web crawling capability
- Multiple link type detection (a, link, script, img, form)
- SSL/TLS support with rustls
- Duplicate URL removal
- More detailed verbose output
- HTML content length reporting
- Link list display in verbose mode

### Changed
- Switched from native-tls to rustls for better SSL/TLS support
- Improved error handling and reporting
- Enhanced link detection algorithm
- Updated documentation with new features

### Fixed
- SSL/TLS connection issues on Windows
- Link parsing and normalization
- URL deduplication
- Error message formatting

## [0.1.2] - 2025-05-23

### Added
- More detailed vulnerability reporting
- Color-coded output for vulnerabilities
- Better error messages

### Changed
- Updated output format to show only vulnerabilities in green
- Improved origin validation checks
- Enhanced credentials checking
- Better methods validation

### Fixed
- Output color consistency
- Origin validation logic
- Credentials checking accuracy
- Methods validation precision

## [0.1.1] - 2025-05-23

### Added
- Initial release
- Basic CORS vulnerability scanning functionality
- Support for single URL scanning
- Support for URL list scanning from file
- Parallel request processing
- SSL/TLS support with invalid certificate handling
- Colored output for better readability
- Verbose output mode
- Configurable timeout
- Windows icon support
- GNU GPL-3.0 license

### Changed
- Improved output formatting
- Enhanced vulnerability detection
- Optimized request handling
- Better error handling

### Fixed
- SSL certificate validation issues
- Parallel request handling bugs
- Memory leaks in request processing
- Output formatting inconsistencies 
