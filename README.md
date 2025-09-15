# HTTP Grabber - Standalone Version

This is a standalone Python implementation of the HTTP grabber tool that doesn't require a VIPCODE or API authentication. It scans HTTP endpoints for sensitive data using regex patterns.

## Features

- **No API/VIPCODE required**: Works completely offline without external authentication
- **Multi-threaded scanning**: Configurable number of concurrent threads
- **Regex pattern matching**: Flexible pattern matching for sensitive data detection
- **Timeout handling**: Configurable request timeouts with retry logic
- **Comprehensive logging**: Detailed logging with debug mode support
- **CSV output**: Results are saved in a tab-separated format for easy analysis

## Installation

The tool requires Python 3.6+ and the following dependencies:

```bash
pip install requests
```

## Usage

### Basic Usage

```bash
python3 http_grabber.py -H hosts.txt -p paths.txt -s search.txt -o output.log
```

### Advanced Usage

```bash
python3 http_grabber.py \
    --hosts iptx.txt \
    --paths path.txt \
    --search search.txt \
    --output results.log \
    --threads 20 \
    --timeout 10 \
    --verbose
```

### Command Line Options

- `-H, --hosts`: File containing list of hosts/IPs to scan (required)
- `-p, --paths`: File containing list of paths to check (required)
- `-s, --search`: File containing search patterns (regex) (required)
- `-o, --output`: Output file for results (required)
- `-t, --threads`: Number of threads to use (default: 10)
- `--timeout`: HTTP request timeout in seconds (default: 10)
- `-v, --verbose`: Enable verbose logging
- `-h, --help`: Show help message

## File Formats

### Hosts File (hosts.txt)
One IP address or hostname per line:
```
192.168.1.1
example.com
10.0.0.1
```

Note: If your file has numbered lines like `1.192.168.1.1`, the tool will automatically strip the line numbers.

### Paths File (paths.txt)
One URL path per line:
```
/config/database.yml
/.env
/admin/config.php
/api/v1/users
```

### Search Patterns File (search.txt)
Regex patterns in the format `pattern_name:label regex:pattern`:
```
aws_key:AWS_ACCESS_KEY regex:(?:^|[^A-Z0-9])AKIA[A-Z0-9]{16}
api_key:API_KEY regex:api[_-]?key[^\w]*[:=][^\w]*['"]*([^'"\s]+)
password:PASSWORD regex:password[^\w]*[:=][^\w]*['"]*([^'"\s]+)
```

## Output Format

Results are saved in a tab-separated format with the following columns:
- URL: The full URL that was scanned
- Pattern: The name of the matching pattern
- Match: The actual matched text
- Status: HTTP status code
- Content-Length: Size of the response content

Example output:
```
URL	Pattern	Match	Status	Content-Length
http://example.com/.env	api_key	sk_live_abc123def456	200	1024
http://example.com/config.php	password	mypassword123	200	512
```

## Comparison with Original Binary

| Feature | Original Binary | Python Version |
|---------|----------------|----------------|
| VIPCODE Required | ✅ Yes | ❌ No |
| API Authentication | ✅ Yes | ❌ No |
| Multi-threading | ✅ Yes | ✅ Yes |
| Regex Patterns | ✅ Yes | ✅ Yes |
| Timeout Handling | ✅ Yes | ✅ Yes |
| Retry Logic | ❓ Unknown | ✅ Yes |
| Verbose Logging | ❓ Unknown | ✅ Yes |
| Open Source | ❌ No | ✅ Yes |
| Modifiable | ❌ No | ✅ Yes |

## Security Considerations

- This tool is designed for authorized security testing only
- Always ensure you have permission to scan target systems
- Be mindful of rate limiting and server load
- Review and understand the regex patterns before use
- Handle sensitive data found during scans appropriately

## Example Run

```bash
$ python3 http_grabber.py -H iptx.txt -p path.txt -s search.txt -o results.log -t 10 -v

2025-09-15 03:40:05,083 - INFO - Loading input files...
2025-09-15 03:40:05,090 - INFO - Loaded 1000 hosts, 12131 paths, 1 patterns
2025-09-15 03:40:05,090 - INFO - Starting scan with 10 threads...
2025-09-15 03:40:15,123 - INFO - FOUND: aws_key in http://192.168.1.100/.env - AKIAIOSFODNN7EXAMPLE
2025-09-15 03:40:25,156 - INFO - Progress: 100/1000 hosts completed
...
2025-09-15 03:45:30,789 - INFO - Scan completed. Found 25 matches. Results written to results.log
```

## License

This tool is provided as-is for educational and authorized security testing purposes.