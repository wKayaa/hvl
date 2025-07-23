# HTTP Grabber - Python Implementation

This is a free, open-source Python implementation of the HTTP grabber functionality that replaces the encrypted/licensed binary.

## What it does

The HTTP Grabber scans web servers for exposed sensitive information like:
- AWS API keys (AKIA*, ASIA*, etc.)
- SendGrid API keys
- Stripe API keys
- Database connection strings
- Authentication tokens
- And many other sensitive patterns

## Usage

```bash
python3 http_grabber.py --hosts <hosts_file> -p <paths_file> -s <search_file> -o <output_file>
```

### Arguments

- `--hosts`: File containing list of hosts/IPs to scan (one per line)
- `-p, --paths`: File containing list of paths to check (one per line)  
- `-s, --search`: File containing search patterns to look for
- `-o, --output`: Output file for results
- `-t, --threads`: Number of concurrent connections (default: 10)
- `--timeout`: Request timeout in seconds (default: 10)
- `-v, --verbose`: Enable verbose logging

### Example

```bash
python3 http_grabber.py --hosts ipo.txt -p path.txt -s search.txt -o results.log -t 20
```

## File Formats

### Hosts file (ipo.txt, iptx.txt)
```
1.192.168.1.1
2.10.0.0.1
```

### Paths file (path.txt)
```
1./config/database/config.json
2./.env
3./backup/database.sql
```

### Search patterns file (search.txt)
```
1.aws_keys:regex:(?:AKIA|ASIA)[A-Z0-9]{16}
2.passwords:regex:(?i)password[\s]*=[\s]*["\']([^"\']+)
```

## Benefits over the original binary

1. **No license/VIPCODE required** - Completely free to use
2. **Open source** - You can see and modify the code
3. **Cross-platform** - Works on any system with Python
4. **Customizable** - Easy to add new search patterns or modify behavior
5. **Modern async HTTP** - Fast concurrent scanning

## Installation

```bash
pip3 install aiohttp
chmod +x http_grabber.py
```

## Dependencies

- Python 3.7+
- aiohttp library

The script automatically handles:
- Concurrent requests with rate limiting
- Timeout handling
- Error handling for unreachable hosts
- Regex pattern matching
- Detailed result logging