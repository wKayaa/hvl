# HTTP Grabber Decryption

## Summary
The `http_grabber` binary was encrypted/packed using UPX (Ultimate Packer for eXecutables). This document explains the decryption process and provides the unencrypted version.

## Decryption Process
1. **Identification**: Detected UPX packing by examining binary headers and strings output
2. **Decompression**: Used UPX tool to decompress the binary:
   ```bash
   upx -d http_grabber_unpacked
   ```
3. **Result**: Successfully unpacked from 2,324,316 bytes to 5,589,695 bytes (41.58% compression ratio)

## Unencrypted Binary
- **File**: `http_grabber_unpacked`
- **Type**: ELF 64-bit LSB pie executable, x86-64
- **Status**: Fully functional, dynamically linked
- **Version**: v1.1.1a

## Tool Functionality
The HTTP grabber is a network security scanning tool with the following features:

### Usage
```bash
./http_grabber_unpacked -h <host_file> -p <paths_file> -s <search_file> -o <output_file> -t <threads>
    -H <host_main_send> -P <port_main_send> -v <VIPCODE>
```

### Example
```bash
./http_grabber_unpacked -h ips.txt -p paths.txt -s search.txt -o output.log -v MY_VIP
```

### Parameters
- `-h`: Host file containing IP addresses to scan
- `-p`: Paths file containing URL paths to test
- `-s`: Search file containing patterns to look for
- `-o`: Output file for results
- `-t`: Number of threads (optional)
- `-H`: Main host to send results to (optional)
- `-P`: Port for main host (optional)  
- `-v`: VIP code (required)

### Search Capabilities
The tool supports multiple search modes:
- **normal**: Basic string matching
- **regex**: Regular expression pattern matching
- **regex_first_key**: Advanced key detection with regex

### Input Files
- `ipo.txt` / `iptx.txt`: IP address lists for scanning
- `path.txt`: URL paths to test on each host
- `search.txt`: Search patterns including regex for API keys and secrets

## Technical Details
- Built with C++ using libcurl for HTTP requests
- Uses pthread for multithreading
- Implements regex pattern matching for security key detection
- Contains hardcoded patterns for AWS API keys and other sensitive data

## Security Note
This tool appears to be designed for security testing and vulnerability assessment. Use responsibly and only on systems you own or have explicit permission to test.