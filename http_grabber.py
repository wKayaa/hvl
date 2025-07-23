#!/usr/bin/env python3
"""
HTTP Grabber - Python implementation
A tool for scanning HTTP endpoints and searching for sensitive information.
This is a free alternative to the compiled http_grabber binary.
"""

import argparse
import asyncio
import aiohttp
import re
import sys
from pathlib import Path
import logging
from urllib.parse import urljoin
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HTTPGrabber:
    def __init__(self, hosts_file, paths_file, search_file, output_file, threads=10, timeout=10):
        self.hosts_file = hosts_file
        self.paths_file = paths_file
        self.search_file = search_file
        self.output_file = output_file
        self.max_concurrent = threads
        self.timeout = timeout
        self.hosts = []
        self.paths = []
        self.search_patterns = []
        self.results = []
        
    def load_files(self):
        """Load hosts, paths, and search patterns from files"""
        try:
            # Load hosts
            with open(self.hosts_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Handle numbered lines like "1.ip.address"
                        if line[0].isdigit() and '.' in line:
                            # Split on first dot if it's a number prefix
                            parts = line.split('.', 1)
                            if parts[0].isdigit():
                                line = parts[1]
                        self.hosts.append(line)
            logger.info(f"Loaded {len(self.hosts)} hosts from {self.hosts_file}")
            
            # Load paths
            with open(self.paths_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Handle numbered lines like "1./path/to/file"
                        if line[0].isdigit() and '.' in line:
                            parts = line.split('.', 1)
                            if parts[0].isdigit():
                                line = parts[1]
                        self.paths.append(line)
            logger.info(f"Loaded {len(self.paths)} paths from {self.paths_file}")
            
            # Load search patterns
            with open(self.search_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Handle numbered lines like "1.name:pattern"
                        if line[0].isdigit() and '.' in line:
                            line = line.split('.', 1)[1]  # Remove number prefix
                        
                        # Parse format: name:pattern or just pattern
                        if ':' in line:
                            parts = line.split(':', 1)
                            if len(parts) == 2:
                                name, pattern = parts
                                self.search_patterns.append({'name': name, 'pattern': pattern})
                        else:
                            self.search_patterns.append({'name': 'unnamed', 'pattern': line})
            logger.info(f"Loaded {len(self.search_patterns)} search patterns from {self.search_file}")
            
        except Exception as e:
            logger.error(f"Error loading files: {e}")
            sys.exit(1)
    
    async def make_request(self, session, url):
        """Make HTTP request to a URL"""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                content = await response.text()
                return {
                    'url': url,
                    'status': response.status,
                    'content': content,
                    'headers': dict(response.headers)
                }
        except asyncio.TimeoutError:
            logger.debug(f"Timeout for {url}")
            return None
        except Exception as e:
            logger.debug(f"Error requesting {url}: {e}")
            return None
    
    def search_content(self, content, url):
        """Search content for sensitive patterns"""
        findings = []
        for pattern_info in self.search_patterns:
            pattern = pattern_info['pattern']
            name = pattern_info['name']
            
            try:
                # Handle regex patterns
                if pattern.startswith('regex:'):
                    regex = pattern[6:]  # Remove 'regex:' prefix
                    matches = re.findall(regex, content, re.IGNORECASE | re.MULTILINE)
                else:
                    # Treat as simple string search
                    if pattern.lower() in content.lower():
                        matches = [pattern]
                    else:
                        matches = []
                
                for match in matches:
                    findings.append({
                        'url': url,
                        'pattern_name': name,
                        'pattern': pattern,
                        'match': match
                    })
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern}': {e}")
                continue
        
        return findings
    
    async def scan_url(self, session, host, path):
        """Scan a single URL"""
        # Construct URL
        if not host.startswith('http'):
            host = f"http://{host}"
        
        url = urljoin(host, path)
        
        # Make request
        response = await self.make_request(session, url)
        if not response:
            return []
        
        # Search for sensitive content
        findings = self.search_content(response['content'], url)
        
        # Add response info to findings
        for finding in findings:
            finding['status_code'] = response['status']
            finding['response_size'] = len(response['content'])
        
        return findings
    
    async def run_scan(self):
        """Run the main scanning process"""
        logger.info("Starting HTTP Grabber scan...")
        
        # Create semaphore for controlling concurrency
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def scan_with_semaphore(session, host, path):
            async with semaphore:
                return await self.scan_url(session, host, path)
        
        # Create session with appropriate headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=5,
            ssl=False
        )
        
        async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
            tasks = []
            
            # Create tasks for all host/path combinations
            for host in self.hosts:
                for path in self.paths:
                    task = scan_with_semaphore(session, host, path)
                    tasks.append(task)
            
            logger.info(f"Created {len(tasks)} scan tasks")
            
            # Execute tasks and collect results
            completed = 0
            for task in asyncio.as_completed(tasks):
                try:
                    findings = await task
                    if findings:
                        self.results.extend(findings)
                    
                    completed += 1
                    if completed % 100 == 0:
                        logger.info(f"Completed {completed}/{len(tasks)} scans, found {len(self.results)} items")
                        
                except Exception as e:
                    logger.error(f"Task failed: {e}")
            
        logger.info(f"Scan completed. Found {len(self.results)} sensitive items.")
    
    def save_results(self):
        """Save results to output file"""
        try:
            with open(self.output_file, 'w') as f:
                f.write("HTTP Grabber Results\n")
                f.write("=" * 50 + "\n\n")
                
                for i, result in enumerate(self.results, 1):
                    f.write(f"[{i}] {result['url']}\n")
                    f.write(f"    Pattern: {result['pattern_name']}\n")
                    f.write(f"    Match: {result['match']}\n")
                    f.write(f"    Status: {result['status_code']}\n")
                    f.write(f"    Size: {result['response_size']} bytes\n")
                    f.write("-" * 50 + "\n")
            
            logger.info(f"Results saved to {self.output_file}")
            
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def run(self):
        """Main execution method"""
        self.load_files()
        
        # Run async scan
        try:
            asyncio.run(self.run_scan())
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
        
        # Save results
        if self.results:
            self.save_results()
        else:
            logger.info("No sensitive information found")

def main():
    parser = argparse.ArgumentParser(
        description="HTTP Grabber - Scan for sensitive information in HTTP responses",
        epilog="Example: python3 http_grabber.py --hosts ips.txt -p paths.txt -s search.txt -o output.log"
    )
    
    parser.add_argument('--hosts', required=True, 
                       help='File containing list of hosts/IPs to scan')
    parser.add_argument('-p', '--paths', required=True,
                       help='File containing list of paths to check')
    parser.add_argument('-s', '--search', required=True,
                       help='File containing search patterns')
    parser.add_argument('-o', '--output', required=True,
                       help='Output file for results')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate input files exist
    for file_path in [args.hosts, args.paths, args.search]:
        if not Path(file_path).exists():
            logger.error(f"File not found: {file_path}")
            sys.exit(1)
    
    # Create and run grabber
    grabber = HTTPGrabber(
        hosts_file=args.hosts,
        paths_file=args.paths,
        search_file=args.search,
        output_file=args.output,
        threads=args.threads,
        timeout=args.timeout
    )
    
    grabber.run()

if __name__ == '__main__':
    main()