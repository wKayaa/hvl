#!/usr/bin/env python3
"""
HTTP Grabber - Standalone version without API/VIPCODE requirement
Scans HTTP endpoints for sensitive data using regex patterns
"""

import argparse
import concurrent.futures
import re
import requests
import sys
import time
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HTTPGrabber:
    def __init__(self, max_threads=10, timeout=10):
        self.max_threads = max_threads
        self.timeout = timeout
        self.session = self._create_session()
        
    def _create_session(self):
        """Create a requests session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set a generic User-Agent
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        return session
    
    def load_file_lines(self, filename):
        """Load lines from a file, removing empty lines and comments"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                lines = []
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Remove line numbers if present (like "1.IP", "2.path")
                        if '.' in line and line.split('.')[0].isdigit():
                            line = '.'.join(line.split('.')[1:])
                        lines.append(line)
                return lines
        except FileNotFoundError:
            logger.error(f"File not found: {filename}")
            return []
        except Exception as e:
            logger.error(f"Error reading file {filename}: {e}")
            return []
    
    def parse_search_patterns(self, search_file):
        """Parse search patterns from file"""
        patterns = []
        lines = self.load_file_lines(search_file)
        
        for line in lines:
            if 'regex:' in line:
                # Extract regex pattern
                regex_part = line.split('regex:')[1].strip()
                try:
                    compiled_pattern = re.compile(regex_part, re.IGNORECASE | re.MULTILINE)
                    patterns.append({
                        'name': line.split('regex:')[0].replace('regex_first_key:', '').strip(),
                        'pattern': compiled_pattern,
                        'raw': regex_part
                    })
                except re.error as e:
                    logger.warning(f"Invalid regex pattern: {regex_part} - {e}")
        
        return patterns
    
    def scan_url(self, base_url, path, patterns):
        """Scan a single URL for patterns"""
        if not base_url.startswith(('http://', 'https://')):
            base_url = f'http://{base_url}'
        
        url = urljoin(base_url, path)
        results = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            content = response.text
            
            for pattern_info in patterns:
                matches = pattern_info['pattern'].findall(content)
                if matches:
                    for match in matches:
                        result = {
                            'url': url,
                            'pattern_name': pattern_info['name'],
                            'match': match if isinstance(match, str) else str(match),
                            'status_code': response.status_code,
                            'content_length': len(content)
                        }
                        results.append(result)
                        logger.info(f"FOUND: {pattern_info['name']} in {url} - {match}")
            
            if not results:
                logger.debug(f"No matches found in {url} (status: {response.status_code})")
                
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout: {url}")
        except requests.exceptions.ConnectionError:
            logger.debug(f"Connection error: {url}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error for {url}: {e}")
        except Exception as e:
            logger.warning(f"Unexpected error for {url}: {e}")
        
        return results
    
    def scan_target(self, args):
        """Scan a single target (host + path combination)"""
        host, paths, patterns = args
        all_results = []
        
        for path in paths:
            results = self.scan_url(host, path, patterns)
            all_results.extend(results)
        
        return all_results
    
    def run_scan(self, hosts_file, paths_file, search_file, output_file):
        """Run the main scanning process"""
        logger.info("Loading input files...")
        
        hosts = self.load_file_lines(hosts_file)
        paths = self.load_file_lines(paths_file)
        patterns = self.parse_search_patterns(search_file)
        
        if not hosts:
            logger.error("No hosts loaded")
            return
        if not paths:
            logger.error("No paths loaded")
            return
        if not patterns:
            logger.error("No search patterns loaded")
            return
        
        logger.info(f"Loaded {len(hosts)} hosts, {len(paths)} paths, {len(patterns)} patterns")
        logger.info(f"Starting scan with {self.max_threads} threads...")
        
        # Prepare arguments for each thread
        scan_args = [(host, paths, patterns) for host in hosts]
        
        all_results = []
        completed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_host = {executor.submit(self.scan_target, arg): arg[0] for arg in scan_args}
            
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                completed += 1
                
                try:
                    results = future.result()
                    all_results.extend(results)
                    logger.info(f"Progress: {completed}/{len(hosts)} hosts completed")
                except Exception as e:
                    logger.warning(f"Error scanning {host}: {e}")
        
        # Write results to output file
        self.write_results(all_results, output_file)
        logger.info(f"Scan completed. Found {len(all_results)} matches. Results written to {output_file}")
    
    def write_results(self, results, output_file):
        """Write results to output file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("URL\tPattern\tMatch\tStatus\tContent-Length\n")
                for result in results:
                    f.write(f"{result['url']}\t{result['pattern_name']}\t{result['match']}\t"
                           f"{result['status_code']}\t{result['content_length']}\n")
        except Exception as e:
            logger.error(f"Error writing results to {output_file}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='HTTP Grabber - Standalone version (no API/VIPCODE required)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -H iptx.txt -p path.txt -s search.txt -o output.log
  %(prog)s --hosts hosts.txt -p paths.txt -s patterns.txt -o results.txt -t 20
        '''
    )
    
    parser.add_argument('--hosts', '-H', required=True, 
                       help='File containing list of hosts/IPs to scan')
    parser.add_argument('-p', '--paths', required=True,
                       help='File containing list of paths to check')
    parser.add_argument('-s', '--search', required=True,
                       help='File containing search patterns (regex)')
    parser.add_argument('-o', '--output', required=True,
                       help='Output file for results')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of threads to use (default: 10)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='HTTP request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    grabber = HTTPGrabber(max_threads=args.threads, timeout=args.timeout)
    grabber.run_scan(args.hosts, args.paths, args.search, args.output)

if __name__ == '__main__':
    main()