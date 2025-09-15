#!/usr/bin/env python3
"""
Example usage script for HTTP Grabber
This demonstrates how to use the tool programmatically
"""

import subprocess
import os
import tempfile

def create_example_files():
    """Create example input files for demonstration"""
    
    # Example hosts - using public testing services
    hosts_content = """httpbin.org
jsonplaceholder.typicode.com
postman-echo.com"""
    
    # Example paths - common endpoints that might contain sensitive info
    paths_content = """/
/robots.txt
/.env
/config.json
/api/status
/health
/info"""
    
    # Example search patterns - looking for common sensitive patterns
    search_content = """api_key:API_KEY regex:api[_-]?key[^\w]*[:=][^\w]*['"]*([a-zA-Z0-9_-]{16,})
password:PASSWORD regex:password[^\w]*[:=][^\w]*['"]*([^'"\s]{6,})
email:EMAIL regex:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
secret:SECRET regex:secret[^\w]*[:=][^\w]*['"]*([^'"\s]{8,})
token:TOKEN regex:token[^\w]*[:=][^\w]*['"]*([a-zA-Z0-9_-]{16,})"""
    
    # Write example files
    with open('example_hosts.txt', 'w') as f:
        f.write(hosts_content)
    
    with open('example_paths.txt', 'w') as f:
        f.write(paths_content)
    
    with open('example_search.txt', 'w') as f:
        f.write(search_content)
    
    print("✓ Created example input files:")
    print("  - example_hosts.txt")
    print("  - example_paths.txt") 
    print("  - example_search.txt")

def run_example_scan():
    """Run an example scan using the created files"""
    
    print("\n🔍 Running example scan...")
    
    cmd = [
        'python3', 'http_grabber.py',
        '-H', 'example_hosts.txt',
        '-p', 'example_paths.txt', 
        '-s', 'example_search.txt',
        '-o', 'example_results.log',
        '-t', '3',
        '--timeout', '10'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✓ Scan completed successfully!")
            print(f"📄 Results saved to: example_results.log")
            
            # Show results summary
            if os.path.exists('example_results.log'):
                with open('example_results.log', 'r') as f:
                    lines = f.readlines()
                    if len(lines) > 1:  # More than just header
                        print(f"🎯 Found {len(lines)-1} matches!")
                        print("\nFirst few results:")
                        for line in lines[:6]:  # Header + first 5 results
                            print(f"  {line.strip()}")
                    else:
                        print("ℹ️  No sensitive data patterns found (this is expected for public APIs)")
        else:
            print(f"❌ Scan failed with return code: {result.returncode}")
            print(f"Error: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("⏰ Scan timed out after 60 seconds")
    except Exception as e:
        print(f"❌ Error running scan: {e}")

def show_comparison():
    """Show comparison between original and new tool"""
    
    print("\n📊 Tool Comparison:")
    print("=" * 50)
    
    comparison = [
        ("Feature", "Original Binary", "Python Version"),
        ("-" * 20, "-" * 15, "-" * 15),
        ("VIPCODE Required", "✅ Yes", "❌ No"),
        ("API Auth Required", "✅ Yes", "❌ No"), 
        ("Open Source", "❌ No", "✅ Yes"),
        ("Modifiable", "❌ No", "✅ Yes"),
        ("Multi-threading", "✅ Yes", "✅ Yes"),
        ("Regex Patterns", "✅ Yes", "✅ Yes"),
        ("Verbose Logging", "❓ Unknown", "✅ Yes"),
        ("Retry Logic", "❓ Unknown", "✅ Yes"),
    ]
    
    # Calculate column widths
    col_widths = [max(len(row[i]) for row in comparison) + 2 for i in range(3)]
    
    for row in comparison:
        print("".join(row[i].ljust(col_widths[i]) for i in range(3)))

def main():
    """Main demonstration function"""
    
    print("🚀 HTTP Grabber - Standalone Version Demo")
    print("=" * 45)
    
    # Check if http_grabber.py exists
    if not os.path.exists('http_grabber.py'):
        print("❌ http_grabber.py not found in current directory")
        return
    
    print("This demo will:")
    print("1. Create example input files")
    print("2. Run a sample scan")
    print("3. Show results")
    print("4. Display tool comparison")
    
    input("\nPress Enter to continue...")
    
    # Create example files
    create_example_files()
    
    # Run example scan
    run_example_scan()
    
    # Show comparison
    show_comparison()
    
    print("\n✨ Demo completed!")
    print("\nTo run your own scan:")
    print("python3 http_grabber.py -H your_hosts.txt -p your_paths.txt -s your_patterns.txt -o results.log")

if __name__ == '__main__':
    main()