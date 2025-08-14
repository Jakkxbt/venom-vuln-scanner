# CobraStrike
General Vulnerability Scanner

# Installation

git clone https://github.com/yourusername/venom-vuln-scanner.git
cd venom-vuln-scanner
python3 venom_scanner.py --help

usage: cli.py [-h] [-i INPUT] [-u URL] [-o OUTPUT] [--formats FORMATS]
              [--types TYPES] [--threads THREADS] [--timeout TIMEOUT]
              [--rate-limit RATE_LIMIT] [--retries RETRIES] [--config CONFIG]
              [--user-agent USER_AGENT] [--proxy PROXY] [--cookies COOKIES]
              [--verbose] [--debug] [--quiet] [--no-color]
              [--log-file LOG_FILE] [--verify-ssl]
              [--confidence-threshold CONFIDENCE_THRESHOLD] [--list-types]
              [--version] [--update-payloads]

# CobraStrike Enhanced Vulnerability Scanner

options:
  -h, --help            show this help message and exit

Input/Output Options:
  -i INPUT, --input INPUT
                        Input file containing URLs to scan (one per line)
  -u URL, --url URL     Single URL to scan
  -o OUTPUT, --output OUTPUT
                        Output directory for results (default: cobra_results)
  --formats FORMATS     Output formats: json,html,xml,text (default:
                        json,text)

Scan Configuration:
  --types TYPES         Vulnerability types to scan for:
                        xss,lfi,ssrf,rce,redirect,javascript (default: all)
  --threads THREADS     Number of concurrent threads (default: 20)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  --rate-limit RATE_LIMIT
                        Requests per second rate limit (default: 50)
  --retries RETRIES     Number of retry attempts for failed requests (default:
                        3)

Configuration Options:
  --config CONFIG       Path to custom configuration file
  --user-agent USER_AGENT
                        Custom User-Agent string
  --proxy PROXY         HTTP proxy URL (e.g., http://127.0.0.1:8080)
  --cookies COOKIES     Path to cookies file

Output Control:
  --verbose, -v         Enable verbose output
  --debug               Enable debug output
  --quiet, -q           Suppress all output except results
  --no-color            Disable colored output
  --log-file LOG_FILE   Path to log file

Security Options:
  --verify-ssl          Enable SSL certificate verification
  --confidence-threshold CONFIDENCE_THRESHOLD
                        Minimum confidence threshold for reporting (0.0-1.0,
                        default: 0.5)

Utility Options:
  --list-types          List available vulnerability types and exit
  --version             show program's version number and exit
  --update-payloads     Update payload files from repository

Examples:
  cli.py -i urls.txt -o results/
  cli.py -i urls.txt -o results/ --types xss,lfi
  cli.py -i urls.txt -o results/ --threads 50 --timeout 15
  cli.py -i urls.txt -o results/ --config custom_config.yaml
  cli.py -i urls.txt -o results/ --formats json,html
  cli.py --list-types
  cli.py --version

For more information, visit: https://github.com/Jakkxbt/CobraStrike

#Usage:
python3 cobra_recon.py -i urls.txt -o results/
