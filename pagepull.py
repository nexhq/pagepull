"""
PagePull - Web Recon & Mirror Tool
==================================

A versatile tool for offensive security assessment and website mirroring.
- 🕷️  Mirror full websites for offline analysis
- 🔍  Passive Recon: Extract comments, secrets, emails, and hidden endpoints
- 📂  Asset Gathering: Pull JS/CSS for static analysis

Install:
    pip install requests beautifulsoup4 lxml brotli colorama

Usage:
    pagepull -u https://example.com --recon        Mirror & Scan for secrets
    pagepull -u https://example.com --stealth      Red team safe mode
    pagepull -u https://example.com --proxy ...    Route traffic through proxy

Version: 1.1.0 (Security Edition)
"""

import os
import re
import sys
import json
import random
import shutil
import requests
from urllib.parse import urljoin, urlparse, unquote, parse_qs
from urllib.robotparser import RobotFileParser
from bs4 import BeautifulSoup
from collections import deque
import time
import hashlib
import base64
import argparse
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
from datetime import datetime, timedelta, timezone


# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_CONFIG = {
    'output_dir': 'website_download',
    'delay': 0.3,
    'timeout': 30,
    'respect_robots': True,
    'stealth_mode': False,
    'workers': 4,
}

# User agents pool for rotation (common browsers)
USER_AGENTS = [
    # Chrome on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    # Chrome on Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    # Firefox on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    # Firefox on Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
    # Safari on Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    # Edge on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
]

# Bot-identifying user agent (honest mode)
BOT_USER_AGENT = 'WebsiteDownloader/1.0 (Offline Copy Tool; +https://github.com)'

ASSET_CATEGORY_MAP = {
    'html': {'.html', '.htm'},
    'css': {'.css'},
    'js': {'.js', '.mjs', '.ts'},
    'image': {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.bmp', '.tiff', '.avif'},
    'font': {'.woff2', '.woff', '.ttf', '.eot', '.otf'},
    'media': {'.mp4', '.webm', '.mp3', '.wav', '.ogg', '.mov'},
    'doc': {'.pdf', '.txt', '.xml', '.json'},
}

VALID_ASSET_TYPES = sorted({k for k in ASSET_CATEGORY_MAP} | {'other'})


# ============================================================================
# RECON & SECURITY MODULE
# ============================================================================

class ReconScanner:
    """Security scanner for passive reconnaissance"""
    
    def __init__(self):
        self.findings = {
            'secrets': [],
            'emails': set(),
            'comments': [],
            'subdomains': set(),
            'interesting_files': []
        }
        self.lock = Lock()
        
        # Regex Patterns
        self.patterns = {
            'aws_key': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'google_api': r'AIza[0-9A-Za-z\\-_]{35}',
            'slack_token': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
            'private_key': r'-----BEGIN [A-Z ]+ PRIVATE KEY-----',
            'generic_secret': r'(?i)(api[_-]?key|auth|secret|token|password|pwd)[\s=:"\']{0,5}[a-zA-Z0-9\-_]{20,}',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        }

    def scan_content(self, url, content, content_type='text'):
        """Scan text content for patterns"""
        if not content:
            return

        # Ensure content is string
        if isinstance(content, bytes):
            try:
                text = content.decode('utf-8', errors='ignore')
            except:
                return
        else:
            text = content

        with self.lock:
            # 1. Email Extraction
            emails = re.findall(self.patterns['email'], text)
            for email in emails:
                if not any(x in email.lower() for x in ['.png', '.jpg', '.gif', '.svg', '.webp']): # Reduce false positives
                    self.findings['emails'].add(email)

            # 2. Secret Scanning
            for p_name, pattern in self.patterns.items():
                if p_name == 'email': continue
                matches = re.finditer(pattern, text)
                for match in matches:
                    snippet = text[max(0, match.start()-20):min(len(text), match.end()+20)]
                    self.findings['secrets'].append({
                        'type': p_name,
                        'value': match.group(0)[:5] + "..." + match.group(0)[-3:], # Redact for display
                        'full_match': match.group(0),
                        'snippet': snippet.strip(),
                        'source': url
                    })

            # 3. Comment Extraction
            if 'html' in content_type:
                comments = re.findall(r'<!--(.*?)-->', text, re.DOTALL)
                for comment in comments:
                    clean_comment = comment.strip()
                    if clean_comment and len(clean_comment) > 3:
                        self.findings['comments'].append({
                            'type': 'HTML',
                            'content': clean_comment,
                            'source': url
                        })
            elif 'javascript' in content_type or 'css' in content_type:
                # Single line
                js_comments = re.findall(r'//(.*?)\n', text)
                # Multi line
                js_multiline = re.findall(r'/\*(.*?)\*/', text, re.DOTALL)
                
                for c in js_comments + js_multiline:
                    clean_c = c.strip()
                    # Filter out common license/webpack noise
                    if len(clean_c) > 5 and not any(x in clean_c.lower() for x in ['copyright', 'license', 'webpack', 'sourceMappingURL']):
                        self.findings['comments'].append({
                            'type': 'JS/CSS',
                            'content': clean_c[:200] + ('...' if len(clean_c)>200 else ''),
                            'source': url
                        })

    def generate_report(self, output_dir):
        """Write recon report to disk"""
        report_path = os.path.join(output_dir, '_recon_report.txt')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("🔒 PAGEPULL RECONNAISSANCE REPORT\n")
            f.write("=================================\n\n")
            
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Total Secrets Found: {len(self.findings['secrets'])}\n")
            f.write(f"Total Emails Found: {len(self.findings['emails'])}\n")
            f.write(f"Total Comments Extracted: {len(self.findings['comments'])}\n\n")
            
            if self.findings['secrets']:
                f.write("🚨 POTENTIAL SECRETS\n")
                f.write("-" * 20 + "\n")
                for secret in self.findings['secrets']:
                    f.write(f"[!] Type: {secret['type']}\n")
                    f.write(f"    Source: {secret['source']}\n")
                    f.write(f"    Context: ...{secret['snippet']}...\n\n")
            
            if self.findings['emails']:
                f.write("📧 EMAIL ADDRESSES\n")
                f.write("-" * 20 + "\n")
                for email in sorted(self.findings['emails']):
                    f.write(f"  - {email}\n")
                f.write("\n")
                
            if self.findings['comments']:
                f.write("💬 INTERESTING COMMENTS\n")
                f.write("-" * 20 + "\n")
                # Show top 50 longest comments (likely more interesting)
                sorted_comments = sorted(self.findings['comments'], key=lambda x: len(x['content']), reverse=True)[:50]
                for c in sorted_comments:
                    f.write(f"[{c['type']}] {c['source']}\n")
                    f.write(f"  {c['content']}\n\n")

        return report_path


# ============================================================================
# ROBOTS.TXT HANDLER
# ============================================================================

class RobotsHandler:
    """Handles robots.txt parsing and compliance"""
    
    def __init__(self, base_url, user_agent='*'):
        self.base_url = base_url
        self.user_agent = user_agent
        self.parser = RobotFileParser()
        self.loaded = False
        self.crawl_delay = None
        self.disallowed_paths = []
        self.allow_all = False  # Flag to allow all if no robots.txt
        
    def load(self):
        """Load and parse robots.txt"""
        try:
            parsed = urlparse(self.base_url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            
            response = requests.get(robots_url, timeout=10)
            if response.status_code == 200:
                # Check if we got actual robots.txt content (not HTML error page)
                content_type = response.headers.get('content-type', '').lower()
                content = response.text.strip()
                
                # If it looks like HTML (Next.js returns HTML for 404), treat as no robots.txt
                if '<html' in content.lower() or '<!doctype' in content.lower() or content.startswith('{'):
                    self.loaded = True
                    self.allow_all = True
                    return True
                
                self.parser.parse(content.splitlines())
                self.loaded = True
                
                # Extract crawl delay
                for line in content.splitlines():
                    if line.lower().startswith('crawl-delay:'):
                        try:
                            self.crawl_delay = float(line.split(':')[1].strip())
                        except:
                            pass
                    # Track disallowed paths for reporting
                    if line.lower().startswith('disallow:'):
                        path = line.split(':')[1].strip()
                        if path:
                            self.disallowed_paths.append(path)
                
                return True
            else:
                # No robots.txt or error - assume everything is allowed
                self.loaded = True
                self.allow_all = True
                return True
                
        except Exception as e:
            # If we can't fetch robots.txt, proceed - assume allowed
            self.loaded = True
            self.allow_all = True
            return False
    
    def can_fetch(self, url):
        """Check if URL is allowed by robots.txt"""
        if not self.loaded:
            self.load()
        
        # If no valid robots.txt, allow everything
        if self.allow_all:
            return True
        
        try:
            return self.parser.can_fetch(self.user_agent, url)
        except:
            return True  # If parsing fails, allow access
    
    def get_crawl_delay(self):
        """Get the crawl delay specified in robots.txt"""
        if not self.loaded:
            self.load()
        return self.crawl_delay
    
    def get_report(self):
        """Get a summary of robots.txt rules"""
        if not self.loaded:
            self.load()
        
        report = {
            'loaded': self.loaded,
            'crawl_delay': self.crawl_delay,
            'disallowed_count': len(self.disallowed_paths),
            'disallowed_paths': self.disallowed_paths[:10]  # First 10
        }
        return report


# ============================================================================
# PROGRESS DISPLAY CLASSES
# ============================================================================

class ProgressBar:
    """A simple progress bar for console output"""
    
    def __init__(self, total=100, prefix='Progress', suffix='Complete', length=50, fill='█', empty='░'):
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.fill = fill
        self.empty = empty
        self.current = 0
        self.lock = Lock()
        
    def update(self, current=None, increment=1):
        """Update the progress bar"""
        with self.lock:
            if current is not None:
                self.current = current
            else:
                self.current += increment
            self._display()
    
    def set_total(self, total):
        """Update the total count"""
        with self.lock:
            self.total = total
    
    def _display(self):
        """Display the progress bar"""
        if self.total == 0:
            percent = 100
        else:
            percent = min(100, (self.current / self.total) * 100)
        
        filled_length = int(self.length * self.current // max(1, self.total))
        bar = self.fill * filled_length + self.empty * (self.length - filled_length)
        
        sys.stdout.write(f'\r{self.prefix} |{bar}| {percent:6.1f}% ({self.current}/{self.total}) {self.suffix}')
        sys.stdout.flush()
        
        if self.current >= self.total:
            print()  # New line when complete
    
    def finish(self):
        """Complete the progress bar"""
        with self.lock:
            self.current = self.total
            self._display()


class Spinner:
    """A simple spinner for indeterminate progress"""
    
    def __init__(self, message="Processing"):
        self.message = message
        self.frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.current_frame = 0
        
    def spin(self, extra_info=""):
        """Display next frame of spinner"""
        frame = self.frames[self.current_frame % len(self.frames)]
        self.current_frame += 1
        info = f" - {extra_info}" if extra_info else ""
        sys.stdout.write(f'\r{frame} {self.message}{info}' + ' ' * 20)
        sys.stdout.flush()
        
    def clear(self):
        """Clear the spinner line"""
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()


class AssetFilter:
    """Controls which assets should be downloaded"""

    def __init__(self, include_types=None, exclude_types=None,
                 include_patterns=None, exclude_patterns=None,
                 min_size=None, max_size=None):
        include_types = include_types or []
        exclude_types = exclude_types or []
        self.include_types = {t.lower() for t in include_types}
        self.exclude_types = {t.lower() for t in exclude_types}
        self.min_size = min_size  # In bytes
        self.max_size = max_size  # In bytes
        self.include_patterns = [re.compile(p) for p in include_patterns or []]
        self.exclude_patterns = [re.compile(p) for p in exclude_patterns or []]

    def allows(self, url, category):
        category = category or 'other'
        cat = category.lower()

        if self.include_types and cat not in self.include_types:
            return False
        if cat in self.exclude_types:
            return False

        for pattern in self.exclude_patterns:
            if pattern.search(url):
                return False

        if self.include_patterns:
            return any(pattern.search(url) for pattern in self.include_patterns)

        return True

    def allows_size(self, size_bytes):
        if size_bytes is None:
            return True
        if self.min_size is not None and size_bytes < self.min_size:
            return False
        if self.max_size is not None and size_bytes > self.max_size:
            return False
        return True


class ArchiveRecorder:
    """Optional WARC recorder"""

    def __init__(self, warc_path=None):
        self.warc_path = warc_path
        self.writer = None
        self.file_handle = None
        self.enabled = False
        self.status_cls = None
        if warc_path:
            try:
                from warcio.warcwriter import WARCWriter
                from warcio.statusandheaders import StatusAndHeaders
                self.status_cls = StatusAndHeaders
                self.file_handle = open(warc_path, 'wb')
                self.writer = WARCWriter(self.file_handle, gzip=True)
                self.enabled = True
            except Exception as e:
                print(f"⚠️  WARC export disabled: {e}")
                self.enabled = False

    def record(self, url, response):
        if not self.enabled or not self.writer or response is None:
            return
        try:
            status_line = f"{response.status_code} {response.reason}"
            headers = list(response.headers.items())
            http_headers = self.status_cls(status_line, headers, protocol='HTTP/1.1')
            payload = BytesIO(response.content)
            record = self.writer.create_warc_record(url, 'response', payload=payload, http_headers=http_headers)
            self.writer.write_record(record)
        except Exception as e:
            print(f"⚠️  Failed to write WARC record for {url}: {e}")

    def close(self):
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None


# ============================================================================
# MAIN DOWNLOADER CLASS
# ============================================================================

class WebsiteDownloader:
    def __init__(self, base_url, output_dir="downloaded_site", stealth_mode=False, 
                 respect_robots=True, base_delay=0.3, quiet=False, worker_count=None,
                 asset_filter=None, incremental=True, state_dir=None, export_formats=None,
                 zip_name=None, warc_name=None, recon_mode=False):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.output_dir = output_dir
        self.visited_urls = set()
        self.downloaded_assets = {}  # Maps URL to local path
        self.pages_to_visit = deque()
        self.skipped_urls = []  # URLs skipped due to robots.txt
        
        # Configuration
        self.stealth_mode = stealth_mode
        self.respect_robots = respect_robots
        self.base_delay = base_delay
        self.quiet = quiet
        self.timeout = DEFAULT_CONFIG['timeout']
        self.worker_count = max(1, worker_count or DEFAULT_CONFIG['workers'])
        
        # Recon Module
        self.recon_mode = recon_mode
        self.scanner = ReconScanner() if recon_mode else None
        
        # Setup session
        self.session = requests.Session()
        self._setup_session()
        
        # Setup robots.txt handler
        self.robots = None
        if respect_robots:
            self.robots = RobotsHandler(base_url, self._get_user_agent())
        
        # Asset filtering
        self.asset_filter = asset_filter or AssetFilter()
        self.asset_lock = Lock()
        self.asset_executor = ThreadPoolExecutor(max_workers=self.worker_count)
        
        # Incremental state
        self.incremental = incremental
        self.state_dir = state_dir or os.path.join(self.output_dir, '.pagepull')
        self.state_path = os.path.join(self.state_dir, 'state.json')
        self.state_data = self._load_state() if self.incremental else {}
        self.state_lock = Lock()
        
        # Export options
        self.export_formats = export_formats or []
        self.zip_name = zip_name
        self.warc_name = warc_name
        warc_path = None
        if 'warc' in self.export_formats:
            if warc_name and os.path.isabs(warc_name):
                warc_path = warc_name
            else:
                warc_filename = warc_name or f"{self.domain}.warc.gz"
                warc_path = os.path.join(self.output_dir, warc_filename)
        self.archive = ArchiveRecorder(warc_path)
        
        # Progress tracking
        self.total_pages = 0
        self.processed_pages = 0
        self.total_assets = 0
        self.downloaded_asset_count = 0
        self.page_progress = None
        self.asset_spinner = None
        self.request_count = 0
        
    def _setup_session(self):
        """Setup the requests session with appropriate headers"""
        self.session.headers.update({
            'User-Agent': self._get_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',  # Do Not Track
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

    def _load_state(self):
        if not os.path.exists(self.state_path):
            return {}
        try:
            with open(self.state_path, 'r', encoding='utf-8') as fh:
                return json.load(fh)
        except Exception:
            return {}

    def _save_state(self):
        if not self.incremental:
            return
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            temp_path = self.state_path + '.tmp'
            with open(temp_path, 'w', encoding='utf-8') as fh:
                json.dump(self.state_data, fh, indent=2)
            os.replace(temp_path, self.state_path)
        except Exception as e:
            self._log(f"⚠️  Failed to save incremental state: {e}")

    def _get_conditional_headers(self, url):
        if not self.incremental:
            return {}
        entry = self.state_data.get(url)
        if not entry:
            return {}
        headers = {}
        if entry.get('etag'):
            headers['If-None-Match'] = entry['etag']
        if entry.get('last_modified'):
            headers['If-Modified-Since'] = entry['last_modified']
        return headers

    def _update_state(self, url, response, local_path):
        if not self.incremental or response is None:
            return
        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        metadata = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            'content_type': response.headers.get('Content-Type'),
            'local_path': local_path,
            'timestamp': timestamp
        }
        with self.state_lock:
            self.state_data[url] = metadata
    
    def _get_user_agent(self):
        """Get user agent string based on mode"""
        if self.stealth_mode:
            return random.choice(USER_AGENTS)
        else:
            return USER_AGENTS[0]  # Default Chrome UA
    
    def _rotate_user_agent(self):
        """Rotate to a new random user agent (stealth mode)"""
        if self.stealth_mode:
            new_ua = random.choice(USER_AGENTS)
            self.session.headers['User-Agent'] = new_ua
    
    def _get_delay(self):
        """Get delay before next request"""
        # Check robots.txt crawl-delay first
        if self.robots and self.robots.get_crawl_delay():
            base = max(self.base_delay, self.robots.get_crawl_delay())
        else:
            base = self.base_delay
        
        # Add random component in stealth mode
        if self.stealth_mode:
            return base + random.uniform(0.5, 2.0)
        else:
            return base + random.uniform(0, 0.3)
    
    def _can_fetch(self, url):
        """Check if URL can be fetched (robots.txt compliance)"""
        if not self.respect_robots or not self.robots:
            return True
        
        allowed = self.robots.can_fetch(url)
        if not allowed:
            self.skipped_urls.append(url)
        return allowed
    
    def _log(self, message):
        """Log message if not in quiet mode"""
        if not self.quiet:
            print(message)
        
    def create_directory(self, path):
        """Create directory if it doesn't exist"""
        if not os.path.exists(path):
            os.makedirs(path)
            
    def get_file_extension(self, url, content_type=None):
        """Get file extension from URL or content type"""
        parsed = urlparse(url)
        path = parsed.path
        
        # Check for Next.js image API
        if '/_next/image' in path:
            query = parse_qs(parsed.query)
            if 'url' in query:
                original_url = query['url'][0]
                ext = os.path.splitext(original_url)[1]
                if ext:
                    return ext
        
        ext = os.path.splitext(path)[1]
        if ext and ext.lower() in ['.html', '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.woff', '.woff2', '.ttf', '.eot']:
            return ext
            
        # Fallback to content type
        if content_type:
            type_map = {
                'text/html': '.html',
                'text/css': '.css',
                'application/javascript': '.js',
                'text/javascript': '.js',
                'image/png': '.png',
                'image/jpeg': '.jpg',
                'image/gif': '.gif',
                'image/svg+xml': '.svg',
                'image/webp': '.webp',
                'image/x-icon': '.ico',
                'font/woff': '.woff',
                'font/woff2': '.woff2',
            }
            for mime, extension in type_map.items():
                if mime in content_type:
                    return extension
        
        return ''

    def get_asset_category(self, url, content_type=None):
        ext = os.path.splitext(urlparse(url).path)[1].lower()
        for category, extensions in ASSET_CATEGORY_MAP.items():
            if ext in extensions:
                return category
        if content_type:
            content_type = content_type.lower()
            if 'text/css' in content_type:
                return 'css'
            if 'javascript' in content_type:
                return 'js'
            if 'image/' in content_type:
                return 'image'
            if 'font/' in content_type:
                return 'font'
            if 'audio/' in content_type or 'video/' in content_type:
                return 'media'
        return 'other'
    
    def get_local_path_for_nextjs_image(self, url):
        """Convert Next.js image URL to local file path"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        
        if 'url' in query:
            original_url = unquote(query['url'][0])
            width = query.get('w', [''])[0]
            quality = query.get('q', [''])[0]
            
            # Create a path based on the original image URL
            path = original_url.lstrip('/')
            name, ext = os.path.splitext(path)
            
            # Add width suffix to differentiate sizes
            if width:
                path = f"{name}_w{width}{ext}"
            
            return os.path.join(self.output_dir, path)
        
        return None
            
    def get_local_path(self, url, is_asset=False):
        """Convert URL to local file path"""
        parsed = urlparse(url)
        path = unquote(parsed.path)
        
        # Handle Next.js image API
        if '/_next/image' in path:
            return self.get_local_path_for_nextjs_image(url)
        
        if not path or path == '/':
            path = '/index.html'
        elif not os.path.splitext(path)[1]:
            # No extension, treat as HTML page
            if path.endswith('/'):
                path = path + 'index.html'
            else:
                path = path + '.html'
                
        # Remove leading slash and create full path
        path = path.lstrip('/')
        return os.path.join(self.output_dir, path)
    
    def is_same_domain(self, url):
        """Check if URL belongs to the same domain"""
        parsed = urlparse(url)
        return parsed.netloc == '' or parsed.netloc == self.domain
    
    def normalize_url(self, url, current_url):
        """Normalize and resolve relative URLs"""
        # Handle protocol-relative URLs
        if url.startswith('//'):
            url = 'https:' + url
        
        # Join with base URL for relative paths
        full_url = urljoin(current_url, url)
        
        # Remove fragments
        parsed = urlparse(full_url)
        return parsed._replace(fragment='').geturl()
    
    def download_file(self, url, local_path, category='asset'):
        """Download a file and save it locally"""
        headers = self._get_conditional_headers(url)
        try:
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            # Handle incremental 304
            if response.status_code == 304:
                entry = self.state_data.get(url, {})
                cached = entry.get('local_path')
                if cached and os.path.exists(cached):
                    with self.asset_lock:
                        self.downloaded_assets[url] = cached
                    return True, entry.get('content_type', ''), True
                # Missing file fallback: fetch again without headers
                response = self.session.get(url, timeout=self.timeout)
                response.raise_for_status()
            else:
                response.raise_for_status()

            content_type = response.headers.get('content-type', '')
            category_name = 'page' if category == 'page' else self.get_asset_category(url, content_type)

            if category != 'page' and not self.asset_filter.allows(url, category_name):
                return False, content_type, False

            content = response.content
            if category != 'page' and not self.asset_filter.allows_size(len(content)):
                return False, content_type, False

            # RECON: Scan asset content
            if self.scanner and category in ['js', 'css', 'doc', 'other']:
                self.scanner.scan_content(url, content, content_type)

            self.create_directory(os.path.dirname(local_path))
            with open(local_path, 'wb') as f:
                f.write(content)

            if category != 'page':
                self.downloaded_asset_count += 1
            if self.archive:
                self.archive.record(url, response)
            self._update_state(url, response, local_path)
            if category != 'page':
                with self.asset_lock:
                    self.downloaded_assets[url] = local_path
            return True, content_type, False
        except Exception:
            return False, '', False
    
    def schedule_asset_download(self, url, current_page_url):
        if not url or url.startswith('data:'):
            return None
        return self.asset_executor.submit(self._download_asset_task, url, current_page_url)

    def _download_asset_task(self, url, current_page_url):
        """Download CSS, JS, images, and other assets"""
        if not url or url.startswith('data:'):
            return url
        full_url = self.normalize_url(url, current_page_url)

        if not self.is_same_domain(full_url):
            return url

        with self.asset_lock:
            if full_url in self.downloaded_assets:
                return self.get_relative_path_from_cache(full_url, current_page_url)

        local_path = self.get_local_path(full_url, is_asset=True)
        if local_path is None:
            return url

        success, content_type, _ = self.download_file(full_url, local_path)

        if success:
            with self.asset_lock:
                self.downloaded_assets[full_url] = local_path
            if local_path.endswith('.css'):
                self.process_css_file(local_path, full_url)

        return self.get_relative_path_from_cache(full_url, current_page_url)
    
    def get_relative_path_from_cache(self, asset_url, page_url):
        """Get relative path from page to asset"""
        with self.asset_lock:
            asset_path = self.downloaded_assets.get(asset_url)
        if not asset_path:
            return asset_url
        page_path = self.get_local_path(page_url)
        
        if page_path is None:
            return asset_url
        
        page_dir = os.path.dirname(page_path)
        
        return os.path.relpath(asset_path, page_dir).replace('\\', '/')
    
    def process_css_file(self, css_path, css_url):
        """Process CSS file and download referenced assets (fonts, images)
        Embeds fonts as base64 to avoid CORS issues with file:// protocol"""
        try:
            import base64
            
            with open(css_path, 'r', encoding='utf-8', errors='ignore') as f:
                css_content = f.read()
            
            # Find url() references
            url_pattern = r'url\(["\']?([^"\')\s]+)["\']?\)'
            urls = re.findall(url_pattern, css_content)
            
            for url in urls:
                if url.startswith('data:'):
                    continue
                    
                full_url = self.normalize_url(url, css_url)
                
                if self.is_same_domain(full_url):
                    with self.asset_lock:
                        already_downloaded = full_url in self.downloaded_assets
                    if not already_downloaded:
                        local_path = self.get_local_path(full_url, is_asset=True)
                        if local_path:
                            success, _, _ = self.download_file(full_url, local_path)
                            if success:
                                with self.asset_lock:
                                    self.downloaded_assets[full_url] = local_path
                                
                            # For fonts, embed as base64 to avoid CORS issues
                            if local_path.endswith(('.woff2', '.woff', '.ttf', '.eot')):
                                try:
                                    with open(local_path, 'rb') as font_file:
                                        font_data = base64.b64encode(font_file.read()).decode('utf-8')
                                    
                                    # Determine MIME type
                                    if local_path.endswith('.woff2'):
                                        mime = 'font/woff2'
                                    elif local_path.endswith('.woff'):
                                        mime = 'font/woff'
                                    elif local_path.endswith('.ttf'):
                                        mime = 'font/ttf'
                                    else:
                                        mime = 'application/vnd.ms-fontobject'
                                    
                                    data_uri = f'data:{mime};base64,{font_data}'
                                    css_content = css_content.replace(url, data_uri)
                                except Exception as e:
                                    # Fallback to relative path
                                    relative_path = os.path.relpath(local_path, os.path.dirname(css_path)).replace('\\', '/')
                                    css_content = css_content.replace(url, relative_path)
                            else:
                                # Update CSS content with relative path for non-fonts
                                relative_path = os.path.relpath(local_path, os.path.dirname(css_path)).replace('\\', '/')
                                css_content = css_content.replace(url, relative_path)
            
            # Save updated CSS
            with open(css_path, 'w', encoding='utf-8') as f:
                f.write(css_content)
                
        except Exception as e:
            print(f"  Warning: Could not process CSS file {css_path}: {e}")
    
    def extract_links(self, soup, current_url):
        """Extract all links from the page"""
        links = set()
        
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:') or href.startswith('tel:'):
                continue
                
            full_url = self.normalize_url(href, current_url)
            
            if self.is_same_domain(full_url):
                # Remove query strings for page URLs (not for images)
                if '/_next/image' not in full_url:
                    parsed = urlparse(full_url)
                    clean_url = parsed._replace(query='').geturl()
                    links.add(clean_url)
                else:
                    links.add(full_url)
                
        return links
    
    def download_original_assets(self):
        """Download original assets from /assets folder"""
        
        # List of known asset paths from the website
        asset_paths = [
            '/assets/center-right.png',
            '/assets/center.png',
            '/assets/down.png',
            '/assets/top-left.png',
            '/assets/top-right.png',
            '/assets/center-left.png',
            '/assets/organizations.png',
            '/assets/citizens.png',
            '/assets/CashcrowBin.jpg',
            '/assets/partner-logos/VOLTANT_LOGO.png',
            '/assets/partner-logos/AJCE_LOGO.png',
            '/assets/partner-logos/M_Da_Vendi_LOGO.png',
            '/assets/partner-logos/MassTrans_LOGO.png',
            '/assets/partner-logos/FQ_Lab_LOGO.png',
            '/assets/partner-logos/carbonandwhale.webp',
            '/assets/advisors/vinod-chacko-upscale.webp',
            '/assets/advisors/arjun-pillai.webp',
            '/assets/advisors/sherin-upscale.webp',
        ]
        
        for path in asset_paths:
            url = self.base_url + path
            local_path = os.path.join(self.output_dir, path.lstrip('/'))
            category = self.get_asset_category(url)
            if not self.asset_filter.allows(url, category):
                continue
            
            with self.asset_lock:
                already = url in self.downloaded_assets
            if not already:
                success, _, _ = self.download_file(url, local_path)
                if success:
                    with self.asset_lock:
                        self.downloaded_assets[url] = local_path
    
    def process_page(self, url):
        """Download and process a single page"""
        # Normalize URL for comparison
        parsed = urlparse(url)
        if '/_next/image' not in url:
            compare_url = parsed._replace(query='').geturl()
        else:
            compare_url = url
            
        if compare_url in self.visited_urls:
            return
            
        self.visited_urls.add(compare_url)
        self.processed_pages += 1
        
        # Update progress display
        page_name = urlparse(url).path or '/'
        if self.page_progress:
            self.page_progress.set_total(max(self.total_pages, len(self.pages_to_visit) + self.processed_pages))
            self.page_progress.update(self.processed_pages)
        
        try:
            response = self.session.get(url, headers=self._get_conditional_headers(url), timeout=self.timeout)
            if response.status_code == 304:
                self._log(f"  ↺ Skipped unchanged page: {page_name}")
                return
            response.raise_for_status()
            if self.archive:
                self.archive.record(url, response)
            
            # Check if it's HTML
            content_type = response.headers.get('content-type', '')
            if 'text/html' not in content_type:
                return
            
            # Parse and beautify HTML - use lxml for better handling
            soup = BeautifulSoup(response.content, 'lxml')
            
            # RECON: Scan HTML content
            if self.scanner:
                self.scanner.scan_content(url, response.content, 'text/html')

            asset_tasks = []

            def queue_asset(element, attribute, asset_url):
                future = self.schedule_asset_download(asset_url, url)
                if future:
                    asset_tasks.append((future, element, attribute))
            
            # REMOVE all Next.js/React JavaScript - it won't work statically
            for script in soup.find_all('script'):
                # Keep inline scripts that don't have src (might be useful)
                # But remove any that reference _next or react
                if script.get('src'):
                    script.decompose()
                elif script.string and ('_next' in str(script.string) or 'react' in str(script.string).lower()):
                    script.decompose()
            
            # Remove preload links for fonts (causes CORS issues with file://)
            for link in soup.find_all('link', rel='preload'):
                link.decompose()
            
            # Download and update CSS links (remove crossorigin attribute)
            for link in soup.find_all('link', rel='stylesheet'):
                if link.get('href'):
                    queue_asset(link, 'href', link['href'])
                if link.get('crossorigin'):
                    del link['crossorigin']
            
            # Download and update style tags with @import
            for style in soup.find_all('style'):
                if style.string:
                    import_pattern = r'@import\s+["\']([^"\']+)["\']'
                    imports = re.findall(import_pattern, style.string)
                    new_content = style.string
                    for imp in imports:
                        new_path = self._download_asset_task(imp, url)
                        new_content = new_content.replace(imp, new_path)
                    style.string = new_content
            
            # Download and update images
            for img in soup.find_all('img', src=True):
                src = img['src']
                # Handle Next.js image URLs - convert to original asset path
                if '/_next/image' in src:
                    parsed_src = urlparse(src)
                    query = parse_qs(parsed_src.query)
                    if 'url' in query:
                        original_path = unquote(query['url'][0])
                        # Download original asset
                        original_url = self.base_url + original_path
                        local_path = os.path.join(self.output_dir, original_path.lstrip('/'))
                        
                        with self.asset_lock:
                            already = original_url in self.downloaded_assets
                        if not already:
                            success, _, _ = self.download_file(original_url, local_path)
                            if success:
                                with self.asset_lock:
                                    self.downloaded_assets[original_url] = local_path
                        
                        # Update img src to point to original asset
                        page_path = self.get_local_path(url)
                        page_dir = os.path.dirname(page_path)
                        relative_path = os.path.relpath(local_path, page_dir).replace('\\', '/')
                        img['src'] = relative_path
                else:
                    queue_asset(img, 'src', src)
                
                # Clear srcset since we're using original images
                if img.get('srcset'):
                    del img['srcset']
            
            # Download and update source elements (for picture, video, audio)
            for source in soup.find_all('source', src=True):
                queue_asset(source, 'src', source['src'])
                
            for source in soup.find_all('source', srcset=True):
                srcset = source['srcset']
                # Handle Next.js image URLs in srcset
                if '/_next/image' in srcset:
                    # Extract first URL and convert
                    first_url = srcset.split(',')[0].strip().split()[0]
                    parsed_src = urlparse(first_url)
                    query = parse_qs(parsed_src.query)
                    if 'url' in query:
                        original_path = unquote(query['url'][0])
                        original_url = self.base_url + original_path
                        local_path = os.path.join(self.output_dir, original_path.lstrip('/'))
                        
                        with self.asset_lock:
                            already = original_url in self.downloaded_assets
                        if not already:
                            success, _, _ = self.download_file(original_url, local_path)
                            if success:
                                with self.asset_lock:
                                    self.downloaded_assets[original_url] = local_path
                        
                        page_path = self.get_local_path(url)
                        page_dir = os.path.dirname(page_path)
                        relative_path = os.path.relpath(local_path, page_dir).replace('\\', '/')
                        source['srcset'] = relative_path
                else:
                    first_src = srcset.split()[0]
                    queue_asset(source, 'srcset', first_src)
            
            # Download and update favicon and icons
            for link in soup.find_all('link', rel=True):
                rel = link.get('rel', [])
                if isinstance(rel, str):
                    rel = [rel]
                if any('icon' in r.lower() for r in rel):
                    if link.get('href'):
                        queue_asset(link, 'href', link['href'])
            
            # Resolve queued asset downloads
            for future, element, attribute in asset_tasks:
                if element is None:
                    continue
                try:
                    new_value = future.result()
                    if new_value:
                        element[attribute] = new_value
                except Exception as exc:
                    if not self.quiet:
                        print(f"  ⚠️  Asset download failed: {exc}")

            # Download and update background images in inline styles
            # Also fix opacity:0 and hidden elements so they show without JS
            for elem in soup.find_all(style=True):
                style = elem['style']
                url_pattern = r'url\(["\']?([^"\')\s]+)["\']?\)'
                urls = re.findall(url_pattern, style)
                for asset_url in urls:
                    if not asset_url.startswith('data:'):
                        new_path = self._download_asset_task(asset_url, url)
                        style = style.replace(asset_url, new_path)
                
                # Fix hidden elements - replace opacity:0 with opacity:1
                style = re.sub(r'opacity\s*:\s*0(?![.\d])', 'opacity:1', style)
                # Fix scale transforms that hide elements
                style = re.sub(r'transform\s*:\s*scale\([0-9.]+\)', 'transform:scale(1)', style)
                elem['style'] = style
            
            # Remove preload links with Next.js image API URLs (they won't work locally)
            for link in soup.find_all('link', rel='preload'):
                if link.get('imagesrcset') and '/_next/image' in link.get('imagesrcset', ''):
                    link.decompose()
                    continue
                if link.get('href'):
                    if '/_next/image' in link.get('href', ''):
                        link.decompose()
                        continue
                    queue_asset(link, 'href', link['href'])
            
            # Extract links for crawling
            new_links = self.extract_links(soup, url)
            for link in new_links:
                parsed_link = urlparse(link)
                if '/_next/image' not in link:
                    compare_link = parsed_link._replace(query='').geturl()
                else:
                    compare_link = link
                    
                if compare_link not in self.visited_urls:
                    self.pages_to_visit.append(link)
            
            # Update internal links to point to local files
            for a in soup.find_all('a', href=True):
                href = a['href']
                if not href.startswith('#') and not href.startswith('javascript:') and not href.startswith('mailto:') and not href.startswith('tel:'):
                    full_url = self.normalize_url(href, url)
                    if self.is_same_domain(full_url):
                        local_path = self.get_local_path(full_url)
                        page_path = self.get_local_path(url)
                        if local_path and page_path:
                            relative = os.path.relpath(local_path, os.path.dirname(page_path)).replace('\\', '/')
                            a['href'] = relative
            
            # Add CSS to fix any remaining JS-dependent animations
            style_fix = soup.new_tag('style')
            style_fix.string = '''
                /* Fix for static HTML - show all elements that would be animated by JS */
                [style*="opacity"] { opacity: 1 !important; }
                .transform-gpu { transform: scale(1) !important; }
                [data-nimg] { opacity: 1 !important; }
            '''
            if soup.head:
                soup.head.append(style_fix)
            
            # Beautify and save HTML
            beautified_html = soup.prettify()
            local_path = self.get_local_path(url)
            
            if local_path:
                self.create_directory(os.path.dirname(local_path))
                
                with open(local_path, 'w', encoding='utf-8') as f:
                    f.write(beautified_html)
                self._update_state(url, response, local_path)
                
                # Clear spinner and show success
                # Compact page save message
                page_name = os.path.basename(local_path)
                self._log(f"  ✓ {page_name}")
            
        except Exception as e:
            print(f"  ❌ Failed to process {url}: {e}")
    
    def download(self):
        """Start downloading the website"""
        print()
        print("┌" + "─" * 58 + "┐")
        print("│  📍 Source: " + self.base_url[:44].ljust(44) + " │")
        print("│  📁 Output: " + self.output_dir[:44].ljust(44) + " │")
        
        # Show mode information
        mode_info = []
        if self.stealth_mode:
            mode_info.append("Stealth")
        if self.recon_mode:
            mode_info.append("Recon Scan")
        if self.respect_robots:
            mode_info.append("Robots.txt")
        if mode_info:
            print("│  🛡️  Mode:   " + ', '.join(mode_info).ljust(44) + " │")
        
        print("└" + "─" * 58 + "┘")
        
        # Load and check robots.txt
        if self.respect_robots and self.robots:
            self._log("")
            self._log("🤖 Checking robots.txt...")
            self.robots.load()
            report = self.robots.get_report()
            
            if report['crawl_delay']:
                self._log(f"   ├─ Crawl delay: {report['crawl_delay']}s")
                self.base_delay = max(self.base_delay, report['crawl_delay'])
            
            if report['disallowed_count'] > 0:
                self._log(f"   ├─ Disallowed: {report['disallowed_count']} paths")
                if report['disallowed_paths']:
                    for path in report['disallowed_paths'][:2]:
                        self._log(f"   │  └─ {path}")
                    if report['disallowed_count'] > 2:
                        self._log(f"   │     ... +{report['disallowed_count'] - 2} more")
            
            self._log("   └─ ✓ Ready to crawl")
        
        self.create_directory(self.output_dir)
        self.pages_to_visit.append(self.base_url)
        
        # Initialize progress bar
        self.page_progress = ProgressBar(
            total=1, 
            prefix='  📄 Pages', 
            suffix='', 
            length=30,
            fill='━',
            empty='╌'
        )
        
        self._log("")
        self._log("📥 Downloading...")
        self._log("")
        
        start_time = time.time()
        skipped_urls = []
        request_count = 0
        
        while self.pages_to_visit:
            url = self.pages_to_visit.popleft()
            
            # Check robots.txt before processing
            if not self._can_fetch(url):
                skipped_urls.append(url)
                self._log(f"  ⏭️  Skipped (robots.txt): {url}")
                continue
            
            self.total_pages = len(self.pages_to_visit) + self.processed_pages + 1
            self.process_page(url)
            request_count += 1
            
            # Rotate user-agent periodically in stealth mode
            if self.stealth_mode and request_count % 5 == 0:
                self._rotate_user_agent()
            
            # Use smart delay (respects crawl-delay and adds randomness)
            delay = self._get_delay()
            time.sleep(delay)
        
        # Finish page progress
        if self.page_progress:
            self.page_progress.finish()
        
        # Download original assets
        self._log("")
        self._log("📦 Fetching additional assets...")
        self.asset_spinner = Spinner("  Processing")
        self.download_original_assets()
        if self.asset_spinner:
            self.asset_spinner.clear()
        
        elapsed_time = time.time() - start_time
        
        # Format time nicely
        if elapsed_time >= 60:
            time_str = f"{int(elapsed_time // 60)}m {int(elapsed_time % 60)}s"
        else:
            time_str = f"{elapsed_time:.1f}s"
        
        print()
        print("┌" + "─" * 58 + "┐")
        print("│" + " ✅ Download Complete ".center(58) + "│")
        print("├" + "─" * 58 + "┤")
        print(f"│  📄 Pages:   {len(self.visited_urls):<43} │")
        print(f"│  📦 Assets:  {len(self.downloaded_assets):<43} │")
        if skipped_urls:
            print(f"│  ⏭️  Skipped: {len(skipped_urls):<43} │")
        print(f"│  ⏱️  Time:    {time_str:<43} │")
        print("├" + "─" * 58 + "┤")
        print(f"│  📁 {os.path.abspath(self.output_dir)[:51]:<53} │")
        print("└" + "─" * 58 + "┘")
        
        # Create a summary file (silent)
        self.create_summary(skipped_urls)
        self.create_exports()
        
        # Generate Recon Report
        if self.scanner and self.recon_mode:
            report_path = self.scanner.generate_report(self.output_dir)
            print()
            print("┌" + "─" * 58 + "┐")
            print("│" + " 🚨 Security Report Generated ".center(58) + "│")
            print("├" + "─" * 58 + "┤")
            print(f"│  📄 {os.path.basename(report_path):<52} │")
            print(f"│  🔑 Secrets:  {len(self.scanner.findings['secrets']):<43} │")
            print(f"│  📧 Emails:   {len(self.scanner.findings['emails']):<43} │")
            print("└" + "─" * 58 + "┘")
            
        self._save_state()
        if self.archive:
            self.archive.close()
        if self.asset_executor:
            self.asset_executor.shutdown(wait=True)
        
    def create_summary(self, skipped_urls=None):
        """Create a summary of downloaded content"""
        skipped_urls = skipped_urls or []
        summary_path = os.path.join(self.output_dir, "_summary.txt")
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(f"Download Summary\n")
            f.write(f"================\n\n")
            f.write(f"Source: {self.base_url}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Stealth: {'Yes' if self.stealth_mode else 'No'}\n")
            f.write(f"Robots.txt: {'Yes' if self.respect_robots else 'No'}\n")
            
            f.write(f"\nPages Downloaded ({len(self.visited_urls)}):\n")
            f.write("-" * 40 + "\n")
            for url in sorted(self.visited_urls):
                f.write(f"  {url}\n")
            
            if skipped_urls:
                f.write(f"\nPages Skipped by robots.txt ({len(skipped_urls)}):\n")
                f.write("-" * 40 + "\n")
                for url in sorted(skipped_urls):
                    f.write(f"  {url}\n")
            
            f.write(f"\nAssets Downloaded ({len(self.downloaded_assets)}):\n")
            f.write("-" * 40 + "\n")
            for url in sorted(self.downloaded_assets.keys()):
                f.write(f"  {url}\n")
                f.write(f"    -> {self.downloaded_assets[url]}\n")
        print()

    def create_exports(self):
        """Create optional export artifacts"""
        if 'zip' in self.export_formats:
            base_name = os.path.abspath(self.zip_name or self.output_dir)
            if base_name.lower().endswith('.zip'):
                base_name = base_name[:-4]
            try:
                zip_path = shutil.make_archive(base_name, 'zip', root_dir=self.output_dir)
                self._log(f"🗜️  ZIP archive created: {zip_path}")
            except Exception as e:
                self._log(f"⚠️  Failed to create ZIP archive: {e}")
        if 'warc' in self.export_formats and self.archive and self.archive.enabled:
            self._log(f"📚 WARC archive ready: {self.archive.warc_path}")


# ============================================================================
# HTTP SERVER
# ============================================================================

def serve_website(directory, port=8000, open_browser=True):
    """Start a simple HTTP server to serve the downloaded website"""
    import http.server
    import socketserver
    import webbrowser
    
    # Change to the directory
    original_dir = os.getcwd()
    os.chdir(directory)
    
    # Custom handler to suppress log output
    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Suppress default logging
    
    # Allow reuse of address
    socketserver.TCPServer.allow_reuse_address = True
    
    try:
        with socketserver.TCPServer(("", port), QuietHandler) as httpd:
            url = f"http://localhost:{port}"
            print()
            print("┌" + "─" * 58 + "┐")
            print("│" + " 🌐 Server Running ".center(58) + "│")
            print("├" + "─" * 58 + "┤")
            print(f"│  🔗 {url:<52} │")
            print(f"│  📁 {os.path.basename(directory):<52} │")
            print("├" + "─" * 58 + "┤")
            print("│  Press Ctrl+C to stop                                   │")
            print("└" + "─" * 58 + "┘")
            print()
            
            if open_browser:
                webbrowser.open(url)
            
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n✓ Server stopped")
    except OSError as e:
        print(f"\n✗ Port {port} in use. Try --port <number>")
    finally:
        os.chdir(original_dir)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def create_sitemap(output_dir, pages):
    """Create a simple HTML sitemap of all downloaded pages"""
    sitemap_path = os.path.join(output_dir, "sitemap.html")
    
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sitemap - Downloaded Website</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
        ul { list-style: none; padding: 0; }
        li { margin: 10px 0; }
        a { color: #4CAF50; text-decoration: none; font-size: 18px; }
        a:hover { text-decoration: underline; }
        .meta { color: #666; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>📄 Downloaded Pages</h1>
    <ul>
"""
    
    for page in sorted(pages):
        filename = os.path.basename(page) if page else 'index.html'
        if not filename.endswith('.html'):
            filename += '.html'
        html += f'        <li><a href="{filename}">{filename}</a></li>\n'
    
    html += f"""    </ul>
    <p class="meta">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</body>
</html>"""
    
    with open(sitemap_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return sitemap_path


def parse_interval_string(value):
    if not value:
        return None
    match = re.match(r'^(\d+)\s*([smhd])$', value.strip(), re.IGNORECASE)
    if not match:
        raise ValueError("Use formats like 30m, 2h, 1d")
    amount = int(match.group(1))
    unit = match.group(2).lower()
    multiplier = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[unit]
    return amount * multiplier


def format_interval(seconds):
    if seconds >= 3600:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{int(hours)}h {int(minutes)}m"
    if seconds >= 60:
        minutes = seconds // 60
        seconds = seconds % 60
        return f"{int(minutes)}m {int(seconds)}s"
    return f"{int(seconds)}s"


def kb_to_bytes(value):
    if value is None:
        return None
    return int(value) * 1024


def print_banner():
    """Print the application banner"""
    print()
    print("┌" + "─" * 58 + "┐")
    print("│" + " 📄 PAGEPULL v1.0 ".center(58) + "│")
    print("│" + " Pull websites for offline viewing ".center(58) + "│")
    print("└" + "─" * 58 + "┘")


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog='pagepull',
        description='Pull websites for offline viewing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pagepull -u https://example.com                Download a website
  pagepull -u https://example.com --serve        Download and start server
  pagepull -u https://example.com --stealth      Safe mode with delays
    pagepull -u https://react.dev --workers 8      Parallel asset fetch
    pagepull -u https://example.com --schedule 24h Auto snapshots every day
    pagepull -u https://example.com --export zip   Create a shareable archive
    pagepull --only-serve -o my_site               Serve existing download
        """
    )
    
    # Download options
    parser.add_argument('--url', '-u', type=str, required=False,
                        help='URL to download (required unless --only-serve)')
    parser.add_argument('--output', '-o', type=str, default=None,
                        help='Output directory (default: based on domain)')
    parser.add_argument('--delay', '-d', type=float, default=DEFAULT_CONFIG['delay'],
                        help='Delay between requests in seconds (default: 0.3)')
    parser.add_argument('--no-clean', action='store_true',
                        help='Keep previous download')
    parser.add_argument('--workers', '-w', type=int, default=DEFAULT_CONFIG['workers'],
                        help='Number of parallel asset workers (default: 4)')
    parser.add_argument('--include-types', nargs='+', choices=VALID_ASSET_TYPES,
                        help='Only download these asset types')
    parser.add_argument('--exclude-types', nargs='+', choices=VALID_ASSET_TYPES,
                        help='Skip these asset types')
    parser.add_argument('--include-pattern', action='append', default=[],
                        help='Regex for asset URLs to include')
    parser.add_argument('--exclude-pattern', action='append', default=[],
                        help='Regex for asset URLs to skip')
    parser.add_argument('--min-asset-size', type=int,
                        help='Minimum asset size in KB')
    parser.add_argument('--max-asset-size', type=int,
                        help='Maximum asset size in KB')
    parser.add_argument('--no-incremental', action='store_true',
                        help='Disable incremental updates (always re-download)')
    parser.add_argument('--fresh', action='store_true',
                        help='Force delete existing output before download')
    
    # Safety options
    parser.add_argument('--stealth', action='store_true',
                        help='Stealth mode (random user-agent, longer delays)')
    parser.add_argument('--recon', action='store_true',
                        help='Enable passive reconnaissance scanner (secrets, emails, comments)')
    parser.add_argument('--no-robots', action='store_true',
                        help='Ignore robots.txt (not recommended)')
    
    # Server options
    parser.add_argument('--serve', '-s', action='store_true',
                        help='Start server after download')
    parser.add_argument('--only-serve', action='store_true',
                        help='Only serve existing download, skip download')
    parser.add_argument('--port', '-p', type=int, default=8000,
                        help='Server port (default: 8000)')
    parser.add_argument('--no-browser', action='store_true',
                        help='Don\'t open browser automatically')
    parser.add_argument('--schedule', type=str,
                        help='Run repeatedly, e.g. 24h, 6h, 30m')
    parser.add_argument('--max-runs', type=int, default=0,
                        help='Limit number of scheduled runs (0 = infinite)')
    parser.add_argument('--export', nargs='+', choices=['zip', 'warc'], default=[],
                        help='Create additional export formats after download')
    parser.add_argument('--zip-name', type=str,
                        help='Custom name/path for ZIP archive')
    parser.add_argument('--warc-name', type=str,
                        help='Custom name/path for WARC file')
    
    # Other options
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Minimal output')
    parser.add_argument('--version', '-v', action='version', version='pagepull v1.0.0')
    
    args = parser.parse_args()
    
    # Validate options
    if not args.only_serve and not args.url:
        parser.error("--url is required (or use --only-serve with --output)")
    if args.only_serve and args.schedule:
        parser.error("--schedule cannot be used with --only-serve")
    
    # Auto-generate output dir from domain if not specified
    if args.output:
        output_dir = args.output
    elif args.url:
        domain = urlparse(args.url).netloc.replace('www.', '').replace('.', '_')
        output_dir = f"{domain}_offline"
    else:
        output_dir = DEFAULT_CONFIG['output_dir']
    
    incremental = not args.no_incremental
    export_formats = args.export or []
    asset_filter = AssetFilter(
        include_types=args.include_types,
        exclude_types=args.exclude_types,
        include_patterns=args.include_pattern,
        exclude_patterns=args.exclude_pattern,
        min_size=kb_to_bytes(args.min_asset_size),
        max_size=kb_to_bytes(args.max_asset_size)
    )
    state_dir = os.path.join(output_dir, '.pagepull')
    preserve_existing = args.no_clean or incremental
    if args.fresh:
        preserve_existing = False
    if args.only_serve:
        preserve_existing = True
    clean_once = not preserve_existing
    clean_every_run = args.fresh and not args.only_serve

    # Print banner unless quiet mode
    if not args.quiet:
        print_banner()
    
    def run_download_cycle(force_clean=False):
        nonlocal clean_once
        if args.only_serve:
            return
        should_clean = force_clean or clean_once
        if os.path.exists(output_dir) and should_clean:
            shutil.rmtree(output_dir)
            if not force_clean:
                clean_once = False
        downloader = WebsiteDownloader(
            args.url,
            output_dir,
            stealth_mode=args.stealth,
            respect_robots=not args.no_robots,
            base_delay=args.delay,
            quiet=args.quiet,
            worker_count=args.workers,
            asset_filter=asset_filter,
            incremental=incremental,
            state_dir=state_dir,
            export_formats=export_formats,
            zip_name=args.zip_name,
            warc_name=args.warc_name,
            recon_mode=args.recon
        )
        downloader.download()
        create_sitemap(output_dir, downloader.visited_urls)
        return downloader

    if args.schedule:
        interval_seconds = parse_interval_string(args.schedule)
        runs = 0
        try:
            while True:
                runs += 1
                run_download_cycle(force_clean=clean_every_run)
                if args.max_runs and runs >= args.max_runs:
                    break
                next_run = datetime.now() + timedelta(seconds=interval_seconds)
                if not args.quiet:
                    print(f"\n⏳ Next run at {next_run:%Y-%m-%d %H:%M:%S} ({format_interval(interval_seconds)})")
                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            print("\n⏹️  Scheduler stopped by user")
    else:
        run_download_cycle(force_clean=clean_every_run)
    
    if args.serve or args.only_serve:
        if not os.path.exists(output_dir):
            print(f"\n✗ Directory '{output_dir}' not found.")
            print("  Download first or specify --output")
            sys.exit(1)
        serve_website(output_dir, args.port, not args.no_browser)


if __name__ == "__main__":
    main()