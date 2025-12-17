<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0.0-orange?style=for-the-badge" alt="Version">
</p>

<h1 align="center">📄 PagePull</h1>

<p align="center">
  <strong>Pull entire websites for offline viewing</strong>
</p>

<p align="center">
  Single-file CLI tool • No installation needed • Works with modern JS frameworks
</p>

---

## 🚀 New in 1.0

- ⚙️ **Parallel asset workers** (`--workers`) for much faster crawls
- 🎯 **Smart filters** to include/exclude asset types, patterns, or sizes
- ♻️ **Incremental refreshes** with conditional requests and caching
- 🕒 **Built-in scheduler** (`--schedule 24h`) for automatic snapshots
- 📦 **Export formats** (`--export zip warc`) for sharing and archiving

---

## ⚡ Quick Start

### One-liner (Download & Run)

```bash
# Download the script
curl -O https://github.com/devkiraa/pagepull/releases/latest/download/pagepull.py

# Install dependencies
pip install requests beautifulsoup4 lxml brotli

# Download a website
python pagepull.py -u https://example.com
```

### Or with Git

```bash
git clone https://github.com/devkiraa/pagepull.git
cd pagepull
pip install -r requirements.txt
python pagepull.py -u https://example.com
```

---

## 📖 Usage

```bash
# Basic download
python pagepull.py -u https://example.com

# Download and preview in browser
python pagepull.py -u https://example.com --serve

# Stealth mode (safer, slower)
python pagepull.py -u https://example.com --stealth

# Custom output folder
python pagepull.py -u https://example.com -o my_backup

# Just serve existing download
python pagepull.py --only-serve -o my_backup
```

---

## 🎯 Options

### Core
| Option | Short | Description |
|--------|-------|-------------|
| `--url` | `-u` | Website URL **(required)** |
| `--output` | `-o` | Output folder (auto-named from domain) |
| `--serve` | `-s` | Start local server after download |
| `--only-serve` | | Just serve an existing folder |
| `--port` | `-p` | Server port (default: 8000) |
| `--no-browser` | | Skip auto-opening the preview |

### Safety & Performance
| Option | Short | Description |
|--------|-------|-------------|
| `--stealth` | | Rotate UAs + random 1-3s delays |
| `--delay` | `-d` | Base delay between requests |
| `--workers` | `-w` | Parallel asset workers (default: 4) |
| `--no-robots` | | Ignore robots.txt (not recommended) |
| `--no-clean` | | Keep previous download even without incremental |
| `--fresh` | | Force full clean before every run |
| `--quiet` | `-q` | Minimal console output |

### Smart Filtering
| Option | Description |
|--------|-------------|
| `--include-types css js image ...` | Only download the listed asset categories |
| `--exclude-types font media ...` | Skip specific categories |
| `--include-pattern <regex>` | Only download assets whose URL matches (repeatable) |
| `--exclude-pattern <regex>` | Skip assets that match (repeatable) |
| `--min-asset-size <KB>` | Skip assets smaller than the threshold |
| `--max-asset-size <KB>` | Skip assets larger than the threshold |

### Incremental, Scheduling & Export
| Option | Description |
|--------|-------------|
| `--no-incremental` | Disable conditional requests/delta updates |
| `--schedule 24h` | Re-run forever every 24 hours (also accepts `30m`, `6h`, etc.) |
| `--max-runs 7` | Stop the scheduler after N runs |
| `--export zip warc` | Produce ZIP archives and WARC bundles |
| `--zip-name backups/mysite.zip` | Custom ZIP destination |
| `--warc-name mysite.warc.gz` | Custom WARC path |

---

## 🛡️ Safety

**Default mode:**
- Respects robots.txt
- 0.3s delays between requests
- Incremental refreshes with conditional requests (304-aware)

**Stealth mode** (`--stealth`):
- Rotates 10 browser user-agents  
- Random 1-3 second delays
- Mimics real browsing

**Incremental caching:**
- Runs keep a `.pagepull/state.json` manifest inside the output folder
- Use `--fresh` to wipe everything before each run
- Use `--no-incremental` when you always want a full re-download

---

## 📋 Requirements

```
Python 3.8+
requests
beautifulsoup4
lxml
brotli
warcio
```

Install all: `pip install -r requirements.txt`

---

## 🔁 Incremental Snapshots

- PagePull stores ETags/Last-Modified headers in `.pagepull/state.json`
- Subsequent runs send conditional requests and skip 304 responses automatically
- Works great for "refresh my mirror" workflows without hammering the origin
- Pass `--no-incremental` (or `--fresh`) if you really want a clean sweep

---

## 🕒 Scheduler Examples

### Built-in loop
```bash
# Pull Example.com every 24h and keep a rolling week of copies
python pagepull.py -u https://example.com --schedule 24h --max-runs 7
```

### Cron (Linux/macOS)
```
0 2 * * * /usr/bin/python3 /opt/pagepull/pagepull.py -u https://example.com -o /data/example_offline --export zip
```

### Windows Task Scheduler (PowerShell)
```
Program/script:  powershell.exe
Add arguments:   -File C:\tools\pagepull.ps1
```

`pagepull.ps1` might contain:
```powershell
python C:\tools\pagepull.py -u https://example.com --export zip --workers 8
```

---

## 📦 Export Formats

| Option | Output |
|--------|--------|
| `--export zip` | Creates `<output>.zip` next to the folder (use `--zip-name backup/site`) |
| `--export warc` | Streams every HTTP response into a WARC file for archival pipelines |

WARC exports use [`warcio`](https://github.com/webrecorder/warcio) under the hood so they can be replayed in Webrecorder, ReplayWeb.page, or any other WARCs toolset.

---

## 📁 What You Get

```
example_com_offline/
├── index.html          # Homepage
├── about.html          # Other pages
├── contact.html
├── assets/             # Images
├── _next/static/       # CSS & fonts
├── .pagepull/state.json # Incremental cache metadata
├── sitemap.html        # Page index
├── _summary.txt        # Download log
├── example_com_offline.zip  # (optional) created when using --export zip
└── example_com_offline.warc.gz # (optional) created when using --export warc
```

---

## 💡 Examples

```bash
# Fast crawl with 8 workers and ZIP export
python pagepull.py -u https://react.dev --workers 8 --export zip

# Only grab HTML/CSS for docs, skip heavy assets
python pagepull.py -u https://docs.example.com --include-types html css --max-asset-size 512

# Respectful nightly snapshot with incremental mode
python pagepull.py -u https://example.com --schedule 24h --max-runs 5

# Serve an existing mirror locally
python pagepull.py --only-serve -o example_com_offline --port 4100
```

---

<p align="center">
  MIT License
</p>
