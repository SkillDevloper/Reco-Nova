# Reco-Nova - Recon Automation Framework

```
 ██████╗ ███████╗ ██████╗ ██████╗       ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗      ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
 ██████╔╝█████╗  ██║     ██║   ██║█████╗██╔██╗ ██║██║   ██║██║   ██║███████║
 ██╔══██╗██╔══╝  ██║     ██║   ██║╚════╝██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
 ██║  ██║███████╗╚██████╗╚██████╔╝      ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝       ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
```
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-red?style=for-the-badge&logo=linux&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/For-Bug%20Bounty-orange?style=for-the-badge"/>
</p>

## ⚠️ Project Status: Prototype (v1.1)

This project is currently in **version 1.1** and is considered a **prototype**.

There may be bugs, errors, or incomplete features present in this version.
Please make sure to **verify and test everything carefully** before using it in any production environment.

> 🚧 **Note:** Development is in progress for version v1.2

<video src="ImageVideo/Sample_Video.mp4" controls width="1000"></video>

A powerful **Linux-based command-line reconnaissance tool** designed to automate key phases of bug bounty and penetration testing reconnaissance. **Professional Edition** with enhanced UI and automatic dependency management.

## ✨ Key Features

- **🔍 Wayback URL Collection**: Gather historical URLs from archive services
- **📊 Parameter Extraction**: Extract HTTP query parameters from URLs
- **🌐 Subdomain Enumeration**: Discover subdomains using multiple tools
- **💡 Live Host Detection**: Identify active web hosts
- **⚡ JavaScript Analysis**: Extract endpoints from JavaScript files
- **🔒 Sensitive File Detection**: Scan for exposed sensitive files
- **📸 Screenshot Capture**: Capture screenshots of web assets
- **🎨 Professional CLI Interface**: Beautiful, colorful, and interactive
- **🔄 Automatic Dependency Management**: Auto-install and update dependencies
- **🛡️ Python 3.12+ Compatible**: Latest Python version support
- **📦 Modular Architecture**: Easy to extend and customize

## 🚀 Installation

### Prerequisites

- **Python 3.12+** (required)
- **Linux operating system** (Kali, Ubuntu, Debian recommended)

### ⚡ Quick Start (Recommended)

**No manual installation needed!** Reco-Nova automatically checks and installs dependencies:

```bash
# Clone the repository
git clone https://github.com/SkillDevloper/reco-nova.git
cd reco-nova

# Run any command - dependencies auto-install!
python reco-nova.py --help
```

### 🔧 Manual Installation

If you prefer manual setup:

```bash
# Install Python dependencies
pip install -r requirements.txt

# Check dependencies
python reco-nova.py --check-deps
```

### 🛠️ External Tools (Optional but Recommended)

Enhanced functionality with these tools:

```bash
# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/sensepost/gowitness@latest

# Add Go tools to PATH
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
```

## 🎮 Usage

### 🎯 Interactive Mode (Recommended)

Experience the beautiful professional interface:

```bash
python reco-nova.py -i
```

**Features:**
- 🎨 Colorful menu system
- 📊 Real-time progress feedback
- 🔍 Interactive domain input
- ✨ Professional animations
- 🛡️ Error handling with prompts

### ⚡ Command Line Mode

#### Basic Usage
```bash
python reco-nova.py -d example.com
```

#### Run Full Reconnaissance
```bash
python reco-nova.py -d example.com --full
```

#### Individual Modules
```bash
# Collect Wayback URLs
python reco-nova.py -d example.com --wayback

# Extract Parameters
python reco-nova.py -d example.com --params

# Discover Subdomains
python reco-nova.py -d example.com --subs

# Detect Live Hosts
python reco-nova.py -d example.com --live

# Analyze JavaScript
python reco-nova.py -d example.com --js

# Scan Sensitive Files
python reco-nova.py -d example.com --sensitive

# Capture Screenshots
python reco-nova.py -d example.com --shots
```

#### Output Options
```bash
# Run without saving files (memory only) - Individual modules show results on screen
python reco-nova.py -d example.com --wayback --no-save
python reco-nova.py -d example.com --params --no-save

# Full reconnaissance always saves output (comprehensive reporting)
python reco-nova.py -d example.com --full --no-save  # Note: Will still save output

# Generate reports only (no individual files)
python reco-nova.py -d example.com --full --reports-only

# Basic usage (no specific module) - shows results on screen if --no-save used
python reco-nova.py -d example.com --no-save
```

#### Help Commands
```bash
# Show help
python reco-nova.py -h
python reco-nova.py --help

# Check dependencies
python reco-nova.py --check-deps
```

## 📁 Output Structure

The tool generates organized output in the `output/` directory:

```
output/
├── urls.txt              # Collected URLs
├── parameters.txt        # Extracted parameters
├── subdomains.txt        # Discovered subdomains
├── live_hosts.txt        # Active hosts
├── javascript_files.txt  # JavaScript files found
├── js_endpoints.txt      # Endpoints from JS
├── sensitive_files.txt    # Sensitive files found
├── api_endpoints.txt     # API endpoints
├── screenshots/          # Captured screenshots
└── reports/              # Professional reports
    ├── report_domain.com.json  # JSON report
    └── report_domain.com.html  # HTML report (with CSS)
```

## 📊 Professional Reports

Reco-Nova automatically generates **both JSON and HTML reports** with comprehensive scan results:

### 🎨 HTML Report Features
- **🌈 Beautiful Design**: Modern, responsive interface with gradients
- **📱 Mobile Friendly**: Works on all devices and screen sizes
- **🔍 Interactive Elements**: Hover effects and animations
- **📊 Visual Summary**: Color-coded statistics and metrics
- **⚠️ Risk Highlighting**: Sensitive files marked in red
- **🎯 Professional Layout**: Enterprise-ready presentation

### 📋 Report Contents
- **Scan Summary**: Count of each data type discovered
- **Detailed Results**: Complete lists of all findings
- **Timestamp**: When the scan was performed
- **Domain Information**: Target domain details
- **Risk Assessment**: Highlighted sensitive findings

### 📄 Report Access
```bash
# Reports are automatically generated in:
output/reports/report_<domain>.html
output/reports/report_<domain>.json

# Open HTML report in browser:
# Double-click the .html file or use:
firefox output/reports/report_<domain>.html
```

## 📋 Output Behavior

### 🎯 Smart Output Management

Reco-Nova provides intelligent output management based on the type of reconnaissance:

#### 📊 **Individual Modules - Screen Display**
When using `--no-save` with individual modules, results are displayed on screen:

```bash
$ python reco-nova.py -d example.com --wayback --no-save

[*] Output saving: DISABLED
[*] Starting Wayback URL Collection...
[!] Output saving is disabled. Results will not be saved to files.

============================================================
[*] URLs Results (25 found)
============================================================
[ 1] https://example.com/login
[ 2] https://example.com/admin
[ 3] https://example.com/api/user
...
Total urls: 25
============================================================
```

#### 🔄 **Full Reconnaissance - Always Saves**
Full reconnaissance always saves output for comprehensive reporting:

```bash
$ python reco-nova.py -d example.com --full --no-save

[!] Note: Full reconnaissance always saves output for comprehensive reporting
[*] Output saving: ENABLED
[+] Saved 25 URLs to output/urls.txt
[+] Saved 8 parameters to output/parameters.txt
...
[+] Generated HTML report: output/reports/report_example.com.html
```

#### � **Basic Usage - Smart Display**
Basic usage (no specific module) shows results on screen when `--no-save` is used:

```bash
$ python reco-nova.py -d example.com --no-save

[*] Output saving: DISABLED
[*] Starting Basic Reconnaissance...
[+] Collected 25 URLs (displayed on screen)
[+] Extracted 8 parameters (displayed on screen)
...
```

### 📱 **Interactive Mode - User Choice**
Interactive mode asks users about saving output per operation:

```bash
> Save output to files? (Y/n): n
[*] Output saving: DISABLED
# Results displayed on screen
```

### 🎨 **Screen Display Features**
- 📊 **Formatted Results**: Numbered lists with clear formatting
- 🎯 **First 20 Items**: Shows initial results, then summary
- 📈 **Total Count**: Clear summary of findings
- 🌈 **Color-Coded**: Professional visual presentation
- ⚠️ **Empty Results**: Clear message when no items found

### Visual Design
- **🌈 Color-Coded Output**: Different colors for different message types
- **📊 Professional ASCII Art**: Beautiful banners and headers
- **🎯 Interactive Menus**: User-friendly selection system
- **✨ Progress Indicators**: Real-time operation feedback

### User Experience
- **🔄 Auto-Dependency Management**: No manual setup required
- **🛡️ Error Handling**: Graceful error recovery with helpful messages
- **📝 Clear Logging**: Structured logs with timestamps
- **🎮 Intuitive Navigation**: Easy-to-use interactive mode

### Cross-Platform Compatibility
- **💻 Windows Support**: Full compatibility with Windows terminals
- **🐧 Linux Optimized**: Best performance on Linux systems
- **⚡ Fast Startup**: Quick dependency checking and loading

## Module Descriptions

### Wayback URL Collection
Collects historical URLs from the Wayback Machine API and filters for relevant web endpoints.

### Parameter Extraction
Analyzes collected URLs to extract unique HTTP query parameters for testing.

### Subdomain Enumeration
Uses multiple tools (subfinder, assetfinder) to discover subdomains related to the target domain.

### Live Host Detection
Checks discovered subdomains to identify which hosts are actively responding.

### JavaScript Analysis
- Discovers JavaScript files from URLs and live hosts
- Extracts API endpoints and hidden paths from JavaScript code
- Identifies potential attack surfaces

### Sensitive File Detection
Scans live hosts for commonly exposed sensitive files like configuration files, backups, and credentials.

### Screenshot Capture
Takes screenshots of live web assets for visual reconnaissance and documentation.

## 📸 Examples

### Full Reconnaissance Example
![Interface1](/ImageVideo/Interface%201.jpg)

### Interactive Mode Example
![Interface1](/ImageVideo/Interface%202.jpg)

## 📝 Logging & Troubleshooting

### Automatic Logging
Logs are automatically generated in the `logs/` directory with timestamps for debugging and audit purposes:

```
logs/
├── recon_20260310_123456.log    # Timestamped session logs
└── recon_20260310_234567.log    # Multiple session support
```

### Common Issues & Solutions

#### 🔧 Dependency Issues
```bash
# Check if dependencies are properly installed
python reco-nova.py --check-deps

# Manual installation if auto-install fails
pip install -r requirements.txt
```

#### 🐍 Python Version Issues
```bash
# Check Python version (requires 3.12+)
python --version

# Upgrade Python if needed
# On Ubuntu/Debian:
sudo apt update && sudo apt install python3.12

# On Kali Linux:
sudo apt update && sudo apt install python3.12
```

#### 🛠️ External Tool Issues
```bash
# Check if Go is installed
go version

# Install Go if missing
# On Ubuntu/Debian:
sudo apt install golang-go

# On Kali Linux:
sudo apt install golang-go
```

#### 🖥️ Windows Compatibility
- Use PowerShell or Command Prompt
- Ensure Python is in PATH
- Run as Administrator if needed

### 🔍 Debug Mode
For detailed debugging, check the log files:
```bash
# View latest log
tail -f logs/recon_$(date +%Y%m%d)_*.log

# Or check all logs
ls -la logs/
```

## Security and Ethics

- Only scan domains you have permission to test
- Focus on passive reconnaissance techniques
- Respect robots.txt and rate limits
- Use responsibly and ethically

## 📋 Changelog

### Version 1.2 - Professional Edition
- ✨ **New Professional CLI Interface** - Beautiful, colorful, and interactive
- 🔄 **Automatic Dependency Management** - Auto-install and update dependencies
- 🛡️ **Python 3.12+ Support** - Latest Python version compatibility
- 🎨 **Enhanced Visual Design** - Professional ASCII art and color schemes
- 📝 **Improved Error Handling** - Graceful error recovery
- 🔍 **Better Logging System** - Structured logs with timestamps
- ⚡ **Performance Optimizations** - Faster startup and execution

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Developer

Developed by **Daniyal Shahid**

---

## ⚠️ Disclaimer

**This tool is intended for authorized security testing only.** Users are responsible for ensuring they have proper authorization before scanning any targets. The developers are not responsible for misuse of this tool.

### 🛡️ Ethical Usage Guidelines

- ✅ **Only scan domains you own or have explicit permission to test**
- ✅ **Focus on passive reconnaissance techniques**
- ✅ **Respect robots.txt and rate limits**
- ✅ **Use responsibly and ethically**
- ❌ **Do not use for malicious purposes**
- ❌ **Do not scan targets without authorization**

---

**🎯 Thank you for using Reco-Nova - Professional Reconnaissance Automation!**
