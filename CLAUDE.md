# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DorkAgent is a LLM-powered automated Google Dorking tool focused on **Attack Vector Identification** and **Information Disclosure Discovery** for security research, bug bounty hunting, and penetration testing reconnaissance. It uses the CrewAI framework to coordinate multiple AI agents that discover potential security vulnerabilities and exposed sensitive information in target domains.

**Primary Objectives:**
- **Attack Vector Discovery**: Identify URLs with parameters vulnerable to XSS, SQLi, SSRF, LFI, etc.
- **Information Disclosure**: Find exposed sensitive files, documents, configurations, and data

## Architecture

The codebase consists of two main entry points:

- **`dorkagent.py`**: Interactive mode with menu-driven interface
- **`dorkagent-cli.py`**: Command-line interface with argparse support

### Core Components

1. **LLM Integration**: Supports OpenAI GPT-4o-mini, Anthropic Claude 3.5 Haiku, and Google Gemini 2.0 Flash
2. **CrewAI Agents**:
   - `searcher`: Executes Google Dork queries using SerperDevTool
   - `bughunter`: Analyzes results for vulnerabilities using ScrapeWebsiteTool  
   - `writer`: Generates security reports
3. **Search Depth**: Supports 1-3 levels (domain.com, *.domain.com, *.*.domain.com)
4. **Notification**: Integration with `notify` tool for Telegram reporting

### Google Dorks

The tool executes 30 predefined Google Dork queries targeting:

**Attack Vector Discovery:**
- Parameter injection points (XSS, SQLi, SSRF vulnerable URLs)
- File inclusion vectors (LFI/RFI opportunities)
- Open redirect parameters
- Command execution endpoints
- Admin panels and authentication bypasses

**Information Disclosure Discovery:**
- Sensitive file exposure (.env, config files, backups, logs)
- Directory listings and exposed source code
- API endpoints and authentication tokens  
- Database dumps and private documents
- Cloud storage misconfigurations (AWS S3, Azure Blob, GCP)
- PII exposure (employee data, credentials, keys)
- Development environment information

## Environment Setup

Required API keys in `.env` file:
- `SERPER_API_KEY` (required for Google searches)
- At least one LLM API key: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY`

## Running the Tool

### Interactive Mode
```bash
python dorkagent.py
```

### CLI Mode
```bash
python dorkagent-cli.py -llm gpt -t example.com -d 1
python dorkagent-cli.py -llm claude -tl domains.txt -d 2 -notify
python dorkagent-cli.py -llm gemini -t example.com -d 3 -vps 6
```

### Command Arguments (CLI)
- `-llm {gpt,claude,gemini}`: LLM type (required)
- `-t TARGET`: Single domain target
- `-tl TARGET_LIST`: File with domain list
- `-d {1,2,3}`: Search depth (default: 1)
- `-notify`: Send reports via notify tool
- `-vps HOURS`: VPS mode - run every N hours with notifications
- `-v`: Verbose output

## Output Structure

Reports are saved to `./log/YYMMDD/` with format:
- Interactive: `YYMMDD_domain.md`
- VPS mode: `YYMMDD_HHMM_domain.md`

## Key Functions

- `verify_api_key()`: Validates required API keys
- `adjust_depth()`: Applies subdomain wildcard patterns
- `sanitize_filename()`: Cleans domain names for file paths
- `agents()`: Creates CrewAI agent instances
- `task()`: Defines the 30 Google Dork queries and analysis tasks
- `send_notification()`: Handles Telegram notifications via notify tool

## Rate Limiting

- CrewAI configured with `max_rpm=15` to avoid API rate limits
- Gemini Flash 2.0 recommended for free usage and performance

## Development Notes

- **Discovery Focus**: Tool identifies potential attack vectors and information disclosure - does NOT perform active testing or exploitation
- Target domain files should contain one domain per line
- The tool filters out example/demo content to reduce false positives
- All findings are categorized by severity (Critical, High, Medium, Low) based on exposure risk
- VPS mode enables continuous monitoring with scheduled execution
- Reports provide actionable intelligence for manual security testing

## Security Research Applications

**Attack Vector Identification:**
- Find URLs with parameters suitable for manual XSS/SQLi testing
- Discover file inclusion opportunities for LFI/RFI testing  
- Locate redirect parameters for open redirect testing
- Identify admin panels for authorization bypass testing

**Information Disclosure Discovery:**
- Exposed configuration files with credentials
- Leaked source code and proprietary documents
- Directory listings revealing application structure
- Cloud storage buckets with sensitive data
- Employee information for social engineering research