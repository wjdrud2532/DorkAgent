# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DorkAgent is a LLM-powered automated Google Dorking tool focused on **Attack Vector Identification** and **Information Disclosure Discovery** for security research, bug bounty hunting, and penetration testing reconnaissance. It uses the CrewAI framework to coordinate multiple AI agents that discover potential security vulnerabilities and exposed sensitive information in target domains.

**Primary Objectives:**
- **Attack Vector Discovery**: Identify URLs with parameters vulnerable to XSS, SQLi, SSRF, LFI, etc.
- **Information Disclosure**: Find exposed sensitive files, documents, configurations, and data

## Installation & Setup

### Package Installation
```bash
# Python 3.11.9 recommended
pip install python-dotenv crewai crewai-tools langchain-openai termcolor prompt-toolkit pyfiglet schedule
```

### Environment Configuration
Create `.env` file with required API keys:
```bash
SERPER_API_KEY=        # Required - https://serper.dev/
OPENAI_API_KEY=        # Optional - set if using OpenAI
ANTHROPIC_API_KEY=     # Optional - set if using Anthropic
GEMINI_API_KEY=        # Optional - set if using Gemini (recommended for free usage)
```

## Common Commands

### Running the Tool
```bash
# Interactive mode
python dorkagent.py

# CLI mode with single target
python dorkagent-cli.py -llm gpt -t example.com -d 1

# CLI mode with target list
python dorkagent-cli.py -llm claude -tl domains.txt -d 2 -notify

# VPS mode for continuous monitoring
python dorkagent-cli.py -llm gemini -t example.com -d 3 -vps 6
```

### Testing & Validation
Since no test framework is configured:
- Manually validate Google Dork queries return expected results
- Test each LLM integration (GPT, Claude, Gemini) separately
- Verify report generation creates proper markdown output in `./log/YYMMDD/`
- Check notification integration with `notify` tool if configured

## Architecture

### Entry Points
- **`dorkagent.py`**: Interactive mode with menu-driven interface
- **`dorkagent-cli.py`**: Command-line interface with argparse support

### Core Components

1. **LLM Integration** (models configured in `select_llm()` and `get_llm()`):
   - OpenAI: GPT-4o-mini (`gpt-4o-mini-2024-07-18`)
   - Anthropic: Claude 3.5 Haiku (`claude-3-5-haiku-20241022`)
   - Google: Gemini 2.0 Flash (`gemini-2.0-flash`)
   - All configured with `max_rpm=15` to avoid rate limits

2. **CrewAI Agents** (defined in `agents()` function):
   - `searcher`: Executes Google Dork queries using SerperDevTool
   - `bughunter`: Analyzes results for vulnerabilities using ScrapeWebsiteTool
   - `writer`: Generates structured security reports
   - All agents use `respect_context_window=True` to handle large results

3. **Search Configuration**:
   - Search depth levels: 1-3 (domain.com, *.domain.com, *.*.domain.com)
   - Results limit: 10-100 per query (configurable in SerperDevTool)
   - Time range: Past month by default (`tbs: "qdr:m"`)

### Google Dork Queries

The tool executes 30 predefined Google Dork queries (defined in `task()` function):

**Attack Vector Discovery Queries (1-15):**
- SQL injection parameters: `inurl:pid`, `inurl:id`, `inurl:uid`
- XSS vulnerable endpoints: `inurl:search`, `inurl:query`, `inurl:page`
- File inclusion vectors: `inurl:file`, `inurl:include`, `inurl:path`
- SSRF parameters: `inurl:url`, `inurl:redirect`, `inurl:return`
- Command execution: `inurl:action`, `inurl:exec`

**Information Disclosure Queries (16-30):**
- Configuration files: `.env`, `config.yml`, `web.config`
- Source code exposure: `.git`, `package.json`, `.gitignore`
- Database dumps: `*.sql`, `*.dump`
- Backup files: `*.bak`, `*.backup`, `*.old`
- Cloud storage: S3 buckets, Azure blobs, GCP storage
- Sensitive documents: Excel files, PDFs with "confidential"
- Directory listings: `intitle:"index of /"`
- Log files: `*.log`, error logs, access logs

### Task Execution Flow

1. **Task 1 (Searcher)**: Executes all 30 Google Dork queries sequentially
   - Documents results even if empty
   - Filters out false positives (demo content, documentation)
   - Returns structured JSON with query results

2. **Task 2 (Bughunter)**: Analyzes discovered URLs for vulnerabilities
   - Categorizes by attack vector type
   - Assesses exploitability (Easy/Medium/Hard)
   - Identifies exposed sensitive information

3. **Task 3 (Writer)**: Generates comprehensive security report
   - Executive summary with risk distribution
   - Attack vector analysis with proof of concept
   - Information disclosure assessment
   - Risk prioritization matrix
   - Manual testing recommendations

## Key Functions

### Core Functions
- `verify_api_key(llm_type)`: Validates required API keys before execution
- `adjust_depth(target_domains, depth)`: Applies subdomain wildcard patterns based on depth selection
- `sanitize_filename(domain)`: Cleans domain names for safe file paths (replaces `*` with `wildcard`)
- `ensure_api_keys(llm_type)`: Interactive prompt for missing API keys (interactive mode only)
- `send_notification(report_path)`: Sends reports via `notify` tool to Telegram

### Environment Management
- `read_env_file(path)`: Loads key-value pairs from .env file
- `write_env_file(path, values)`: Persists API keys to .env file
- `ensure_packages()`: Auto-installs missing Python packages on startup

## Output Structure

Reports are saved with the following structure:
- Directory: `./log/YYMMDD/`
- Interactive mode: `YYMMDD_domain.md`
- VPS mode: `YYMMDD_HHMM_domain.md`
- CLI mode: `YYMMDD_domain.md`

Report sections include:
1. Executive Summary with risk distribution
2. Attack Vector Analysis (AV-001, AV-002, etc.)
3. Information Disclosure Assessment (ID-001, ID-002, etc.)
4. Risk Prioritization Matrix
5. Technical recommendations for manual testing

## Rate Limiting & Performance

- CrewAI configured with `max_rpm=15` to avoid API rate limits
- SerperDevTool default: 10 results per query (max: 100)
- Context window management via `respect_context_window=True`
- LLMContextLengthExceededError handling for large result sets
- Gemini Flash 2.0 recommended for free usage and performance

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

## Development Notes

### CLI Arguments
- `-llm {gpt,claude,gemini}`: LLM type (required)
- `-t TARGET`: Single domain target
- `-tl TARGET_LIST`: File with domain list (one per line)
- `-d {1,2,3}`: Search depth (default: 1)
- `-notify`: Send reports via notify tool
- `-vps HOURS`: VPS mode - run every N hours with notifications
- `-v`: Verbose output

### Customization Points
1. **Search results count**: Modify `n_results` in `site-packages/crewai_tools/tools/serper_dev_tool/`
2. **Search duration**: Change `tbs` parameter in SerperDevTool (`qdr:w` for week, `qdr:m` for month)
3. **Google dorks**: Edit queries in `task()` function
4. **Agent behavior**: Modify agent configurations in `agents()` function

### Error Handling
- Missing API keys trigger interactive prompts or exit with error
- File not found errors for target lists are handled gracefully
- LLM context length errors caught and managed
- Notification failures logged but don't stop execution

### Important Constraints
- Tool identifies potential vulnerabilities - does NOT perform active testing
- Filters exclude documentation, examples, and demo content
- All findings categorized by severity (Critical, High, Medium, Low, Info)
- Reports provide actionable intelligence for manual security testing