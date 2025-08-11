# DorkAgent
🤖 LLM-powered agent for automated Google Dorking in bug hunting &amp; pentesting.

<img src="banner.gif" alt="banner" width="1000">                   
                                                                                                    
## Usage
1. Git clone
```bash
> git clone https://github.com/yee-yore/DorkAgent.git
```

2. Install packages
```bash
# python version = 3.11.9
> pip install -r requirements.txt
or
> pip install python-dotenv crewai crewai-tools langchain-openai termcolor prompt-toolkit pyfiglet schedule
```

3. Configure API keys in the `.env` file  
- `SERPER_API_KEY` is **required**  
- You must set at least **one** LLM API key (e.g., OpenAI, Anthropic, or Gemini) depending on your preference  
- You can also integrate other LLMs: https://docs.crewai.com/concepts/llms
```bash
SERPER_API_KEY=        # Required - https://serper.dev/
OPENAI_API_KEY=        # Optional - set if using OpenAI
ANTHROPIC_API_KEY=     # Optional - set if using Anthropic
GEMINI_API_KEY=        # Optional - set if using Gemini (recommended)
```

4. Run DorkAgent
**Interactive Mode:**
```bash
> python dorkagent.py
```

**CLI Mode:**
```bash
> python dorkagent-cli.py -h  # See all options
> python dorkagent-cli.py -llm gpt -t example.com -d 1
```

For more description
https://medium.com/@yee-yore/llm-powered-agent-for-automated-google-dorking-dcb14d609dc2

## CLI Usage

The CLI version (`dorkagent-cli.py`) provides command-line interface for automated workflows and scripting.

**Help Message:**
```bash
> python dorkagent-cli.py -h

usage: dorkagent-cli.py [-h] -llm {gpt,claude,gemini} (-t TARGET | -tl TARGET_LIST) 
                        [-d {1,2,3}] [-notify] [-vps HOURS] [-v]

DorkAgent - LLM-powered Google Dorking tool for bug hunting & pentesting

options:
  -h, --help            show this help message and exit
  -llm {gpt,claude,gemini}, --llm-type {gpt,claude,gemini}
                        LLM type to use (gpt/claude/gemini)
  -t TARGET, --target TARGET
                        Single target domain (e.g., example.com)
  -tl TARGET_LIST, --target-list TARGET_LIST
                        Path to file containing list of target domains
  -d {1,2,3}, --depth {1,2,3}
                        Search depth: 1=target.com, 2=*.target.com, 3=*.*.target.com (default: 1)
  -notify, --notify     Send report via notify tool
  -vps HOURS, --vps HOURS
                        VPS mode: Run periodically every N hours and send results via telegram
  -v, --verbose         Enable verbose output
```

**Usage Examples:**
```bash
# Single domain scan
python dorkagent-cli.py -llm gpt -t example.com -d 1

# Multiple domains with notification
python dorkagent-cli.py -llm claude -tl domains.txt -d 2 -notify

# Deep scan with verbose output  
python dorkagent-cli.py -llm gemini -t subdomain.example.com -d 3 -notify -v

# VPS mode - continuous monitoring every hour
python dorkagent-cli.py -llm gpt -tl domains.txt -d 1 -vps 1

# VPS mode - scan every 6 hours
python dorkagent-cli.py -llm claude -t example.com -d 2 -vps 6
```

**CLI Parameters:**
- `-llm`: Choose LLM provider (gpt/claude/gemini) 
- `-t`: Single target domain
- `-tl`: File with domain list (one per line)
- `-d`: Search depth (1=domain.com, 2=*.domain.com, 3=*.*.domain.com)
- `-notify`: Send results via notify tool (Telegram integration)
- `-vps`: VPS mode - run every N hours with automatic notifications
- `-v`: Verbose output for debugging

## Customize
1. The number of google results (`serper_dev_tool.py` inside `site-packages/crewai_tools/tools/serper_dev_tool/`)
```bash
class SerperDevTool(BaseTool):
    ...
    args_schema: Type[BaseModel] = SerperDevToolSchema
    base_url: str = "https://google.serper.dev"
    n_results: int = 10 # min: 10, max: 100
    ...
```
2. Duration of google search results (`serper_dev_tool.py`)

```bash
# https://serper.dev/playground

def _make_api_request(self, search_query: str, search_type: str) -> dict:
    ...
    payload = json.dumps({"q": search_query, "num": self.n_results, "tbs": "qdr:m"}) # Past week: "qdr:w", Past month: "qdr:m"
    ...
```
3. Google dorks (`task()`)
```bash
# Reference https://github.com/TakSec/google-dorks-bug-bounty
```
4. Agents (`agents()`)
```bash
# https://docs.crewai.com/concepts/agents
```


## Update Log
- **2025-08-11**: **DorkAgent v1.4** - Enhanced security reports with specific information disclosure details, added CLI interface (dorkagent-cli.py) with argparse support, fixed critical notification race condition bug, improved attack vector analysis with actual parameters and payloads, added comprehensive development documentation (CLAUDE.md), restored requirements.txt format
- **2025-05-18**: Modified README.md and banner, Added juicy google dorks, Medium article (https://medium.com/@yee-yore/llm-powered-agent-for-automated-google-dorking-dcb14d609dc2)
- **2025-04-17**: Removed tasks(old).py, the version prior to prompt engineering; Deleted Google Dork for finding "Confidential" documents (most results were merely informative); Removed Google Dork targeting login panels; Added settings to help avoid LLM provider rate limits; Integrated Gemini Flash 2.0 (free to use and currently considered the best value LLM); Merged tasks.py and agents.py into dorkagent.py for simplified maintenance
- **2025-04-01**: Added hybrid LLM option (GPT & Claude); Added dork `intitle:"IIS Windows Server"`; Applied prompt engineering to tasks.py; Added default depth consideration for subdomain inputs; Added `requirements.txt` for Windows/MacOS compatibility