# DorkAgent
🤖 LLM-powered agent for automated Google Dorking in bug hunting &amp; pentesting.

<img src="workflow.png" alt="Workflow Diagram" width="500">                   
                                                                                                    
## Usage
1. Install packages
```bash
> pip install -r requirements.txt
```
2. Config API keys in `.env` file 
Set either OpenAI or Anthropic API` key. Also, you can add any types of LLM https://docs.crewai.com/concepts/llms
```bash
SERPER_API_KEY= # https://serper.dev/
OPENAI_API_KEY= 
ANTHROPIC_API_KEY=
```

3. Set up __target_domains__ in `main.py` file
```bash
target_domains = [ # BBP, VDP, etc
    "airbnb.com",
    "dyson.com",
    "starbucks.com",
    "tiktok.com",
    "tesla.com",
]
```

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
2. Duration of googling (`serper_dev_tool.py`)

```bash
# https://serper.dev/playground

def _make_api_request(self, search_query: str, search_type: str) -> dict:
    ...
    payload = json.dumps({"q": search_query, "num": self.n_results, "qdr:m"}) # Past week: "qdr:w", Past month: "qdr:m"
    ...
```
3. Google dorks (`tasks.py`)
```bash
# Reference https://github.com/TakSec/google-dorks-bug-bounty
```
4. Agents (`agent.py`)
```bash
# https://docs.crewai.com/concepts/agents
```

## TODO
- Improvement on false positives
- Conversion to a CLI-based tool
- Addition of Google Dorks for exploring various attack surfaces
- Support for Telegram bot 