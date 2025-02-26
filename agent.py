from crewai import Agent, LLM
from crewai_tools import SerperDevTool, ScrapeWebsiteTool
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from dotenv import load_dotenv
import os

load_dotenv()

ClaudeHaiku = LLM(
    api_key=os.getenv('ANTHROPIC_API_KEY'),
    model='anthropic/claude-3-5-haiku-20241022',
)

search_tool = SerperDevTool()
scrape_tool = ScrapeWebsiteTool()

searcher = Agent(
    role="searcher",
    goal="Performing advanced Google searches using Google Dorks",
    backstory="An expert in Google Dorking techniques for information gathering",
    verbose=False,
    allow_delegation=False,
    tools=[search_tool],
    max_iter=8,
    llm=ChatOpenAI(model_name="gpt-4o-mini-2024-07-18", temperature=0),
    #llm=ClaudeHaiku,
)

bughunter = Agent(
    role="bughunter",
    goal="Identifying attack surfaces and vulnerabilities in target domains",
    backstory="A skilled penetration tester specializing in web security and vulnerability assessments",
    verbose=False,
    allow_delegation=False,
    #tools=[scrape_tool],
    max_iter=2,
    llm=ChatOpenAI(model_name="gpt-4o-mini-2024-07-18", temperature=0),
    #llm=ClaudeHaiku,
)

writer = Agent(
    role="writer",
    goal="Generating well-structured and detailed reports based on findings",
    backstory="A technical writer specializing in cybersecurity documentation and structured reporting",
    verbose=True,
    allow_delegation=False,
    max_iter=2,
    llm=ChatOpenAI(model_name="gpt-4o-mini-2024-07-18", temperature=0), 
    #lm=ClaudeHaiku,
)