from dotenv import load_dotenv
from datetime import datetime
from contextlib import redirect_stdout, redirect_stderr
from crewai import Crew
from agent import initialize_agents
from tasks import task
from langchain_openai import ChatOpenAI
from crewai import LLM
from termcolor import colored
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter

import sys, re, os
import pyfiglet

def clear_terminal():
    os.system("cls" if os.name == "nt" else "clear")

def display_banner():
    ascii_banner = pyfiglet.figlet_format("Dork Agent", font="big")
    print(colored(ascii_banner, "red"))
    print(colored("                                        by yee-yore", "magenta"))
    print("\n")
    print("DorkAgent is a LLM-powered agent for automated Google Dorking in bug hunting & pentesting.")
    print(colored("[Ver] Current DorkAgent version is v1.1", "cyan"))
    print("=" * 90)

def verify_api_key(llm_type):
    required_keys = ["SERPER_API_KEY"]

    if llm_type == "openai":
        required_keys.append("OPENAI_API_KEY")
    elif llm_type == "anthropic":
        required_keys.append("ANTHROPIC_API_KEY")

    load_dotenv()

    missing_keys = [key for key in required_keys if not os.getenv(key)]
    if missing_keys:
        print("🚨 Missing required API keys:")
        for key in missing_keys:
            print(f"   ❌ {key} is not set")
        print("\nPlease check your .env file and set the missing keys.")
        sys.exit(1)

def select_llm():
    ClaudeHaiku = LLM(
        api_key=os.getenv('ANTHROPIC_API_KEY'),
        model='anthropic/claude-3-5-haiku-20241022',
    )

    GPT4oMini = ChatOpenAI(model_name="gpt-4o-mini-2024-07-18", temperature=0)
    
    while True:
        print("\n")
        print("1. GPT-4o Mini")
        print("2. Claude 3.5 Haiku")
        print("\n")
        
        choice = input("[?] Choose LLM for Agents (1 - 2): ").strip()
        
        if choice == "1":
            return GPT4oMini, "openai"
        elif choice == "2":
            return ClaudeHaiku, "anthropic"
        else:
            print("❌ Invalid choice. Please enter 1 - 2.")

def get_file_path(prompt_text):
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def get_target_domains():
    target_domains = []

    while True:
        print("\n")
        print("1] Single Domain")
        print("2] Multi Domain (from file)")
        print("\n")
        
        choice = input("[?] Enter your target type (1 - 2): ").strip()

        if choice == "1":
            domain = input("[?] Enter the target domain: ").strip()
            target_domains.append(domain)
            break
            
        elif choice == "2": 
            file_path = get_file_path("[?] Enter the file path: ")
            if os.path.isfile(file_path):
                with open(file_path, "r", encoding="utf-8") as file:
                    for line in file:
                        domain = line.strip()
                        target_domains.append(domain)
                break 
            else:
                print("❌ File not found. Please enter a valid file path.")
        
        else:
            print("🚨 Invalid choice. Please select 1 - 2.")

    return target_domains

def select_depth():
    while True:
        print("\n")
        print("1] *.target.com")
        print("2] *.*.target.com")
        print("3] *.*.*.target.com")
        print("\n")

        depth = input("[?] Choose depth for dorking (1 - 3): ").strip()
        
        if depth == "1" or "2" or "3":
            return depth
        else:
            print("❌ Invalid choice. Please enter 1 - 3.")

def adjust_depth(target_domains, depth):
    try:
        depth = int(depth)  
        if depth not in [1, 2, 3]:  
            raise ValueError("Invalid depth value")
    except ValueError:
        print("❌ Invalid depth input. Defaulting to depth = 1.")
        depth = 1

    prefix = ".".join(["*"] * depth)  
    adjusted_domains = [f"{prefix}.{domain}" for domain in target_domains]

    return adjusted_domains

class Tee:
    ANSI_ESCAPE = re.compile(r'\x1B\[[0-9;]*m')  # Regex to remove ANSI escape codes

    def __init__(self, file, stream):
        self.file = file
        self.stream = stream

    def write(self, data):
        clean_data = self.ANSI_ESCAPE.sub('', data)  # Remove ANSI codes
        self.file.write(clean_data)
        self.stream.write(data)  # Keep original data with ANSI codes for console
        self.file.flush()  # Ensure data is written immediately

    def flush(self):
        self.file.flush()
        self.stream.flush()

if __name__ == "__main__":

    # Display banner
    clear_terminal()
    display_banner()

    # Select LLM
    selected_llm, llm_type = select_llm()
    agents = initialize_agents(selected_llm)

    # API KEY verification
    load_dotenv()
    verify_api_key(llm_type)

    # Get domain(s)
    clear_terminal()
    domains = get_target_domains()

    # Select depth
    clear_terminal()
    depth = select_depth()
    target_domains = adjust_depth(domains, depth)

    # Make directory for logging
    date = datetime.now().strftime("%y%m%d")
    LOG_DIR = os.path.join("./log", date)
    os.makedirs(LOG_DIR, exist_ok=True)

    for target_domain in target_domains:
        domain = target_domain.split('.', maxsplit=target_domain.count('*'))[-1]
        log = os.path.join(LOG_DIR, f"{date}_{domain}.log")
        report = os.path.join(LOG_DIR, f"{date}_{domain}.md")

        crew = Crew(
            agents=list(agents.values()),  
            tasks=task(target_domain, agents),  
            verbose=1,
        )

        with open(log, "w", encoding="utf-8") as log, \
            redirect_stdout(Tee(log, sys.__stdout__)), \
            redirect_stderr(Tee(log, sys.__stderr__)):
            
            print(f"Dorking on {target_domain}...")
            
            result = crew.kickoff()

            with open(report, "w", encoding="utf-8") as f:
                f.write(str(result))