from dotenv import load_dotenv
from datetime import datetime
from contextlib import redirect_stdout, redirect_stderr
from crewai import Crew
from agent import searcher, bughunter, writer
from tasks import task

import sys, re, os

load_dotenv()

date = datetime.now().strftime("%y%m%d")
LOG_DIR = os.path.join("./log", date)

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

def main():

    target_domains = [ # add domains (BBP, VDP ...)
        
    ]

    os.makedirs(LOG_DIR, exist_ok=True)

    for target_domain in target_domains:
        log = os.path.join(LOG_DIR, f"{date}_{target_domain}.log")
        report = os.path.join(LOG_DIR, f"{date}_{target_domain}.md")

        crew = Crew(
                    agents=[searcher, bughunter, writer], 
                    tasks=task(target_domain),  
                    verbose=1,
        )

        with open(log, "w", encoding="utf-8") as log, \
            redirect_stdout(Tee(log, sys.__stdout__)), \
            redirect_stderr(Tee(log, sys.__stderr__)):
            
            print(f"Dorking on {target_domain}...")
            
            result = crew.kickoff()

            with open(report, "w", encoding="utf-8") as f:
                f.write(str(result))

main()