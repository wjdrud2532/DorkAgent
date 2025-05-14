from dotenv import load_dotenv
from datetime import datetime
from crewai import Crew, LLM, Task, Agent
from langchain_openai import ChatOpenAI
from termcolor import colored
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter

from crewai_tools import SerperDevTool

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
    print(colored("[Ver] Current DorkAgent version is v1.3", "cyan"))
    print("=" * 90)

def verify_api_key(llm_type):
    required_keys = ["SERPER_API_KEY"]

    if llm_type == "openai":
        required_keys.append("OPENAI_API_KEY")
    elif llm_type == "anthropic":
        required_keys.append("ANTHROPIC_API_KEY")
    elif llm_type == "gemini":
        required_keys.append("GEMINI_API_KEY")

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

    GPT4oMini = ChatOpenAI(
        model_name="gpt-4o-mini-2024-07-18", 
        temperature=0
    )

    GeminiFlash = LLM(
        api_key=os.getenv('GEMINI_API_KEY'),
        model='gemini/gemini-2.0-flash',
    )
    
    while True:
        print("\n")
        print("1. GPT-4o Mini")
        print("2. Claude 3.5 Haiku")
        print("3. Gemini 2.0 Flash")
        print("\n")
        
        choice = input("[?] Choose LLM for Agents (1 - 3): ").strip()
        
        if choice == "1":
            return GPT4oMini, "openai"
        elif choice == "2":
            return ClaudeHaiku, "anthropic"
        elif choice == "3":
            return GeminiFlash, "gemini"
        else:
            print("❌ Invalid choice. Please enter 1 - 3.")

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
        print("1] target.com")
        print("2] *.target.com")
        print("3] *.*.target.com")
        print("4] *.*.*.target.com")
        print("\n")

        depth = input("[?] Choose depth for dorking (1 - 4): ").strip()
        
        if depth in ["1", "2", "3", "4"]:
            return depth
        else:
            print("❌ Invalid choice. Please enter 1 - 4.")

def integrate_notify(): 
    while True: 
        print("\n") 
        print("\n") 
 
        notify = input("[?] Do you want to send a report using notify? (Y or N): ").strip() 
         
        if notify in ["Y", "y", "N", "n"]: 
            return notify 
        else: 
            print("❌ Invalid choice. Please enter Y or N")

def adjust_depth(target_domains, depth):
    try:
        depth = int(depth)  
        if depth < 1:  
            raise ValueError("Invalid depth value")
    except ValueError:
        print("❌ Invalid depth input. Defaulting to depth = 1.")
        depth = 1

    if depth == 1:
        adjusted_domains = target_domains
    else:
        prefix = ".".join(["*"] * (depth - 1))  
        adjusted_domains = [f"{prefix}.{domain}" for domain in target_domains]

    return adjusted_domains

def sanitize_filename(domain_name):

    # '*' -> 'wildcard'
    sanitized = domain_name.replace('*', 'wildcard')
    sanitized = re.sub(r'[\\/*?:"<>|]', '', sanitized)
    
    return sanitized

def agents(llm):

    searcher = Agent(
        role="searcher",
        goal="Performing advanced Google searches using Google Dorks",
        backstory="An expert in Google Dorking techniques for information gathering",
        verbose=True,
        allow_delegation=False,
        tools=[SerperDevTool()],
        llm=llm,
        respect_context_window=True,
    )

    bughunter = Agent(
        role="bughunter",
        goal="Identifying attack surfaces and vulnerabilities in target domains",
        backstory="A skilled penetration tester specializing in web security and vulnerability assessments",
        verbose=False,
        allow_delegation=False,
        llm=llm,
        respect_context_window=True,
    )

    writer = Agent(
        role="writer",
        goal="Generating well-structured and detailed reports based on findings",
        backstory="A technical writer specializing in cybersecurity documentation and structured reporting",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        respect_context_window=True,
    )

    return [searcher, bughunter, writer]

def task(target_domain, agents):
       
    task1 = Task(
        description=f"""
        # Google Dorking Search Analysis

        ## Objective
        Execute the following Google Dork queries for the domain {target_domain} and collect ONLY REAL search results that actually exist.

        ## Google Dork Query List
        1. site:{target_domain} (intitle:"index of /" | intitle:"docker-compose.yml" | intitle:".env" | intitle:"config.yml" | intitle:".git" | intitle:"package.json" | intitle:"requirements.txt" | intitle:".gitignore" | intitle:"IIS Windows Server")
        2. site:{target_domain} (ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:csv | ext:ppt | ext:pptx | ext:txt | ext:rtf | ext:odt) ("INTERNAL USE ONLY" | "INTERNAL ONLY" | "TRADE SECRET" | "NOT FOR DISTRIBUTION" | "NOT FOR PUBLIC RELEASE" | "EMPLOYEE ONLY")
        3. site:{target_domain} (ext:csv | ext:txt | ext:json | ext:xlsx | ext:xls | ext:sql | ext:log) (intext:"id" | intext:"uid" | intext:"uuid" | intext:"username" | intext:"password" | intext:"userid" | intext:"email" | intext:"ssn" | intext:"phone" | intext:"date of birth" | intext:"Social Security Number" | intext:"credit card" | intext:"CCV" | intext:"CVV" | intext:"card number")
        4. site:{target_domain} (inurl:action | inurl:page | inurl:pid | inurl:uid | inurl:id | inurl:search | inurl:cid | inurl:idx | inurl:no)
        5. site:{target_domain} (inurl:admin | inurl:administrator | inurl:wp-login)
        6. site:{target_domain} ext:txt inurl:robots.txt
        7. site:{target_domain} (ext:yaml | ext:yml | ext:ini | ext:conf | ext:config | ext:log | ext:pdf) (intext:"token" | intext:"access_token" | intext:"api_key" | intext:"private_key" | intext:"secret")
        8. site:{target_domain} (inurl:/download.jsp | inurl:/downloads.jsp | inurl:/upload.jsp) | inurl:/uploads.jsp | inurl:/download.php | inurl:/downloads.php | inurl:/upload.php) | inurl:/uploads.php)
        9. site:{target_domain} (inurl:index.php?page | inurl:file | inurl:inc | inurl:layout | inurl:template | inurl:content | inurl:module)
        10. site:{target_domain} (ext:pdf | ext:doc | ext:docx | ext:ppt | ext:pptx) (intext:"join.slack" | intext:"t.me" | intext:"trello.com/invite" | intext:"notion.so" | intext:"atlassian.net" | intext:"asana.com" | intext:"teams.microsoft.com" | intext:"zoom.us/j" | intext:"bit.ly")
        11. site:{target_domain} (inurl:url= | inurl:continue= | inurl:redirect | inurl:return | inurl:target | inurl:site= | inurl:view= | inurl:path | inurl:returl= | inurl:next= | inurl:fallback= | inurl:u= | inurl:goto= | inurl:link=)
        12. (site:*.s3.amazonaws.com | site:*.s3-external-1.amazonaws.com | site:*.s3.dualstack.us-east-1.amazonaws.com | site:*.s3.ap-south-1.amazonaws.com) "{target_domain}"
        13. site:{target_domain} inurl:eyJ (inurl:token | inurl:jwt | inurl:access | inurl:auth | inurl:authorization | inurl:secret)

        ## Execution Process - YOU MUST FOLLOW THIS
        1. Execute EACH of the 13 queries in sequence - DO NOT SKIP ANY QUERIES
        2. Document results for each query even if it returns nothing
        3. Continue until ALL 13 queries have been executed
        4. Only then compile final results

        ## Search Guidelines
        - Execute each query exactly in the format specified above.
        - If a query returns no results, immediately proceed to the next google dork.
        - ONLY report URLs that you ACTUALLY find in the search results.
        - NEVER fabricate or hallucinate any URLs or search results.
        - If all queries return no results, return empty results list.
        - Search only within the provided domain; do not expand the search scope.
      
        ## Exclusion Criteria
        - Exclude results containing the following keywords (high false positive likelihood):
          * Common documents: "Advertisement", "Agreement", "Terms", "Policy", "License", "Disclaimer"
          * Support materials: "API Docs", "Forum", "Help", "Community", "Code of Conduct", "Knowledge Base", "Support Center", "Customer Support"
          * Development content: "Developers", "Statement", "Support", "Rules", "Docs", "Developer Portal", "Engineering Blog"
          * Test content: "example", "sample", "demo", "test", "dummy", "placeholder", "mockup"
          * Documents: "Guideline", "Template", "Documentation", "User Manual", "Reference Guide"
          * Corporate communications: "About Us", "Press", "Media", "Careers"

        - Also exclude:
          * Files with naming patterns like:
            - "example_*", "sample_*", "test_*", "demo_*"
            - "*_test.*", "*_sample.*", "*_demo.*"
          * Content that appears non-production:
            - Sequential IDs (user1, user2, user3)
            - Dummy email patterns (test@example.com, admin@localhost, user@test.com)
            - Placeholder usernames (admin, root, temp, organizer)
          * Content with artificial data patterns:
            - Generic sequential identifiers
            - Predictable naming conventions
            - Standardized test data
          * Training materials or documentation examples
          * Onboarding and introductory content

        - Comprehensive URL filtering:
          * Exclude URLs containing subdirectories like:
            - "/help/"
            - "/support/"
            - "/docs/"
            - "/examples/"
            - "/tutorial/"
          * Avoid results from known documentation domains
          * Filter out URLs with explicit non-production indicators
        """,
        expected_output=f"""
        <findings>
        [
          {{
            "total_queries": <number_of_queries_executed>,
            "queries_with_results": <number_of_queries_with_results>,
            "total_urls_found": <number_of_urls_found>,
            "results": [
              // Only include this section if results were actually found
              {{
                "query_index": <index_of_query>,
                "query": "<exact_query_executed>",
                "urls_found": [
                  {{
                    "url": "<actual_url_found>",
                    "title": "<actual_page_title>",
                    "description": "<brief_description_of_actual_content>"
                  }}
                  // Additional URLs if found
                ]
              }}
              // Additional queries with results
            ],
            "queries_without_results": [<indices_of_queries_that_returned_no_results>]
          }}
        ]
        </findings>
        """,
        agent=agents[0]
    )
    
    task2 = Task(
        description=f"""
        # Vulnerability and Attack Vector Analysis

        ## Objective
        Analyze the Google Dorking results found by the searcher to identify potential security vulnerabilities or attack vectors.
        
        ## CRITICAL INSTRUCTIONS
        - ONLY analyze URLs that were ACTUALLY found by the searcher in Task 1.
        - DO NOT invent, fabricate, or hallucinate any vulnerabilities or findings.
        - If no URLs were found by the searcher, report that no vulnerabilities could be identified.
        - DO NOT use example data from this prompt as actual findings.
        - ALWAYS base your analysis SOLELY on real search results.
        
        ## Filtering Example/Testing Data
        - EXCLUDE any files with names containing words like "example", "sample", "demo", "test", "dummy"
        - Do not report vulnerabilities based on example, training, or test files
        - Be skeptical of data that looks too perfect or follows obvious patterns (e.g., sequential IDs, test@example.com)
        - For user data, verify it appears to be actual user information rather than placeholder content
        - If data contains elements like "example_value_based_audience_file" or similar indicators of non-production data, exclude it
        - Pay special attention to file metadata, headers, or comments that might indicate test/example status

        ## Analysis Categories
        1. Sensitive File Exposure:
           - Configuration files (.env, config.yml, web.config, .ini, .conf)
           - Source code-related files (.git, package.json, requirements.txt, .gitignore)
           - Directory listings (index of /)
           - Log files (*.log)
           - Backup files (*.bak, *.backup, *.old)
           - Database dump files (*.sql, *.dump)

        2. Sensitive Information Exposure:
           - API keys, access tokens, OAuth credentials
           - Hardcoded passwords, connection strings
           - Cloud credentials (AWS/Azure/GCP)
           - Encryption keys, private certificates
           - Session identifiers, cookie information
           - Personally identifiable information (PII) - emails, phone numbers, social security numbers, credit card info

        3. Potential Attack Vectors:
           - URL parameter manipulation points (inurl:action, inurl:page, inurl:pid, inurl:uid, inurl:id, inurl:search, etc.)
           - Parameters potentially vulnerable to SQL injection
           - Output points potentially vulnerable to XSS
           - URL/file handling parameters with SSRF potential
           - Potential file inclusion attack vectors (inurl:index.php?page, inurl:file, inurl:inc, etc.)
           - File upload/download endpoints (inurl:/upload.php, inurl:/uploads.jsp, inurl:/download.php, etc.)
           - File path parameters potentially vulnerable to path traversal attacks

        4. Authentication/Authorization Issues:
           - Exposed admin pages (inurl:admin, inurl:administrator, inurl:wp-login)
           - Insecure authentication mechanisms
           - Access control flaws (IDOR, etc.)
           - Open redirect vulnerabilities (inurl:url, inurl:continue, inurl:returnto, inurl:redirect, etc.)
           - Session management issues

        5. Infrastructure Information Exposure:
           - Cloud storage misconfigurations (S3 buckets, Azure Blob, etc.)
           - Internal IP addresses, hostnames
           - Development/testing environment information
           - Service structure information
           - Internal collaboration tool links (Slack, Trello, Notion, Teams, etc.)
           - Restricted path information through robots.txt
           - Server version, operating system information

        ## Severity Assessment Criteria
        - Critical: Direct system access or sensitive data exposure (credentials, tokens, PII)
        - High: Access to important functions/data (source code, configuration files, internal documents)
        - Medium: Vulnerabilities with limited impact (partial information disclosure, potential injection points)
        - Low: Information exposure without a direct attack vector

        ## For Each Finding, Analyze:
        1. Vulnerability type
        2. Location (URL)
        3. Severity (Critical, High, Medium, Low)
        4. Vulnerability description
        5. Potential impact
        6. Attack vector (PoC or verification method)
        """,
        expected_output=f"""
        <findings>
        [
          {{
            "domain": "{target_domain}",
            "total_urls_analyzed": <number_of_urls_analyzed>,
            "total_vulnerabilities": <number_of_vulnerabilities_found>,
            "total_excluded": <number_of_urls_excluded>,
            "vulnerabilities": [
              // Only include if actual vulnerabilities were found based on real results
              {{
                "type": "<vulnerability_type>",
                "subtype": "<vulnerability_subtype>",
                "url": "<actual_url_from_search_results>",
                "severity": "<severity_level>",
                "description": "<description_of_actual_vulnerability>",
                "impact": "<potential_impact>",
                "evidence": "<actual_evidence_from_page>",
                "exploit_vector": "<how_the_vulnerability_could_be_exploited>",
                "remediation": "<recommended_fix>"
              }}
              // Additional vulnerabilities if found
            ],
            "excluded_urls": [
              // Only include if URLs were excluded
              {{
                "url": "<excluded_url>",
                "reason": "<reason_for_exclusion>"
              }}
              // Additional excluded URLs
            ]
          }}
        ]
        </findings>
        """,
        agent=agents[1],
    )

    task3 = Task(
        description=f"""
        # Security Report Creation

        ## Objective
        Create a professional security report for {target_domain} based on the Google Dorking results from the searcher and vulnerability analysis from the bug hunter.

        ## CRITICAL INSTRUCTIONS
        - ONLY include vulnerabilities that were ACTUALLY identified by the bug hunter in Task 2.
        - NEVER fabricate or hallucinate any vulnerabilities, findings, or evidence.
        - If the bug hunter found no vulnerabilities, state clearly that no vulnerabilities were found.
        - Use ONLY real data from the previous tasks - do not use any example data from this prompt.
        - If no URLs or vulnerabilities were found, create a simple report stating that no issues were identified.

        ## Report Structure
        1. Summary
           - Number of vulnerabilities found (classified by severity)
           - Key findings
           - Overall risk assessment

        2. Vulnerability Findings
           - Categorized by severity (Critical, High, Medium, Low)
           - Detailed description of each vulnerability
           - Evidence (URLs, screenshots, code, etc.)
           - Potential impact analysis

        3. Attack Scenarios
           - Possible attack scenarios using the vulnerabilities found
           - Vulnerability chaining possibilities
           - Potential damage from successful attacks

        ## Important Notes
        - If no vulnerabilities are found, display only "Total Found: 0, List of Findings: None".
        - Include all URLs and evidence.
        - Clearly indicate the severity and rationale for each vulnerability.
        - Use professional and clear language.

        ## Report Format
        - Clear titles and section divisions
        - Severity icons: 🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low
        - Unique ID for each vulnerability (e.g., VULN-001, VULN-002)
        - Clean formatting using tables, code blocks, etc.
        """,
        expected_output=f"""
        # Security Assessment Report for {target_domain}

        ## 1. Summary
        - **Target Domain**: {target_domain}
        - **Vulnerabilities Found**:
          - 🔴 Critical: <number_of_critical_vulnerabilities>
          - 🟠 High: <number_of_high_vulnerabilities>
          - 🟡 Medium: <number_of_medium_vulnerabilities>
          - 🔵 Low: <number_of_low_vulnerabilities>
        - **Total Vulnerabilities**: <total_number_of_vulnerabilities>
        - **Overall Risk Level**: <overall_risk_assessment>

        ### Key Findings
        - <key_finding_1>
        - <key_finding_2>
        - <key_finding_3>

        ## 2. Vulnerability Findings

        <If no vulnerabilities were found, include only: "No vulnerabilities were identified during this assessment.">

        ### 🔴 Critical Vulnerabilities

        <Include only if critical vulnerabilities were found>

        #### VULN-001: <vulnerability_title>
        - **URL**: <actual_url>
        - **Description**: <actual_description>
        - **Evidence**: <actual_evidence>
        - **Impact**: <actual_impact>
        - **Attack Vector**: <actual_attack_vector>

        ### 🟠 High Vulnerabilities

        <Include only if high vulnerabilities were found>

        ### 🟡 Medium Vulnerabilities

        <Include only if medium vulnerabilities were found>

        ### 🔵 Low Vulnerabilities

        <Include only if low vulnerabilities were found>

        ## 3. Attack Scenarios

        <Include only if vulnerabilities were found>
        
        ### Scenario 1: <attack_scenario_title>
        <description_of_attack_scenario>
        
        ### Scenario 2: <attack_scenario_title>
        <description_of_attack_scenario>
        """,
        agent=agents[2],
    )
    return [task1, task2, task3]

if __name__ == "__main__":

    # Display banner
    clear_terminal()
    display_banner()

    # Select LLM
    llm, llm_type = select_llm()
    agents = agents(llm)

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

    # Integrate notify 
    notify = integrate_notify()

    # Make directory for logging
    date = datetime.now().strftime("%y%m%d")
    LOG_DIR = os.path.join("./log", date)
    os.makedirs(LOG_DIR, exist_ok=True)

    for target_domain in target_domains:
        original_domain = target_domain 
        
        if '*' in target_domain:
            domain_parts = target_domain.split('.')
            base_domain = domain_parts[1]  
        else:
            domain = target_domain.split('.', maxsplit=target_domain.count('.'))[-1]
            base_domain = target_domain
        
        safe_domain = sanitize_filename(base_domain)
        
        tasks = task(original_domain, agents)

        crew = Crew(
            agents=agents,  
            tasks=tasks, 
            verbose=1,
            max_rpm=15, # use 15, if you're using gemini free plan
            output_log_file=True,
        )

        print(f"Dorking on {original_domain}...")

        result = crew.kickoff()

        report = os.path.join(f"log/{date}", f"{date}_{safe_domain}.md")
        
        if notify.lower() in ["y"]: 
            try: 
                cmd = f'notify -bulk -p telegram -i "{report}"' 
                os.system(cmd) 
                print(f"Report sent successfully via notify!") 
            except Exception as e: 
                print(f"Error sending report via notify: {str(e)}")

        with open(report, "w", encoding="utf-8") as f:
            f.write(str(result))