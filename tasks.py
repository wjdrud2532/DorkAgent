from crewai import Task

def task(target_domain, agents):
       
    task1 = Task(
        description=f"""
        # Google Dorking Search Analysis

        ## Objective
        Execute the following Google Dork queries for the domain {target_domain} and collect ONLY REAL search results that actually exist.

        ## Google Dork Query List
        1. site:{target_domain} (intitle:"index of /" | intitle:"docker-compose.yml" | intitle:".env" | intitle:"config.yml" | intitle:".git" | intitle:"package.json" | intitle:"requirements.txt" | intitle:".gitignore" | intitle:"IIS Windows Server")
        2. site:{target_domain} (ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:csv | ext:ppt | ext:pptx | ext:txt | ext:rtf | ext:odt) ("CONFIDENTIAL" | "INTERNAL USE ONLY" | "INTERNAL ONLY" | "TRADE SECRET" | "NOT FOR DISTRIBUTION" | "NOT FOR PUBLIC RELEASE" | "EMPLOYEE ONLY")
        3. site:{target_domain} (ext:csv | ext:txt | ext:json | ext:xlsx | ext:xls | ext:sql | ext:log) (intext:"id" | intext:"uid" | intext:"uuid" | intext:"username" | intext:"password" | intext:"userid" | intext:"email" | intext:"ssn" | intext:"phone" | intext:"date of birth" | intext:"Social Security Number" | intext:"credit card" | intext:"CCV" | intext:"CVV" | intext:"card number")
        4. site:{target_domain} (inurl:action | inurl:page | inurl:pid | inurl:uid | inurl:id | inurl:search | inurl:cid | inurl:idx | inurl:no)
        5. site:{target_domain} (inurl:admin | inurl:administrator | inurl:login | inurl:wp-login)
        6. site:{target_domain} ext:txt inurl:robots.txt
        7. site:{target_domain} (ext:yaml | ext:yml | ext:ini | ext:conf | ext:config | ext:log | ext:pdf) (intext:"token" | intext:"access_token" | intext:"api_key" | intext:"private_key" | intext:"secret")
        8. site:{target_domain} (inurl:/download.jsp | inurl:/downloads.jsp | inurl:/upload.jsp) | inurl:/uploads.jsp | inurl:/download.php | inurl:/downloads.php | inurl:/upload.php) | inurl:/uploads.php)
        9. site:{target_domain} (inurl:index.php?page | inurl:file | inurl:inc | inurl:layout | inurl:template | inurl:content | inurl:module)
        10. site:{target_domain} (ext:pdf | ext:doc | ext:docx | ext:ppt | ext:pptx) (intext:"join.slack" | intext:"t.me" | intext:"trello.com/invite" | intext:"notion.so" | intext:"atlassian.net" | intext:"asana.com" | intext:"teams.microsoft.com" | intext:"zoom.us/j" | intext:"bit.ly")
        11. site:{target_domain} (inurl:url | inurl:continue | inurl:returnto | inurl:redirect | inurl:return | inurl:target | inurl:site | inurl:view | inurl:path)
        12. (site:*.s3.amazonaws.com | site:*.s3-external-1.amazonaws.com | site:*.s3.dualstack.us-east-1.amazonaws.com | site:*.s3.ap-south-1.amazonaws.com) "{target_domain}"

        ## Search Guidelines
        - Execute each query exactly in the format specified above.
        - If a query returns no results, immediately proceed to the next query.
        - ONLY report URLs that you ACTUALLY find in the search results.
        - NEVER fabricate or hallucinate any URLs or search results.
        - If all queries return no results, return empty results list.
        - For each URL found, provide a brief description of the actual content.

        ## Exclusion Criteria
        Exclude results if the URL, title, or filename contains any of the following keywords (high likelihood of false positives):
        - "Advertisement", "Agreement", "Terms and conditions", "Terms of Use"
        - "API Docs", "Forum", "Help", "Community", "Code of Conduct"
        - "Developers", "Statement", "Support", "Rules", "example", "sample", "demo", "test"
        - "Guideline", "Template", "dummy", "placeholder"
        
        Pay special attention to filtering out:
        - Files with names containing "example_", "sample_", "test_", "demo_"
        - Files that appear to be templates, training materials, or examples
        - Documentation examples, test data, and dummy content

        ## Important Notes
        - Search only within the provided domain; do not expand the search scope.
        - Do not use queries other than the dork queries provided above.
        - Provide all URLs in exact full URL format.
        - Indicate when a query was executed even if it yielded no results.
        - NEVER generate fictional findings or examples - only report what you actually find.
        
        ## Content Validation
        For each potentially sensitive file found, perform the following checks:
        - Examine the filename for indicators that it might be example data (e.g., "example_", "sample_", "demo_")
        - Check if the data appears to be realistic or if it seems to be placeholder/dummy data
        - If the file contains user information, check if it appears to be real user data or training examples
        - Look for clues in the file metadata or content suggesting it's for instructional purposes
        - Assess whether data patterns look genuine (random distribution) or artificial (patterns like "user1", "user2", etc.)
        
        Only report files that appear to contain genuine sensitive information, not example data.
        """,
        expected_output=f"""
        <findings>
        [
          {{
            "domain": "{target_domain}",
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
        agent=agents["searcher"]
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
           - Confidential markings in internal documents ("CONFIDENTIAL", "INTERNAL USE ONLY", etc.)

        3. Potential Attack Vectors:
           - URL parameter manipulation points (inurl:action, inurl:page, inurl:pid, inurl:uid, inurl:id, inurl:search, etc.)
           - Parameters potentially vulnerable to SQL injection
           - Output points potentially vulnerable to XSS
           - URL/file handling parameters with SSRF potential
           - Potential file inclusion attack vectors (inurl:index.php?page, inurl:file, inurl:inc, etc.)
           - File upload/download endpoints (inurl:/upload.php, inurl:/uploads.jsp, inurl:/download.php, etc.)
           - File path parameters potentially vulnerable to path traversal attacks

        4. Authentication/Authorization Issues:
           - Exposed admin pages (inurl:admin, inurl:administrator, inurl:login, inurl:wp-login)
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
        agent=agents["bughunter"],
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
        agent=agents["writer"],
    )
    return [task1, task2, task3]