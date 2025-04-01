from crewai import Task

def task(target_domain, agents):
       
    task1 = Task(
        description=f"""
        # Google Dorking Search Analysis

        ## Objective
        Execute the following Google Dork queries for the domain {target_domain} and collect search results.

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
        - Verify that each URL is accessible.
        - Provide a brief description of the content for each URL.

        ## Exclusion Criteria
        Exclude results if the URL or title contains any of the following keywords (high likelihood of false positives):
        - "Advertisement", "Agreement", "Terms and conditions", "Terms of Use"
        - "API Docs", "Forum", "Help", "Community", "Code of Conduct"
        - "Developers", "Statement", "Support", "Rules", "example"
        - "Guideline", "Template"

        ## Important Notes
        - Search only within the provided domain; do not expand the search scope.
        - Do not use queries other than the dork queries provided above.
        - Provide all URLs in exact full URL format.
        - Indicate when a query was executed even if it yielded no results.
        """,
        expected_output=f"""
        <findings>
        [
          {{
            "domain": "{target_domain}",
            "total_queries": 12,
            "queries_with_results": 3,
            "total_urls_found": 7,
            "results": [
              {{
                "query_index": 1,
                "query": "site:{target_domain} (intitle:\\"index of /\\" | intitle:\\"docker-compose.yml\\" | intitle:\\".env\\" | intitle:\\"config.yml\\" | intitle:\\".git\\" | intitle:\\"package.json\\" | intitle:\\"requirements.txt\\" | intitle:\\".gitignore\\" | intitle:\\"IIS Windows Server\\")",
                "urls_found": [
                  {{
                    "url": "https://{target_domain}/directory/",
                    "title": "Index of /directory",
                    "description": "Directory listing showing config files and source code"
                  }},
                  {{
                    "url": "https://{target_domain}/assets/",
                    "title": "Index of /assets",
                    "description": "Directory listing containing JavaScript and CSS assets"
                  }}
                ]
              }},
              {{
                "query_index": 6,
                "query": "site:{target_domain} ext:txt inurl:robots.txt",
                "urls_found": [
                  {{
                    "url": "https://{target_domain}/robots.txt",
                    "title": "Robots.txt file",
                    "description": "Contains disallowed directories including /admin and /internal"
                  }}
                ]
              }},
              {{
                "query_index": 7,
                "query": "site:{target_domain} (ext:yaml | ext:yml | ext:ini | ext:conf | ext:config | ext:log | ext:pdf) (intext:\\"token\\" | intext:\\"access_token\\" | intext:\\"api_key\\" | intext:\\"private_key\\" | intext:\\"secret\\")",
                "urls_found": [
                  {{
                    "url": "https://{target_domain}/config/app.config",
                    "title": "Application Configuration",
                    "description": "Configuration file containing API keys and database credentials"
                  }},
                  {{
                    "url": "https://{target_domain}/logs/debug.log",
                    "title": "Debug Log",
                    "description": "Log file containing error messages with tokens"
                  }},
                  {{
                    "url": "https://{target_domain}/settings/db.yaml",
                    "title": "Database Settings",
                    "description": "YAML file with database connection strings"
                  }},
                  {{
                    "url": "https://{target_domain}/api/swagger.yml",
                    "title": "API Documentation",
                    "description": "API documentation with example authentication tokens"
                  }}
                ]
              }}
            ],
            "queries_without_results": [2, 3, 4, 5, 8, 9, 10, 11, 12]
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
            "total_urls_analyzed": 7,
            "total_vulnerabilities": 3,
            "total_excluded": 1,
            "vulnerabilities": [
              {{
                "type": "sensitive_file_exposure",
                "subtype": "directory_listing",
                "url": "https://{target_domain}/directory/",
                "severity": "High",
                "description": "Directory listing enabled showing configuration files and source code",
                "impact": "Attackers can access sensitive files not meant for public access including configuration files with credentials",
                "evidence": "Directory listing shows .env files and database configuration",
                "exploit_vector": "Direct access to URL reveals all directory contents. Attacker can navigate to sensitive files like https://{target_domain}/directory/.env",
                "remediation": "Disable directory listing in web server configuration and restrict access to sensitive directories"
              }},
              {{
                "type": "information_disclosure",
                "subtype": "restricted_paths",
                "url": "https://{target_domain}/robots.txt",
                "severity": "Medium",
                "description": "Robots.txt reveals sensitive directories and admin interfaces",
                "impact": "Provides information about restricted areas and potential attack surfaces",
                "evidence": "Disallow: /admin/\nDisallow: /internal/\nDisallow: /backup/",
                "exploit_vector": "Attacker can directly access restricted paths: https://{target_domain}/admin/, https://{target_domain}/internal/",
                "remediation": "Remove sensitive path information from robots.txt and ensure proper authentication"
              }},
              {{
                "type": "credential_exposure",
                "subtype": "api_key",
                "url": "https://{target_domain}/config/app.config",
                "severity": "Critical",
                "description": "API keys and database credentials exposed in configuration file",
                "impact": "Complete unauthorized access to API services and database systems",
                "evidence": "API_KEY=Abcd1234XyzPQr56789\nDB_PASSWORD=SecurePass123!",
                "exploit_vector": "Attacker can use exposed credentials to access API: curl -H 'Authorization: Bearer Abcd1234XyzPQr56789' https://api.{target_domain}/v1/users",
                "remediation": "Remove configuration files from public access, implement proper authentication, and rotate exposed credentials immediately"
              }}
            ],
            "excluded_urls": [
              {{
                "url": "https://{target_domain}/api/swagger.yml",
                "reason": "API documentation excluded based on 'API Docs' keyword"
              }}
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

        ## Report Structure
        1. Summary
           - Assessment date
           - Number of vulnerabilities found (classified by severity)
           - Key findings
           - Overall risk assessment

        2. Methodology
           - Explanation of Google Dorking search methodology
           - Categories of queries used
           - Analysis approach

        3. Vulnerability Findings
           - Categorized by severity (Critical, High, Medium, Low)
           - Detailed description of each vulnerability
           - Evidence (URLs, screenshots, code, etc.)
           - Potential impact analysis

        4. Attack Scenarios
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
        - **Assessment Date**: {{'{{currentDate}}'}}
        - **Target Domain**: {target_domain}
        - **Vulnerabilities Found**:
          - 🔴 Critical: 1
          - 🟠 High: 1
          - 🟡 Medium: 1
          - 🔵 Low: 0
        - **Total Vulnerabilities**: 3
        - **Overall Risk Level**: 🔴 Critical

        ### Key Findings
        - API keys and database credentials exposed in configuration file
        - Directory listing enabled, allowing access to sensitive files
        - Sensitive paths and admin interfaces revealed through robots.txt

        ## 2. Methodology
        This assessment was conducted using Google Dorking techniques to analyze publicly accessible information on the web. A total of 12 Google Dork queries were executed to explore directory listings, configuration files, sensitive documents, log files, admin pages, and more.

        ### Google Dork Categories Used
        - Configuration and source code exposure
        - Sensitive document discovery
        - PII and credential exposure
        - Parameter manipulation points
        - Admin interfaces
        - Robots.txt analysis
        - API key and token exposure
        - File upload/download endpoints
        - File inclusion vulnerability points
        - Internal tool and communication leakage
        - Open redirect vulnerability points
        - Cloud storage exposure

        ## 3. Vulnerability Findings

        ### 🔴 Critical Vulnerabilities

        #### VULN-001: API Keys and Database Credentials Exposure
        - **URL**: https://{target_domain}/config/app.config
        - **Description**: Publicly accessible configuration file exposing API keys and database credentials in plaintext.
        - **Evidence**:
        ```
        API_KEY=Abcd1234XyzPQr56789
        DB_PASSWORD=SecurePass123!
        DB_USER=admin
        DB_HOST=internal-db.{target_domain}
        ```
        - **Impact**: Attackers can gain complete access to API services and databases, potentially leading to data exfiltration, modification, or deletion.
        - **Attack Vector**: Authentication to API using exposed credentials:
        ```
        curl -H 'Authorization: Bearer Abcd1234XyzPQr56789' https://api.{target_domain}/v1/users
        ```

        ### 🟠 High Vulnerabilities

        #### VULN-002: Directory Listing Enabled
        - **URL**: https://{target_domain}/directory/
        - **Description**: Web server has directory listing enabled, exposing sensitive files and directory structure.
        - **Evidence**: Accessing the /directory/ path displays a list of all files, including .env files.
        - **Impact**: Attackers can access sensitive configuration files, backup files, and source code not intended for public access.
        - **Attack Vector**: Direct browser access to view all files and navigate to sensitive content:
        ```
        https://{target_domain}/directory/.env
        https://{target_domain}/directory/backup/
        ```

        ### 🟡 Medium Vulnerabilities

        #### VULN-003: Sensitive Path Disclosure via Robots.txt
        - **URL**: https://{target_domain}/robots.txt
        - **Description**: The robots.txt file reveals sensitive directories and admin interface locations.
        - **Evidence**:
        ```
        User-agent: *
        Disallow: /admin/
        Disallow: /internal/
        Disallow: /backup/
        ```
        - **Impact**: Exposes important paths and potential attack surfaces to attackers.
        - **Attack Vector**: Attackers can directly access these URLs:
        ```
        https://{target_domain}/admin/
        https://{target_domain}/internal/
        https://{target_domain}/backup/
        ```

        ## 4. Attack Scenarios

        ### Scenario 1: Database Access and User Information Theft
        1. Attacker obtains database credentials from the exposed configuration file (VULN-001)
        2. Remotely connects to the database and accesses user tables
        3. Downloads all user information (emails, password hashes, personal data)
        4. Attempts to crack password hashes or hijack accounts

        ### Scenario 2: API Manipulation and Admin Access
        1. Uses the exposed API key (VULN-001) to send authenticated requests to the API
        2. Explores API for privilege escalation possibilities
        3. Creates admin account or modifies permissions of existing accounts
        4. Accesses admin interface (VULN-003) to take complete control of the system
        """,
        agent=agents["writer"],
    )
    return [task1, task2, task3]