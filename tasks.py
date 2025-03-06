from crewai import Task

def task(target_domain, agents):

    task1 = Task(
        description=f"""
        Conduct Google Dorking on the domain {target_domain}, applying only the specified dorks.

        Note: If a Google Dork query returns no results, immediately proceed to the next dork. Do not use any dorks beyond those listed.

        site:{target_domain} (intitle:"index of /" | intitle:"docker-compose.yml" | intitle:".env" | intitle:"config.yml" | intitle:".git" | intitle:"package.json" | intitle:"requirements.txt" | intitle:".gitignore")
        site:{target_domain} (ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:csv | ext:ppt | ext:pptx | ext:txt | ext:rtf | ext:odt) ("CONFIDENTIAL" | "INTERNAL USE ONLY" | "INTERNAL ONLY" | "TRADE SECRET" | "NOT FOR DISTRIBUTION" | "NOT FOR PUBLIC RELEASE" | "EMPLOYEE ONLY")
        site:{target_domain} (ext:yaml | ext:yml | ext:ini | ext:conf | ext:config | ext:log | ext:pdf) (intext:"token" | intext:"access_token" | intext:"api_key" | intext:"private_key" | intext:"secret")
        site:{target_domain} (ext:csv | ext:txt | ext:json | ext:xlsx | ext:xls | ext:sql | ext:log) (intext:"id" | intext:"uid" | intext:"uuid" | intext:"username" | intext:"password" | intext:"userid" | intext:"email" | intext:"ssn" | intext:"phone" | intext:"date of birth" | intext:"Social Security Number" | intext:"credit card" | intext:"CCV" | intext:"CVV" | intext:"card number")
        site:{target_domain} (ext:pdf | ext:doc | ext:docx | ext:ppt | ext:pptx) (intext:"join.slack" | intext:"t.me" | intext:"trello.com/invite" | intext:"notion.so" | intext:"atlassian.net" | intext:"asana.com" | intext:"teams.microsoft.com" | intext:"zoom.us/j" | intext:"bit.ly")
        site:{target_domain} (inurl:url | inurl:continue | inurl:returnto | inurl:redirect | inurl:return | inurl:target | inurl:site | inurl:view | inurl:path)
        site:{target_domain} (inurl:action | inurl:page | inurl:pid | inurl:uid | inurl:id | inurl:search | inurl:cid | inurl:idx | inurl:no)
        site:{target_domain} (inurl:admin | inurl:administrator | inurl:login | inurl:wp-login)
        site:{target_domain} ext:txt inurl:robots.txt
        site:{target_domain} (inurl:/download.jsp | inurl:/downloads.jsp | inurl:/upload.jsp) | inurl:/uploads.jsp | inurl:/download.php | inurl:/downloads.php | inurl:/upload.php) | inurl:/uploads.php)
        site:{target_domain} (inurl:index.php?page | inurl:file | inurl:inc | inurl:layout | inurl:template | inurl:content | inurl:module)
        (site:*.s3.amazonaws.com | site:*.s3-external-1.amazonaws.com | site:*.s3.dualstack.us-east-1.amazonaws.com | site:*.s3.ap-south-1.amazonaws.com) "{target_domain}"
        """,
        expected_output=f"""Findings discovered on {target_domain} through Google Dorking: """,
        agent=agents["searcher"]
    )

    task2 = Task(
        description=f"""
        If you have found something, please determine whether it can be used as an attack surface or vulnerability for bug hunting or penetration testing.

        Note: Exclude any results that contain keywords such as “Terms of Use,” “API Docs,” “Forum,” “Help,” “Community,” “Code of Conduct,” “Developers,” “Statement,” “Rules,” “Agreement,” “Guideline,” and “Template.” 
        """,
        expected_output=f"""Identified attack surfaces or security vulnerabilities: """,
        agent=agents["bughunter"],
    )

    task3 = Task(
        description=f"""
        If any findings (attack surfaces or security vulnerabilities) were identified in the previous task, compile them into a structured report.

        Note: If no findings exist, display only:  
        
        “Total Found: 0
        List of Findings: None”
        """,
        expected_output=f"""Security Report for {target_domain}
        1. Total Found:
        2. List of Findings: 
        """,
        agent=agents["writer"],
    )
    return [task1, task2, task3]