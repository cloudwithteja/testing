# Lendesk Security Challenge

Welcome! This challenge is intended to evaluate your ability to identify, analyze, and clearly communicate security vulnerabilities in a realistic web application environment.

## Instructions

You are tasked with performing a security assessment of the provided application and delivering a pentest-style report. Your report should demonstrate both your technical ability to find vulnerabilities and your communication skills in presenting them clearly to the target audience – in this case, a theoretical team of software developers and product managers responsible for the application.

Your report should include:

1. Testing methodology
   - Tools, techniques and approaches used.
   - Which parts of the application you tested and why.
2. Findings

   For each vulnerability found:

   - Title & Description: What is the issue?
   - Risk Level: High / Medium / Low
   - Impact: Why it's a vulnerability and what could happen if exploited.
   - Evidence: Screenshots, payloads, requests, or reproduction steps (as needed).
   - Remediation: Clear guidance on how the issue should be resolved.

3. Summary
   - Overall risk posture of the application.
   - Most critical issue discovered.
   - General security recommendations.

### Scope

You may run the app locally and/or explore the code statically. You are encouraged to use any tools and techniques you would typically apply in this style of assessment, including:

- Manual code review
- Tools such as Postman, curl, Burp Suite, etc.
- Linters or security scanners
- Any other techniques you deem appropriate

In scope:

- All source code and configuration files included in the provided codebase
- All routes and behaviours of the application
- Any logic accessible through the code or API

Not in scope:

- Infrastructure-level vulnerabilities
- Denial-of-service (DoS) attacks — these are typically mitigated at the infrastructure level and are not part of this assessment

## What's included

A Node/Typescript web application that contains intentional security flaws for the purpose of this challenge – some obvious, some subtle.

See [app.md](app.md) for instructions on getting started with the application.

## Artifacts

Please submit your report in either Markdown or PDF format. You do not need to return a copy of the codebase — just the report is sufficient.
