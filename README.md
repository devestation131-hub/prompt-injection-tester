# 🤖 AI Prompt Injection Security Tester
**Language:** Python 3 | **Author:** Zachari Higgins

Tests LLM-powered applications for prompt injection vulnerabilities. Includes 10 attack categories with automated detection and HTML report generation.

## Test Categories
- System Prompt Leak, Identity Manipulation, Delimiter Escape
- Data Extraction, Filter Evasion, Indirect Injection
- Multi-turn Jailbreak, Authorization Bypass, Tool Abuse, Logic Bombs

## Usage
```bash
pip install requests
python prompt_injection_tester.py --url http://localhost:8080/api/chat
python prompt_injection_tester.py --url https://myapp.com/ask --header "Authorization: Bearer TOKEN"
```

## Ethical Use
Only test applications you own or have authorization to assess.