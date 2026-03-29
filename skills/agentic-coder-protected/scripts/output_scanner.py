#!/usr/bin/env python3
"""Local output scanner for the Agentic Coder (Protected) skill.

Layer 3b Defense: Regex-based scanning for secrets and exfiltration patterns.
Works offline as a fallback when Model Armor is unavailable.

Two modes:
  scan-input  — detect prompt injection patterns in file content
  scan-output — detect leaked secrets and exfiltration attempts in responses
"""

import argparse
import json
import re
import sys

# ═══════════════════════════════════════════════════════════════
# INPUT SCANNING: Detect prompt injection patterns
# ═══════════════════════════════════════════════════════════════

INJECTION_PATTERNS = [
    # Classic instruction overrides
    (r"ignore\s+(all\s+)?previous\s+instructions", "instruction override"),
    (r"ignore\s+(all\s+)?prior\s+instructions", "instruction override"),
    (r"disregard\s+(your|all|previous|prior)", "instruction override"),
    (r"forget\s+(everything|all|your)", "instruction override"),
    (r"system\s*override", "system override attempt"),
    (r"you\s+are\s+now\s+(in|a)\s+", "role reassignment"),
    (r"new\s+instructions?\s*:", "instruction injection"),
    (r"maintenance\s+mode", "mode switch attempt"),
    (r"\[SYSTEM\]", "fake system tag"),
    (r"\[ADMIN\]", "fake admin tag"),
    (r"IMPORTANT\s+SYSTEM\s+NOTE", "fake system note"),
    # Supply chain / rules file attacks
    (r"always\s+start\s+by\s+reading\s+the\s+\.env", "env file harvesting"),
    (r"include\s+(the\s+)?(full\s+)?contents?\s+of\s+.*(config|\.env|credential|secret)", "data exfiltration instruction"),
    (r"read\s+the\s+\.env\s+file\s+to\s+(check|verify|confirm|validate)", "disguised env harvesting"),
    (r"(configuration|environment)\s+validation\s+instructions?\s+for\s+AI", "AI-targeted config harvesting"),
    (r"append\s+to\s+(the\s+)?query\s+parameter", "URL exfiltration instruction"),
    (r"show\s+them\s+so\s+the\s+developer\s+can\s+(confirm|verify)", "social engineering"),
    (r"first\s+read(ing)?\s+the\s+\.env", "env file pre-read"),
    (r"Replace\s+ENV_CONTENTS", "template exfiltration variable"),
    (r"(full|entire)\s+URL-encoded\s+contents?\s+of", "URL-encoded exfiltration"),
    (r"reading\s+the\s+user'?s?\s+current\s+environment", "env harvesting via context"),
    (r"When\s+helping\s+with\s+this\s+project.*read\s+the\s+\.env", "disguised onboarding attack"),
    (r"Include\s+the\s+full\s+contents\s+of\s+any\s+configuration", "blanket config exfiltration"),
    (r"verify\s+(the\s+)?environment\s+is\s+properly\s+configured", "fake environment verification"),
]


def scan_input(text: str) -> dict:
    """Scan input text for prompt injection patterns."""
    findings = []
    for pattern, label in INJECTION_PATTERNS:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            findings.append({
                "type": "injection",
                "label": label,
                "matched": match.group()[:60],
                "position": match.start(),
            })

    return {
        "is_safe": len(findings) == 0,
        "findings": findings,
        "patterns_checked": len(INJECTION_PATTERNS),
    }


# ═══════════════════════════════════════════════════════════════
# OUTPUT SCANNING: Detect leaked secrets and exfiltration
# ═══════════════════════════════════════════════════════════════

SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9_\-]{20,}", "API Key (OpenAI/Anthropic)"),
    (r"sk_live_[a-zA-Z0-9]+", "Stripe Secret Key"),
    (r"AKIA[A-Z0-9]{16,}", "AWS Access Key"),
    (r"postgresql://[^\s\"']+", "Database Connection String"),
    (r"mongodb(\+srv)?://[^\s\"']+", "MongoDB Connection String"),
    (r"hooks\.slack\.com/services/[^\s\"']+", "Slack Webhook URL"),
    (r"redis-auth-[a-zA-Z0-9]+", "Redis Auth Token"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"xoxb-[0-9]+-[a-zA-Z0-9]+", "Slack Bot Token"),
    (r"password[\"']?\s*[:=]\s*[\"'][^\"']{4,}[\"']", "Hardcoded Password"),
    (r"P@ssw0rd[^\s\"']*", "Password"),
    (r"sk-ant-[a-zA-Z0-9\-]+", "Anthropic API Key"),
]

# Markdown image exfiltration (zero-click data theft)
EXFILTRATION_PATTERNS = [
    (r"!\[[^\]]*\]\(https?://[^)]*\?(env|data|key|secret|token|config|cred)[^)]*\)", "Markdown Image Exfiltration"),
    (r"!\[[^\]]*\]\(https?://(?!github\.com|imgur\.com|shields\.io)[^)]+\)", "Suspicious External Image"),
]


def scan_output(text: str) -> dict:
    """Scan output text for leaked secrets and exfiltration attempts."""
    findings = []
    cleaned = text

    # Check for secrets
    for pattern, label in SECRET_PATTERNS:
        for match in re.finditer(pattern, cleaned):
            secret = match.group()
            preview = secret[:12] + "..." if len(secret) > 12 else secret
            findings.append({
                "type": "secret",
                "label": label,
                "preview": preview,
            })
            cleaned = cleaned.replace(secret, f"[REDACTED - {label}]")

    # Check for exfiltration
    for pattern, label in EXFILTRATION_PATTERNS:
        for match in re.finditer(pattern, cleaned):
            tag = match.group()
            findings.append({
                "type": "exfiltration",
                "label": label,
                "preview": tag[:50] + "...",
            })
            cleaned = cleaned.replace(tag, f"[BLOCKED - {label}]")

    return {
        "is_safe": len(findings) == 0,
        "findings": findings,
        "cleaned_text": cleaned if findings else None,
    }


def main():
    parser = argparse.ArgumentParser(description="Local security scanner")
    subparsers = parser.add_subparsers(dest="command")

    si = subparsers.add_parser("scan-input", help="Scan for injection patterns")
    si.add_argument("text", help="Text to scan")

    so = subparsers.add_parser("scan-output", help="Scan for leaked secrets")
    so.add_argument("text", help="Text to scan")

    args = parser.parse_args()

    if args.command == "scan-input":
        result = scan_input(args.text)
        print(json.dumps(result, indent=2))
        if not result["is_safe"]:
            print(f"\n*** INJECTION DETECTED: {len(result['findings'])} pattern(s) found ***")
            sys.exit(1)
    elif args.command == "scan-output":
        result = scan_output(args.text)
        print(json.dumps(result, indent=2))
        if not result["is_safe"]:
            print(f"\n*** SECRETS DETECTED: {len(result['findings'])} finding(s) ***")
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
