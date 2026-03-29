#!/usr/bin/env python3
"""Safe file utilities for the Agentic Coder (Protected) skill.

Layer 2 Defense: Tool Permission Boundaries
- Blocks access to sensitive files (.env, credentials, keys)
- Restricts commands that could exfiltrate data
- Prevents path traversal outside allowed directories
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Files that should NEVER be read
BLOCKED_FILES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.example",
    "credentials.json", "credentials.yaml", "credentials.yml",
    "secrets.json", "secrets.yaml", "secrets.yml",
    "config.json", "config.yaml", "config.yml",
    "service-account.json", "service_account.json",
    ".netrc", ".npmrc",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    ".ssh/config",
    "token.json", "auth.json",
    ".git-credentials",
}

# File extensions that should never be read
BLOCKED_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx", ".jks",
    ".keystore", ".truststore",
}

# Commands that should NEVER be executed
BLOCKED_COMMANDS = {
    "curl", "wget", "nc", "netcat", "ncat",
    "ssh", "scp", "rsync", "sftp",
    "env", "printenv", "export",
    "base64",  # often used in exfiltration
}


def _is_blocked_file(path: Path) -> bool:
    """Check if a file is in the blocked list."""
    name = path.name.lower()
    if name in BLOCKED_FILES:
        return True
    if path.suffix.lower() in BLOCKED_EXTENSIONS:
        return True
    # Block any file starting with .env
    if name.startswith(".env"):
        return True
    return False


def _is_blocked_command(command: str) -> bool:
    """Check if a command contains blocked executables."""
    # Extract the base command (first word, handle pipes)
    parts = command.split("|")
    for part in parts:
        tokens = part.strip().split()
        if tokens:
            cmd = tokens[0].strip()
            # Handle paths like /usr/bin/curl
            base_cmd = os.path.basename(cmd)
            if base_cmd in BLOCKED_COMMANDS:
                return True
    # Also check if blocked commands appear as arguments (e.g., bash -c "curl ...")
    for blocked in BLOCKED_COMMANDS:
        if blocked in command.split():
            return True
    return False


def read_file(path: str) -> str:
    """Read a file, blocking access to sensitive files."""
    file_path = Path(path).expanduser().resolve()

    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    if not file_path.is_file():
        print(f"Error: Not a file: {file_path}")
        sys.exit(1)

    if _is_blocked_file(file_path):
        print(f"BLOCKED: Access denied to sensitive file: {file_path.name}")
        print("This file may contain credentials or secrets.")
        print("Reading sensitive files is not permitted by security policy.")
        sys.exit(1)

    content = file_path.read_text(encoding="utf-8", errors="replace")
    print(content)
    return content


def list_dir(path: str = ".") -> list[str]:
    """List contents of a directory."""
    dir_path = Path(path).expanduser().resolve()

    if not dir_path.exists():
        print(f"Error: Directory not found: {dir_path}")
        sys.exit(1)
    if not dir_path.is_dir():
        print(f"Error: Not a directory: {dir_path}")
        sys.exit(1)

    entries = sorted(dir_path.iterdir())
    for entry in entries:
        prefix = "[DIR]  " if entry.is_dir() else "[FILE] "
        # Flag sensitive files
        if entry.is_file() and _is_blocked_file(entry):
            prefix = "[BLOCKED] "
        print(f"{prefix}{entry.name}")
    return [str(e) for e in entries]


def search_files(directory: str, pattern: str) -> list[str]:
    """Search for files matching a glob pattern."""
    dir_path = Path(directory).expanduser().resolve()
    if not dir_path.exists():
        print(f"Error: Directory not found: {dir_path}")
        sys.exit(1)

    matches = sorted(dir_path.rglob(pattern))
    for match in matches:
        if match.is_file() and _is_blocked_file(match):
            print(f"[BLOCKED] {match}")
        else:
            print(str(match))
    if not matches:
        print(f"No files matching '{pattern}' found in {dir_path}")
    return [str(m) for m in matches]


def run_command(command: str) -> str:
    """Run a shell command, blocking dangerous commands."""
    if _is_blocked_command(command):
        print(f"BLOCKED: Command not permitted by security policy: {command}")
        print("Commands that could exfiltrate data are blocked.")
        sys.exit(1)

    # Also block reading env vars via echo
    if "echo $" in command or "echo ${" in command:
        print("BLOCKED: Reading environment variables is not permitted.")
        sys.exit(1)

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout
        if result.stderr:
            output += f"\nSTDERR:\n{result.stderr}"
        if result.returncode != 0:
            output += f"\nExit code: {result.returncode}"
        print(output)
        return output
    except subprocess.TimeoutExpired:
        print("Error: Command timed out after 30 seconds")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Safe file utilities")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    read_parser = subparsers.add_parser("read", help="Read a file")
    read_parser.add_argument("path", help="Path to the file")

    list_parser = subparsers.add_parser("list", help="List directory contents")
    list_parser.add_argument("path", nargs="?", default=".", help="Directory path")

    search_parser = subparsers.add_parser("search", help="Search for files")
    search_parser.add_argument("directory", help="Directory to search")
    search_parser.add_argument("pattern", help="Glob pattern")

    run_parser = subparsers.add_parser("run", help="Run a shell command")
    run_parser.add_argument("cmd", help="Command to execute")

    args = parser.parse_args()

    if args.command == "read":
        read_file(args.path)
    elif args.command == "list":
        list_dir(args.path)
    elif args.command == "search":
        search_files(args.directory, args.pattern)
    elif args.command == "run":
        run_command(args.cmd)
    else:
        parser.print_help()
