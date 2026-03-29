#!/usr/bin/env python3
"""Google Model Armor integration for the Agentic Coder (Protected) skill.

Layer 3a Defense: Cloud-based input and output scanning via Google Model Armor API.
Detects prompt injection, jailbreak attempts, malicious URIs, sensitive data leaks,
and responsible AI violations.

Requires:
  pip install google-cloud-modelarmor

Setup:
  gcloud auth application-default login
  - OR set GOOGLE_APPLICATION_CREDENTIALS to a service account key

Template: projects/YOUR_PROJECT_ID/locations/YOUR_LOCATION/templates/YOUR_TEMPLATE_ID

To configure:
  1. Replace YOUR_PROJECT_ID with your GCP project ID
  2. Replace YOUR_LOCATION with your Model Armor region (e.g., us-central1)
  3. Replace YOUR_TEMPLATE_ID with your Model Armor template name
"""

import argparse
import json
import sys


# Model Armor configuration — REPLACE THESE WITH YOUR OWN
PROJECT = "YOUR_PROJECT_ID"           # e.g., "my-gcp-project-123456"
LOCATION = "YOUR_LOCATION"            # e.g., "us-central1"
TEMPLATE_ID = "YOUR_TEMPLATE_ID"      # e.g., "my-agent-template"
TEMPLATE = f"projects/{PROJECT}/locations/{LOCATION}/templates/{TEMPLATE_ID}"
ENDPOINT = f"modelarmor.{LOCATION}.rep.googleapis.com"


def _get_client():
    """Create a Model Armor client."""
    try:
        from google.api_core.client_options import ClientOptions
        from google.cloud import modelarmor_v1
    except ImportError:
        print("Error: google-cloud-modelarmor not installed.")
        print("Run: pip install google-cloud-modelarmor")
        sys.exit(1)

    client = modelarmor_v1.ModelArmorClient(
        transport="rest",
        client_options=ClientOptions(api_endpoint=ENDPOINT),
    )
    return client


def _format_filter_results(filter_results) -> dict:
    """Format Model Armor filter results (MapComposite) into a readable dict."""
    output = {}

    # filter_results is a map: key (str) -> FilterResult
    # Each FilterResult has sub-fields like pi_and_jailbreak_filter_result, sdp_filter_result, etc.
    FILTER_ACCESSORS = {
        "pi_and_jailbreak": "pi_and_jailbreak_filter_result",
        "malicious_uris": "malicious_uri_filter_result",
        "sdp": "sdp_filter_result",
        "rai": "rai_filter_result",
        "csam": "csam_filter_filter_result",
    }

    for key, filter_result in filter_results.items():
        accessor = FILTER_ACCESSORS.get(key)
        if not accessor:
            continue
        sub = getattr(filter_result, accessor, None)
        if sub is None:
            continue

        entry = {}
        if hasattr(sub, "execution_state") and sub.execution_state:
            entry["execution_state"] = sub.execution_state.name if hasattr(sub.execution_state, "name") else str(sub.execution_state)
        if hasattr(sub, "match_state") and sub.match_state:
            entry["match_state"] = sub.match_state.name if hasattr(sub.match_state, "name") else str(sub.match_state)
        if hasattr(sub, "confidence_level") and sub.confidence_level:
            entry["confidence"] = sub.confidence_level.name if hasattr(sub.confidence_level, "name") else str(sub.confidence_level)

        # SDP has inspect_result with findings
        if key == "sdp" and hasattr(sub, "inspect_result") and sub.inspect_result:
            ir = sub.inspect_result
            if hasattr(ir, "execution_state") and ir.execution_state:
                entry["execution_state"] = ir.execution_state.name if hasattr(ir.execution_state, "name") else str(ir.execution_state)
            if hasattr(ir, "match_state") and ir.match_state:
                entry["match_state"] = ir.match_state.name if hasattr(ir.match_state, "name") else str(ir.match_state)
            if hasattr(ir, "findings") and ir.findings:
                entry["findings"] = [
                    {
                        "info_type": str(f.info_type.name) if hasattr(f, "info_type") and f.info_type else "unknown",
                        "likelihood": str(f.likelihood) if hasattr(f, "likelihood") else "unknown",
                    }
                    for f in ir.findings
                ]

        if entry:
            output[key] = entry

    return output


def scan_input(text: str) -> dict:
    """
    Scan user input or file content for injection attacks via Model Armor.

    Returns dict with filter results and overall safety assessment.
    """
    from google.cloud import modelarmor_v1

    client = _get_client()
    request = modelarmor_v1.SanitizeUserPromptRequest(
        name=TEMPLATE,
        user_prompt_data=modelarmor_v1.DataItem(text=text),
    )

    try:
        response = client.sanitize_user_prompt(request=request)
    except Exception as e:
        return {"error": str(e), "is_safe": None}

    sr = response.sanitization_result
    match_state = sr.filter_match_state.name if hasattr(sr.filter_match_state, "name") else str(sr.filter_match_state)

    result = {
        "sanitization_result": match_state,
        "filters": _format_filter_results(sr.filter_results) if sr.filter_results else {},
        "is_safe": match_state != "MATCH_FOUND",
    }
    return result


def scan_output(text: str) -> dict:
    """
    Scan model output for leaked secrets and sensitive data via Model Armor.

    Returns dict with filter results and overall safety assessment.
    """
    from google.cloud import modelarmor_v1

    client = _get_client()
    request = modelarmor_v1.SanitizeModelResponseRequest(
        name=TEMPLATE,
        model_response_data=modelarmor_v1.DataItem(text=text),
    )

    try:
        response = client.sanitize_model_response(request=request)
    except Exception as e:
        return {"error": str(e), "is_safe": None}

    sr = response.sanitization_result
    match_state = sr.filter_match_state.name if hasattr(sr.filter_match_state, "name") else str(sr.filter_match_state)

    result = {
        "sanitization_result": match_state,
        "filters": _format_filter_results(sr.filter_results) if sr.filter_results else {},
        "is_safe": match_state != "MATCH_FOUND",
    }
    return result


def main():
    parser = argparse.ArgumentParser(description="Model Armor scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan_in = subparsers.add_parser("scan-input", help="Scan input text for injection")
    scan_in.add_argument("text", help="Text to scan")

    scan_out = subparsers.add_parser("scan-output", help="Scan output for leaked secrets")
    scan_out.add_argument("text", help="Text to scan")

    args = parser.parse_args()

    if args.command == "scan-input":
        result = scan_input(args.text)
        print(json.dumps(result, indent=2, default=str))
        if not result.get("is_safe", True):
            print("\n*** BLOCKED: Prompt injection or malicious content detected ***")
            sys.exit(1)
    elif args.command == "scan-output":
        result = scan_output(args.text)
        print(json.dumps(result, indent=2, default=str))
        if not result.get("is_safe", True):
            print("\n*** BLOCKED: Sensitive data detected in output ***")
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
