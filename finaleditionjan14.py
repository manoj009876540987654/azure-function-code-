# function_app.py

import logging
import os
import json
import requests
import azure.functions as func
from azure.identity import DefaultAzureCredential
from uuid import uuid4
from datetime import datetime

app = func.FunctionApp()

# ========= HARD-CODED VM DETAILS =========
SUBSCRIPTION_ID = "7a735755-6139-4d2c-8ba4-5fccaaae24a0"
RESOURCE_GROUP = "AI-Ops-Project"
VM_NAME = "App-Server-01"

# ========= IN-MEMORY FIX STORE (DEMO ONLY) =========
# fix_id -> list of shell commands
FIX_STORE: dict[str, list[str]] = {}

# ========= HELPERS =========

def send_teams(card: dict) -> None:
    url = os.getenv("TEAMS_WEBHOOK_URL")
    if not url:
        logging.error("Missing TEAMS_WEBHOOK_URL")
        return
    requests.post(url, json=card, timeout=10)


def format_commands(cmds: list[str]) -> str:
    lines = ["```bash"]
    for i, cmd in enumerate(cmds, 1):
        lines.append(f"{i}. {cmd}")
    lines.append("```")
    return "\n".join(lines)


def parse_runcommand_output(resp_json: dict) -> str:
    output = []
    for item in resp_json.get("value", []):
        msg = item.get("message", "")
        if msg:
            output.append(msg.strip())
    return "\n\n".join(output) if output else "No output returned"


def build_report_html(commands: list[str], output: str) -> str:
    cmd_block = "\n".join(commands)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""
    <html>
      <head>
        <title>Remediation Execution Report</title>
      </head>
      <body style="font-family: Arial, sans-serif; margin: 40px;">
        <h2 style="color: #107C10;">✅ Remediation Executed Successfully</h2>

        <p><b>VM:</b> {VM_NAME}</p>
        <p><b>Time:</b> {timestamp}</p>

        <h3>Commands Executed</h3>
        <pre style="background:#f4f4f4; padding:12px;">{cmd_block}</pre>

        <h3>Execution Output</h3>
        <pre style="background:#111; color:#0f0; padding:12px; white-space:pre-wrap;">
{output}
        </pre>
      </body>
    </html>
    """

# ========= ALERT INGEST =========

@app.function_name(name="alert_ingest")
@app.route(
    route="alert_ingest",
    methods=["POST"],
    auth_level=func.AuthLevel.ANONYMOUS,
)
def alert_ingest(req: func.HttpRequest) -> func.HttpResponse:
    try:
        data = req.get_json()
    except Exception:
        return func.HttpResponse("Invalid JSON", status_code=400)

    labels = data.get("alert", {}).get("labels", {})
    ai = data.get("ai", {})

    alertname = labels.get("alertname")
    instance = labels.get("instance", "unknown")

    summary = ai.get("summary")
    explanation = ai.get("explanation")
    commands = ai.get("commands")

    if not all([alertname, summary, explanation, commands]):
        return func.HttpResponse("Missing required fields", status_code=400)

    if not isinstance(commands, list) or not commands:
        return func.HttpResponse("Commands must be a non-empty list", status_code=400)

    fix_id = str(uuid4())
    FIX_STORE[fix_id] = commands

    card = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"Alert {alertname}",
        "themeColor": "0076D7",
        "title": f"🚨 Alert: {alertname}",
        "sections": [
            {
                "facts": [
                    {"name": "Instance", "value": instance}
                ],
                "text": (
                    f"**🤖 AI Summary**\n{summary}\n\n"
                    f"**Explanation**\n{explanation}\n\n"
                    f"**Proposed Fix**\n{format_commands(commands)}"
                ),
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "✅ Run Fix",
                "targets": [
                    {
                        "os": "default",
                        "uri": (
                            f"{os.getenv('FUNCTION_BASE_URL')}"
                            f"/api/teams_action?action=run_fix&fix_id={fix_id}"
                        ),
                    }
                ],
            },
            {
                "@type": "OpenUri",
                "name": "❌ Reject",
                "targets": [
                    {
                        "os": "default",
                        "uri": (
                            f"{os.getenv('FUNCTION_BASE_URL')}"
                            f"/api/teams_action?action=reject"
                        ),
                    }
                ],
            },
        ],
    }

    send_teams(card)

    return func.HttpResponse(
        json.dumps({"sent": True, "fix_id": fix_id}),
        mimetype="application/json",
    )

# ========= TEAMS ACTION =========

@app.function_name(name="teams_action")
@app.route(route="teams_action", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def teams_action(req: func.HttpRequest) -> func.HttpResponse:
    try:
        action = req.params.get("action")

        if action == "reject":
            return func.HttpResponse(
                "<h3>❌ Fix rejected</h3>",
                mimetype="text/html"
            )

        if action != "run_fix":
            return func.HttpResponse(
                "<h3>❌ Invalid action</h3>",
                status_code=400,
                mimetype="text/html"
            )

        fix_id = req.params.get("fix_id")
        if not fix_id or fix_id not in FIX_STORE:
            return func.HttpResponse(
                "<h3>❌ Fix expired or not found</h3>",
                status_code=400,
                mimetype="text/html"
            )

        commands = FIX_STORE.pop(fix_id)

        credential = DefaultAzureCredential()
        token = credential.get_token(
            "https://management.azure.com/.default"
        ).token

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        url = (
            f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
            f"/resourceGroups/{RESOURCE_GROUP}"
            f"/providers/Microsoft.Compute/virtualMachines/{VM_NAME}"
            f"/runCommand?api-version=2023-03-01"
        )

        payload = {
            "commandId": "RunShellScript",
            "script": commands
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=60)

        logging.warning(f"RunCommand status={resp.status_code}")
        logging.warning(resp.text)

        if resp.status_code not in (200, 202):
            return func.HttpResponse(
                "<h3>❌ Fix execution failed</h3>",
                mimetype="text/html"
            )

        return func.HttpResponse(
            "<h3>✅ Fix executed successfully</h3>",
            mimetype="text/html"
        )

    except Exception as e:
        logging.exception("teams_action failed")
        return func.HttpResponse(
            f"<h3>❌ Error</h3><pre>{str(e)}</pre>",
            mimetype="text/html",
            status_code=500
        )

