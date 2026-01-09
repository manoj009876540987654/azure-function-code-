import azure.functions as func
import json, os, requests, base64, paramiko
from openai import OpenAI

app = func.FunctionApp()

# ---------- Safe OpenAI Client ----------
def get_openai_client():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    return OpenAI(api_key=api_key)


def generate_ai_remediation(incident, description):
    client = get_openai_client()
    if not client:
        return "OPENAI_API_KEY not configured"

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    prompt = f"""
You are a senior Site Reliability Engineer.

Incident: {incident}
Description: {description}

Provide:
1. Root cause
2. Step-by-step Linux remediation commands
3. Safety warnings if any
"""

    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a senior Site Reliability Engineer."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2
    )

    return resp.choices[0].message.content


# ---------- SOP Lookup ----------
def lookup_sop_internal(incident):
    api = os.getenv("SOP_GITHUB_API")
    token = os.getenv("GITHUB_TOKEN")

    url = f"{api}/{incident}.json"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}

    r = requests.get(url, headers=headers, timeout=10)

    if r.status_code != 200:
        return None

    data = r.json()
    decoded = base64.b64decode(data["content"]).decode("utf-8")
    return json.loads(decoded)


# ---------- VM Executor ----------
def run_on_vm(commands):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=os.getenv("VM_IP"),
        username=os.getenv("VM_USER"),
        password=os.getenv("VM_PASS"),
        timeout=10
    )

    for cmd in commands:
        ssh.exec_command(cmd)

    ssh.close()


# ---------- Teams Sender ----------
def send_teams_card(title, text, actions=None):
    webhook = os.getenv("TEAMS_WEBHOOK_URL")

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": title,
        "title": title,
        "text": text,
        "potentialAction": actions or []
    }

    requests.post(webhook, json=card, timeout=10)


# ---------- ENTRY: Alert Receiver ----------
@app.function_name(name="alert_receiver")
@app.route(route="alert_receiver", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def alert_receiver(req: func.HttpRequest) -> func.HttpResponse:
    alert = req.get_json()["alerts"][0]

    incident = alert["labels"].get("alertname", "unknown")
    description = alert["annotations"].get("description", "")

    sop = lookup_sop_internal(incident)

    if sop:
        run_on_vm(sop["commands"])
        send_teams_card(
            f"✅ Auto-remediated {incident}",
            f"Executed SOP commands:\n{chr(10).join(sop['commands'])}"
        )
        return func.HttpResponse("auto remediated")

    ai_solution = generate_ai_remediation(incident, description)

    actions = [
        {
            "@type": "HttpPOST",
            "name": "Approve Fix",
            "target": f"{os.getenv('CALLBACK_BASE_URL')}/api/approval_callback",
            "body": json.dumps({
                "incident": incident,
                "description": description,
                "ai_solution": ai_solution
            }),
            "headers": [{"name": "Content-Type", "value": "application/json"}]
        }
    ]

    send_teams_card(
        f"⚠️ {incident} needs approval",
        f"AI Suggested Fix:\n{ai_solution}",
        actions
    )

    return func.HttpResponse("approval sent")


# ---------- Approval Callback ----------
@app.function_name(name="approval_callback")
@app.route(route="approval_callback", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def approval_callback(req: func.HttpRequest) -> func.HttpResponse:
    data = req.get_json()
    incident = data["incident"]
    ai_solution = data["ai_solution"]

    commands = [line for line in ai_solution.splitlines() if line.strip().startswith("sudo")]

    run_on_vm(commands)

    send_teams_card(
        f"✅ Approved & Executed {incident}",
        f"Commands executed:\n{chr(10).join(commands)}"
    )

    return func.HttpResponse("approved and executed")
