import azure.functions as func
import json, os, requests, base64, paramiko, traceback
from openai import OpenAI

app = func.FunctionApp()

# OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ================= AI Helper =================
def generate_ai_remediation(incident, description):
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    prompt = f"""
You are a senior SRE.

Incident: {incident}
Description: {description}

Give:
1. Root cause
2. Step-by-step Linux remediation commands
3. Safety warning
"""

    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2
    )

    return resp.choices[0].message.content


# ================= SSH Runner =================
def run_remote_commands(cmds):
    try:
        host = os.getenv("VM_HOST")
        user = os.getenv("VM_USER")
        password = os.getenv("VM_PASSWORD")

        if not host or not user or not password:
            raise Exception("Missing VM credentials")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=user, password=password, timeout=10)

        results = []
        for c in cmds:
            stdin, stdout, stderr = ssh.exec_command(c)
            results.append({
                "cmd": c,
                "stdout": stdout.read().decode(),
                "stderr": stderr.read().decode()
            })

        ssh.close()
        return results

    except Exception as e:
        print("SSH ERROR:", str(e))
        print(traceback.format_exc())
        return [{"error": str(e)}]


# ================= Lookup SOP =================
@app.function_name(name="lookup_sop")
@app.route(route="lookup_sop", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def lookup_sop(req: func.HttpRequest) -> func.HttpResponse:
    incident = req.params.get("incident") or req.params.get("error_key")
    if not incident:
        return func.HttpResponse("Missing incident", status_code=400)

    api = os.getenv("SOP_GITHUB_API")
    token = os.getenv("GITHUB_TOKEN")

    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    r = requests.get(f"{api}/{incident}.json", headers=headers)

    if r.status_code == 404:
        return func.HttpResponse(json.dumps({"found": False}), mimetype="application/json")

    data = r.json()
    sop = json.loads(base64.b64decode(data["content"]).decode())
    return func.HttpResponse(json.dumps({"found": True, "sop": sop}), mimetype="application/json")


# ================= Send Alert to Teams =================
@app.function_name(name="send_approval_card")
@app.route(route="send_approval_card", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def send_approval_card(req: func.HttpRequest) -> func.HttpResponse:
    payload = req.get_json()
    alert = payload["alerts"][0]

    labels = alert.get("labels", {})
    annotations = alert.get("annotations", {})

    context = {
        "incident": labels.get("alertname"),
        "severity": labels.get("severity"),
        "description": annotations.get("description", "")
    }

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "Incident",
        "title": f"🚨 {context['incident']} ({context['severity']})",
        "sections": [{"facts": [{"name": k, "value": v} for k, v in context.items()]}],
        "potentialAction": [{
            "@type": "HttpPOST",
            "name": "Investigate",
            "target": os.getenv("CALLBACK_BASE_URL") + "/api/approval_callback",
            "body": json.dumps(context),
            "headers": [{"name": "Content-Type", "value": "application/json"}]
        }]
    }

    requests.post(os.getenv("TEAMS_WEBHOOK_URL"), json=card)
    return func.HttpResponse(json.dumps({"status": "sent"}), mimetype="application/json")


# ================= Approval Callback =================
@app.function_name(name="approval_callback")
@app.route(route="approval_callback", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def approval_callback(req: func.HttpRequest) -> func.HttpResponse:
    data = req.get_json()
    incident = data["incident"]
    description = data.get("description", "")

    sop_lookup = requests.get(
        f"{os.getenv('CALLBACK_BASE_URL')}/api/lookup_sop?incident={incident}"
    ).json()

    if sop_lookup.get("found"):
        cmds = [x["cmd"] for x in sop_lookup["sop"]["plan"]]
        results = run_remote_commands(cmds)
        msg = f"🛠 Executed SOP for {incident}:\n```json\n{json.dumps(results, indent=2)}\n```"
    else:
        msg = f"🤖 AI Suggestion for {incident}:\n{generate_ai_remediation(incident, description)}"

    requests.post(os.getenv("TEAMS_WEBHOOK_URL"), json={"text": msg})
    return func.HttpResponse(json.dumps({"status": "processed"}), mimetype="application/json")


# ================= Save SOP =================
@app.function_name(name="save_sop")
@app.route(route="save_sop", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def save_sop(req: func.HttpRequest) -> func.HttpResponse:
    data = req.get_json()
    api = os.getenv("SOP_GITHUB_API")
    token = os.getenv("GITHUB_TOKEN")

    payload = {
        "message": f"Add SOP for {data['error_key']}",
        "content": base64.b64encode(json.dumps(data["sop"], indent=2).encode()).decode()
    }

    headers = {"Authorization": f"token {token}"}
    requests.put(f"{api}/{data['error_key']}.json", headers=headers, json=payload)
    return func.HttpResponse(json.dumps({"status": "saved"}), mimetype="application/json")
