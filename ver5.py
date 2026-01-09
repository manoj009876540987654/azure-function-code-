import azure.functions as func
import json, os, requests

app = func.FunctionApp()

# ================= Helper: Send approval card =================
def send_teams_approval_card(incident, sop):
    webhook = os.getenv("TEAMS_WEBHOOK_URL")
    callback = os.getenv("CALLBACK_BASE_URL")

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": f"Incident {incident}",
        "title": f"🚨 {incident} remediation approval",
        "sections": [
            {
                "facts": [
                    {"name": "Risk", "value": sop.get("risk", "unknown")},
                    {"name": "Description", "value": sop.get("description", "")},
                    {"name": "Commands", "value": "\n".join([p["cmd"] for p in sop.get("plan", [])])}
                ]
            }
        ],
        "potentialAction": [
            {
                "@type": "HttpPOST",
                "name": "✅ Approve",
                "target": f"{callback}/api/approval_callback",
                "body": json.dumps({"decision": "approve", "incident": incident}),
                "headers": [{"name": "Content-Type", "value": "application/json"}]
            },
            {
                "@type": "HttpPOST",
                "name": "❌ Reject",
                "target": f"{callback}/api/approval_callback",
                "body": json.dumps({"decision": "reject", "incident": incident}),
                "headers": [{"name": "Content-Type", "value": "application/json"}]
            }
        ]
    }

    requests.post(webhook, json=card, timeout=10)

# ================= Lookup SOP =================
@app.function_name(name="lookup_sop")
@app.route(route="lookup_sop", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def lookup_sop(req: func.HttpRequest) -> func.HttpResponse:
    incident = req.params.get("incident")
    if not incident:
        return func.HttpResponse("Missing incident", status_code=400)

    api = os.getenv("SOP_GITHUB_API")
    token = os.getenv("GITHUB_TOKEN")

    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    url = f"{api}/{incident}.json"

    r = requests.get(url, headers=headers, timeout=10)

    if r.status_code == 404:
        return func.HttpResponse(json.dumps({"found": False}), mimetype="application/json")

    data = r.json()
    import base64
    sop = json.loads(base64.b64decode(data["content"]).decode("utf-8"))

    return func.HttpResponse(json.dumps({"found": True, "sop": sop}), mimetype="application/json")

# ================= Agent webhook =================
@app.function_name(name="agent_webhook")
@app.route(route="agent_webhook", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def agent_webhook(req: func.HttpRequest) -> func.HttpResponse:
    payload = req.get_json()
    alert = payload["alerts"][0]

    incident = alert["labels"].get("alertname")

    sop_lookup = requests.get(
        f"{os.getenv('CALLBACK_BASE_URL')}/api/lookup_sop?incident={incident}",
        timeout=5
    ).json()

    if sop_lookup.get("found"):
        send_teams_approval_card(incident, sop_lookup["sop"])
        return func.HttpResponse(json.dumps({"status": "waiting_for_approval", "incident": incident}), mimetype="application/json")

    return func.HttpResponse(json.dumps({"status": "no_sop_found", "incident": incident}), mimetype="application/json")

# ================= Approval callback =================
@app.function_name(name="approval_callback")
@app.route(route="approval_callback", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def approval_callback(req: func.HttpRequest) -> func.HttpResponse:
    data = req.get_json()
    decision = data.get("decision")
    incident = data.get("incident")

    return func.HttpResponse(json.dumps({"decision": decision, "incident": incident}), mimetype="application/json")
