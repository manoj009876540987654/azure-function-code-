import azure.functions as func
import json, os, requests, base64
from openai import OpenAI

app = func.FunctionApp()

# OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# ========== AI Remediation Helper ==========
def generate_ai_remediation(incident, description):
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    prompt = f"""
You are a senior Site Reliability Engineer.

Incident: {incident}
Description: {description}

Give:
1. Likely root cause
2. Step-by-step Linux remediation commands
3. Any safety warning if needed
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


# ========== Lookup SOP from GitHub ==========
@app.function_name(name="lookup_sop")
@app.route(route="lookup_sop", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def lookup_sop(req: func.HttpRequest) -> func.HttpResponse:
    try:
        incident = req.params.get("incident") or req.params.get("error_key")

        if not incident:
            return func.HttpResponse("Missing incident parameter", status_code=400)

        github_api = os.getenv("SOP_GITHUB_API")
        token = os.getenv("GITHUB_TOKEN")

        if not github_api or not token:
            return func.HttpResponse("Missing GitHub configuration", status_code=500)

        url = f"{github_api}/{incident}.json"
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}

        r = requests.get(url, headers=headers, timeout=10)

        if r.status_code == 404:
            return func.HttpResponse(json.dumps({"found": False}), mimetype="application/json")

        if r.status_code != 200:
            return func.HttpResponse(f"GitHub error {r.status_code}: {r.text}", status_code=500)

        data = r.json()
        decoded = base64.b64decode(data["content"]).decode("utf-8")
        sop = json.loads(decoded)

        return func.HttpResponse(json.dumps({"found": True, "sop": sop}), mimetype="application/json")

    except Exception as e:
        return func.HttpResponse(f"Internal error: {str(e)}", status_code=500)


# ========== Send Approval Card to Teams ==========
@app.function_name(name="send_approval_card")
@app.route(route="send_approval_card", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def send_approval_card(req: func.HttpRequest) -> func.HttpResponse:
    try:
        payload = req.get_json()

        alert = payload.get("alerts", [])[0]

        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})

        incident = labels.get("alertname", "unknown")
        severity = labels.get("severity", "unknown")

        context = {
            "incident": incident,
            "severity": severity,
            "labels": labels,
            "annotations": annotations,
            "startsAt": alert.get("startsAt"),
            "generatorURL": alert.get("generatorURL"),
        }

        webhook = os.getenv("TEAMS_WEBHOOK_URL")
        callback = os.getenv("CALLBACK_BASE_URL")

        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": f"Incident {incident}",
            "title": f"🚨 {incident} ({severity})",
            "sections": [{
                "facts": [{"name": k, "value": str(v)} for k,v in context.items()]
            }],
            "potentialAction": [{
                "@type": "HttpPOST",
                "name": "Investigate",
                "target": f"{callback}/api/approval_callback",
                "body": json.dumps(context),
                "headers": [{"name": "Content-Type", "value": "application/json"}]
            }]
        }

        requests.post(webhook, json=card, timeout=10)
        return func.HttpResponse(json.dumps({"status": "sent"}), mimetype="application/json")

    except Exception as e:
        return func.HttpResponse(str(e), status_code=500)

                    
# ========== Approval Callback ==========
@app.function_name(name="approval_callback")
@app.route(route="approval_callback", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def approval_callback(req: func.HttpRequest) -> func.HttpResponse:
    try:
        data = req.get_json()
        decision = data.get("decision")
        incident = data.get("incident")
        description = data.get("description", "")

        if not decision or not incident:
            return func.HttpResponse(json.dumps({"error": "Missing decision or incident"}), status_code=400)

        if decision == "approve":
            sop_lookup = requests.get(
                f"{os.getenv('CALLBACK_BASE_URL')}/api/lookup_sop?incident={incident}", timeout=5
            ).json()

            if sop_lookup.get("found"):
                status = "approved_sop"
            else:
                ai_solution = generate_ai_remediation(incident, description)
                webhook = os.getenv("TEAMS_WEBHOOK_URL")

                requests.post(webhook, json={
                    "text": f"🤖 AI suggested remediation for **{incident}**:\n\n{ai_solution}"
                }, timeout=10)

                status = "approved_ai"

        elif decision == "reject":
            status = "rejected"

        else:
            return func.HttpResponse(json.dumps({"error": "Invalid decision"}), status_code=400)

        return func.HttpResponse(json.dumps({"status": status, "incident": incident}), mimetype="application/json")

    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)


# ========== Save SOP to GitHub ==========
@app.function_name(name="save_sop")
@app.route(route="save_sop", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def save_sop(req: func.HttpRequest) -> func.HttpResponse:
    try:
        data = req.get_json()
        error_key = data.get("error_key")
        sop = data.get("sop")

        api = os.getenv("SOP_GITHUB_API")
        token = os.getenv("GITHUB_TOKEN")

        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}

        payload = {
            "message": f"Add SOP for {error_key}",
            "content": base64.b64encode(json.dumps(sop, indent=2).encode()).decode()
        }

        requests.put(f"{api}/{error_key}.json", headers=headers, json=payload, timeout=10)
        return func.HttpResponse(json.dumps({"status": "saved"}), mimetype="application/json")

    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)

