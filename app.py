import json
import os
from datetime import datetime

from flask import Flask, flash, redirect, render_template, request, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")
DATA_FILE = os.path.join(os.path.dirname(__file__), "ips_data.json")


def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def default_state():
    return {
        "sensors": [
            {"id": "sensor-01", "name": "DMZ Web Sensor", "status": "online", "throughput": "2.7 Gbps", "blocked_today": 138},
            {"id": "sensor-02", "name": "Core Network Sensor", "status": "online", "throughput": "3.9 Gbps", "blocked_today": 242},
            {"id": "sensor-03", "name": "Endpoint IDS", "status": "degraded", "throughput": "1.3 Gbps", "blocked_today": 91},
        ],
        "policies": {
            "mode": "inline",
            "default_action": "deny",
            "alert_threshold": "medium",
            "response": "active",
            "inspection": "deep",
            "retention_days": 180,
        },
        "rules": [
            {
                "id": 1,
                "name": "SIG-1001",
                "category": "Web Exploit",
                "severity": "critical",
                "action": "deny",
                "description": "Detect SQL injection patterns in request strings.",
                "enabled": True,
            },
            {
                "id": 2,
                "name": "SIG-2002",
                "category": "Brute Force",
                "severity": "high",
                "action": "block",
                "description": "Multiple failed admin logins from the same source.",
                "enabled": True,
            },
            {
                "id": 3,
                "name": "SIG-3003",
                "category": "C2 Beaconing",
                "severity": "medium",
                "action": "alert",
                "description": "Periodic outbound connections to suspicious domains.",
                "enabled": True,
            },
        ],
        "incidents": [
            {
                "id": 1001,
                "title": "Credential stuffing against admin portal",
                "severity": "high",
                "status": "open",
                "src_ip": "203.0.113.45",
                "sensor": "sensor-02",
                "created_at": "2026-09-21T11:20:00Z",
            },
            {
                "id": 1002,
                "title": "Outbound command-and-control beacon",
                "severity": "medium",
                "status": "investigating",
                "src_ip": "198.51.100.77",
                "sensor": "sensor-01",
                "created_at": "2026-09-21T09:40:00Z",
            },
        ],
        "events": [
            {
                "id": 1,
                "timestamp": "2026-09-21T12:35:00Z",
                "sensor": "sensor-01",
                "src_ip": "203.0.113.45",
                "dst_ip": "10.20.30.45",
                "signature": "SIG-1001",
                "severity": "critical",
                "action": "block",
                "summary": "SQLi payload matched in HTTP request body.",
            },
            {
                "id": 2,
                "timestamp": "2026-09-21T12:18:00Z",
                "sensor": "sensor-02",
                "src_ip": "198.51.100.77",
                "dst_ip": "172.16.10.8",
                "signature": "SIG-3003",
                "severity": "medium",
                "action": "alert",
                "summary": "Beaconing to suspicious external domain.",
            },
            {
                "id": 3,
                "timestamp": "2026-09-21T11:48:00Z",
                "sensor": "sensor-02",
                "src_ip": "203.0.113.1",
                "dst_ip": "10.10.10.25",
                "signature": "SIG-2002",
                "severity": "high",
                "action": "block",
                "summary": "Repeated failed login attempts on admin service.",
            },
            {
                "id": 4,
                "timestamp": "2026-09-21T11:30:00Z",
                "sensor": "sensor-03",
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.90",
                "signature": "SIG-3003",
                "severity": "low",
                "action": "monitor",
                "summary": "Low confidence suspicious beaconing pattern observed.",
            },
        ],
    }


def load_state():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as file:
            try:
                data = json.load(file)
                if data:
                    return data
            except json.JSONDecodeError:
                pass
    state = default_state()
    save_state(state)
    return state


def save_state(state):
    with open(DATA_FILE, "w", encoding="utf-8") as file:
        json.dump(state, file, indent=2)


def signature_summary(events):
    counts = {}
    for event in events:
        key = event["signature"]
        counts[key] = counts.get(key, 0) + 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)


@app.route("/")
def dashboard():
    state = load_state()
    events = state["events"]
    stats = {
        "total_events": len(events),
        "blocked": sum(1 for event in events if event["action"] == "block"),
        "critical": sum(1 for event in events if event["severity"] == "critical"),
        "open_incidents": sum(1 for incident in state["incidents"] if incident["status"] == "open"),
    }
    return render_template(
        "dashboard.html",
        state=state,
        stats=stats,
        signatures=signature_summary(events),
    )


@app.route("/incidents")
def incidents():
    state = load_state()
    return render_template("incidents.html", incidents=state["incidents"])


@app.route("/rules")
def rules():
    state = load_state()
    return render_template("rules.html", rules=state["rules"])


@app.route("/policies")
def policies():
    state = load_state()
    return render_template("policies.html", policies=state["policies"], sensors=state["sensors"])


@app.route("/simulate_event", methods=["POST"])
def simulate_event():
    state = load_state()
    event = {
        "id": (max((item["id"] for item in state["events"]), default=0) + 1),
        "timestamp": now_iso(),
        "sensor": request.form.get("sensor", "sensor-01"),
        "src_ip": request.form.get("src_ip", "203.0.113.99"),
        "dst_ip": request.form.get("dst_ip", "10.10.10.22"),
        "signature": request.form.get("signature", "SIG-4004"),
        "severity": request.form.get("severity", "medium"),
        "action": request.form.get("action", "alert"),
        "summary": request.form.get("summary", "Manual IPS simulation triggered from security operations console."),
    }
    state["events"].insert(0, event)
    incident_created = False

    if event["severity"] in {"high", "critical"}:
        incident = {
            "id": (max((item["id"] for item in state["incidents"]), default=0) + 1),
            "title": f"{event['signature']} activity from {event['src_ip']}",
            "severity": event["severity"],
            "status": "open",
            "src_ip": event["src_ip"],
            "sensor": event["sensor"],
            "created_at": now_iso(),
        }
        state["incidents"].insert(0, incident)
        incident_created = True

    save_state(state)
    flash(
        f"Event {event['signature']} from {event['src_ip']} was created successfully.",
        "success",
    )
    if incident_created:
        flash("A linked incident was opened automatically for this event.", "info")
    return redirect(url_for("dashboard"))


@app.route("/add_rule", methods=["POST"])
def add_rule():
    state = load_state()
    new_rule = {
        "id": (max((rule["id"] for rule in state["rules"]), default=0) + 1),
        "name": request.form.get("name", "SIG-XXXX"),
        "category": request.form.get("category", "Custom"),
        "severity": request.form.get("severity", "medium"),
        "action": request.form.get("action", "alert"),
        "description": request.form.get("description", "Custom rule added from management console."),
        "enabled": True,
    }
    state["rules"].append(new_rule)
    save_state(state)
    return redirect(url_for("rules"))


@app.route("/toggle_rule/<int:rule_id>", methods=["POST"])
def toggle_rule(rule_id):
    state = load_state()
    for rule in state["rules"]:
        if rule["id"] == rule_id:
            rule["enabled"] = not rule["enabled"]
            break
    save_state(state)
    return redirect(url_for("rules"))


@app.route("/update_policy", methods=["POST"])
def update_policy():
    state = load_state()
    state["policies"] = {
        "mode": request.form.get("mode", state["policies"].get("mode")),
        "default_action": request.form.get("default_action", state["policies"].get("default_action")),
        "alert_threshold": request.form.get("alert_threshold", state["policies"].get("alert_threshold")),
        "response": request.form.get("response", state["policies"].get("response")),
        "inspection": request.form.get("inspection", state["policies"].get("inspection")),
        "retention_days": int(request.form.get("retention_days", state["policies"].get("retention_days"))),
    }
    save_state(state)
    return redirect(url_for("policies"))


@app.route("/close_incident/<int:incident_id>", methods=["POST"])
def close_incident(incident_id):
    state = load_state()
    for incident in state["incidents"]:
        if incident["id"] == incident_id:
            incident["status"] = "closed"
            incident["closed_at"] = now_iso()
            break
    save_state(state)
    return redirect(url_for("incidents"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
