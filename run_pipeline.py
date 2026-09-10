import os
import json
import subprocess
import glob
import datetime
from collections import defaultdict
from groq import Groq
from pydantic import BaseModel, ValidationError
from typing import Optional, List

# --- Setup ---
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
LOG_FILE = os.path.expanduser("~/cowrie_latest.json")

class SessionAnalysis(BaseModel):
    prediction_available: bool
    risk_level: str
    current_stage: str
    predicted_next_action: Optional[str]
    confidence: Optional[int]
    reasoning: List[str]
    prediction_note: Optional[str]

ANALYSIS_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "session_analysis",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "prediction_available": {"type": "boolean"},
                "risk_level": {"type": "string", "enum": ["Low", "Medium", "High"]},
                "current_stage": {"type": "string"},
                "predicted_next_action": {"type": ["string", "null"]},
                "confidence": {"type": ["integer", "null"]},
                "reasoning": {"type": "array", "items": {"type": "string"}},
                "prediction_note": {"type": ["string", "null"]}
            },
            "required": ["prediction_available", "risk_level", "current_stage",
                         "predicted_next_action", "confidence", "reasoning", "prediction_note"],
            "additionalProperties": False
        }
    }
}

print("Step 1/4: Copying fresh logs from Cowrie...")
subprocess.run([
    "docker", "cp",
    "cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json",
    LOG_FILE
])

print("Step 2/4: Parsing sessions...")
sessions = defaultdict(lambda: {"commands": [], "downloads": [], "src_ip": None})

with open(LOG_FILE, "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        sid = entry.get("session")
        if not sid:
            continue
        event = entry.get("eventid", "")
        if event == "cowrie.session.connect":
            sessions[sid]["src_ip"] = entry.get("src_ip")
        elif event == "cowrie.command.input":
            cmd = entry.get("input")
            if cmd:
                sessions[sid]["commands"].append(cmd)
        elif event == "cowrie.session.file_download":
            sessions[sid]["downloads"].append(entry.get("url"))

print("Step 3/4: Sending sessions to AI for analysis...")
os.makedirs("analyses", exist_ok=True)

for sid, data in sessions.items():
    if not data["commands"]:
        continue

    commands_text = "\n".join(f"{i+1}. {cmd}" for i, cmd in enumerate(data["commands"]))

    prompt = f"""You are a cybersecurity analyst reviewing a honeypot session log.
Below is a sequence of commands typed by an attacker who connected to an SSH honeypot.

Commands (in order):
{commands_text}

Files downloaded: {data['downloads'] if data['downloads'] else 'None'}

Analyze this session as a completed attack sequence. Classify current_stage using
a MITRE ATT&CK-style stage name based on the most advanced behavior observed
(e.g. Reconnaissance, Discovery, Credential Access, Ingress Tool Transfer).

Even though this session has ended, predict what this attacker would likely do
NEXT if they reconnected or continued this attack chain, based on the pattern of
behavior observed (e.g. an attacker who downloaded a payload would likely execute
it next). This is a standard threat-intelligence practice: predicting likely
next steps in an attack chain, not literally the next keystroke.

Only set prediction_available to false if the session had zero meaningful
commands (e.g. the attacker connected and disconnected with no activity at all).
"""

    print(f"  Analyzing session {sid}...")

    analysis = None
    raw_response_text = None

    try:
        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[{"role": "user", "content": prompt}],
            response_format=ANALYSIS_SCHEMA
        )
        raw_response_text = response.choices[0].message.content
        parsed = json.loads(raw_response_text)
        analysis = SessionAnalysis(**parsed)
    except (json.JSONDecodeError, ValidationError, Exception) as e:
        print(f"    Warning: could not get valid analysis for {sid}: {e}")

    with open(f"analyses/{sid}.json", "w") as f:
        json.dump({
            "session_id": sid,
            "src_ip": data["src_ip"],
            "commands": data["commands"],
            "raw_ai_response": raw_response_text,
            "parsed_analysis": analysis.model_dump() if analysis else None
        }, f, indent=2)

print("Step 4/4: Building dashboard...")

sessions_for_dashboard = []
for filepath in glob.glob("analyses/*.json"):
    with open(filepath, "r") as f:
        sessions_for_dashboard.append(json.load(f))

risk_order = {"High": 0, "Medium": 1, "Low": 2}
colors = {"Low": "#22c55e", "Medium": "#f59e0b", "High": "#ef4444"}
colors_bg = {"Low": "#f0fdf4", "Medium": "#fffbeb", "High": "#fef2f2"}

def sort_key(s):
    a = s.get("parsed_analysis")
    return risk_order.get(a["risk_level"], 3) if a else 3

sessions_for_dashboard.sort(key=sort_key)

cards_html = ""
high_count = med_count = low_count = 0

for s in sessions_for_dashboard:
    analysis = s.get("parsed_analysis")
    sid = s["session_id"]
    src_ip = s["src_ip"]
    num_commands = len(s["commands"])

    if not analysis:
        cards_html += f"""
        <div class="card">
            <div class="card-header">
                <div><h3>Session {sid}</h3>
                <p class="meta">Source IP: {src_ip} &nbsp;\u2022&nbsp; {num_commands} commands run</p></div>
                <span class="badge" style="background:#94a3b8">Analysis Failed</span>
            </div>
            <div class="analysis" style="border-left-color:#94a3b8; background:#f8fafc;">
                The AI analysis could not be completed for this session.
            </div>
        </div>
        """
        continue

    risk = analysis["risk_level"]
    if risk == "High": high_count += 1
    elif risk == "Medium": med_count += 1
    else: low_count += 1

    if analysis["prediction_available"]:
        prediction_block = f"""
        <p><strong>Predicted Next Action:</strong> {analysis['predicted_next_action']}</p>
        <div class="confidence-row">
            <span>Confidence: {analysis['confidence']}%</span>
            <span class="info-icon" title="AI-generated estimate, not a statistically calibrated probability">\u24d8</span>
        </div>
        <div class="confidence-bar-bg">
            <div class="confidence-bar-fill" style="width:{analysis['confidence']}%; background:{colors[risk]}"></div>
        </div>
        <p class="reasoning-label">Why this prediction?</p>
        <ul class="reasoning-list">
        """
        for r in analysis["reasoning"]:
            prediction_block += f"<li>{r}</li>"
        prediction_block += "</ul>"
    else:
        note = analysis['prediction_note'] if analysis['prediction_note'] else "Not enough activity in this session to predict a next action."
        prediction_block = f"""<p class="unavailable">Prediction unavailable \u2014 {note}</p>"""

    cards_html += f"""
    <div class="card">
        <div class="card-header">
            <div><h3>Session {sid}</h3>
            <p class="meta">Source IP: {src_ip} &nbsp;\u2022&nbsp; {num_commands} commands run &nbsp;\u2022&nbsp; Stage: {analysis['current_stage']}</p></div>
            <span class="badge" style="background:{colors[risk]}">{risk} Risk</span>
        </div>
        <div class="analysis" style="border-left-color:{colors[risk]}; background:{colors_bg[risk]}">
            {prediction_block}
        </div>
    </div>
    """

timestamp = datetime.datetime.now().strftime("%B %d, %Y at %I:%M %p")
total = len(sessions_for_dashboard)

html_page = f"""
<!DOCTYPE html>
<html>
<head>
<title>Honeypot Attacker Analysis Dashboard</title>
<meta charset="UTF-8">
<style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        margin: 0; padding: 40px 20px; min-height: 100vh; }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    .header {{ background: linear-gradient(135deg, #6366f1, #8b5cf6);
        border-radius: 16px; padding: 32px; color: white; margin-bottom: 24px;
        box-shadow: 0 10px 30px rgba(99,102,241,0.3); }}
    .header h1 {{ margin: 0 0 8px 0; font-size: 26px; }}
    .header .status {{ display:flex; justify-content:space-between; align-items:center; margin-top:12px; }}
    .header .badge-monitoring {{ background:rgba(255,255,255,0.2); padding:4px 14px; border-radius:20px; font-size:13px; }}
    .header p {{ margin: 0; opacity: 0.9; font-size: 14px; }}
    .stats {{ display: flex; gap: 16px; margin-bottom: 24px; }}
    .stat-box {{ flex: 1; background: white; border-radius: 12px; padding: 20px;
        text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
    .stat-box .num {{ font-size: 32px; font-weight: bold; }}
    .stat-box .label {{ color: #64748b; font-size: 13px; margin-top: 4px; }}
    .card {{ background: white; border-radius: 14px; padding: 24px; margin-bottom: 18px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08); }}
    .card-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }}
    .card-header h3 {{ margin: 0; font-size: 18px; color: #1e293b; }}
    .meta {{ color: #64748b; font-size: 13px; margin: 6px 0 0 0; }}
    .badge {{ color: white; padding: 6px 16px; border-radius: 20px; font-size: 13px; font-weight: 600; white-space: nowrap; }}
    .analysis {{ padding: 16px; border-radius: 8px; border-left: 4px solid; font-size: 14px; line-height: 1.6; color: #334155; }}
    .confidence-row {{ display:flex; align-items:center; gap:6px; margin-top:10px; font-weight:600; }}
    .info-icon {{ cursor:help; color:#94a3b8; font-size:13px; }}
    .confidence-bar-bg {{ background:#e2e8f0; border-radius:6px; height:8px; margin:6px 0 14px 0; overflow:hidden; }}
    .confidence-bar-fill {{ height:100%; border-radius:6px; }}
    .reasoning-label {{ font-weight:600; margin:12px 0 4px 0; }}
    .reasoning-list {{ margin:0; padding-left:20px; }}
    .reasoning-list li {{ margin-bottom:4px; }}
    .unavailable {{ font-style:italic; color:#64748b; }}
    .timestamp {{ text-align: center; color: #94a3b8; font-size: 13px; margin-top: 24px; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>\U0001f36f Honeypot Attacker Analysis Dashboard</h1>
        <p>SSH Honeypot \u2014 AI-assisted behaviour analysis and next-action prediction</p>
        <div class="status">
            <span class="badge-monitoring">\u25cf MONITORING</span>
            <span style="font-size:13px;">Last updated: {timestamp}</span>
        </div>
    </div>
    <div class="stats">
        <div class="stat-box"><div class="num" style="color:#ef4444">{high_count}</div><div class="label">High Risk</div></div>
        <div class="stat-box"><div class="num" style="color:#f59e0b">{med_count}</div><div class="label">Medium Risk</div></div>
        <div class="stat-box"><div class="num" style="color:#22c55e">{low_count}</div><div class="label">Low Risk</div></div>
        <div class="stat-box"><div class="num" style="color:#6366f1">{total}</div><div class="label">Total Sessions</div></div>
    </div>
    {cards_html}
    <p class="timestamp">Confidence values are AI-generated estimates, not statistically calibrated probabilities.</p>
</div>
</body>
</html>
"""

with open("dashboard.html", "w") as f:
    f.write(html_page)

print("\nAll done! Run 'xdg-open dashboard.html' to view it.")
