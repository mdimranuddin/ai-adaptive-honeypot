import json
import os
import glob
import datetime

# --- Load every session's saved analysis from the analyses/ folder ---
sessions = []
for filepath in glob.glob("analyses/*.json"):
    with open(filepath, "r") as f:
        sessions.append(json.load(f))

# --- Build display data for each session ---
risk_order = {"High": 0, "Medium": 1, "Low": 2}
colors = {"Low": "#22c55e", "Medium": "#f59e0b", "High": "#ef4444"}
colors_bg = {"Low": "#f0fdf4", "Medium": "#fffbeb", "High": "#fef2f2"}

cards_html = ""
high_count = med_count = low_count = 0

# Sort: sessions with a failed/missing analysis go last; otherwise by risk
def sort_key(s):
    analysis = s.get("parsed_analysis")
    if not analysis:
        return 3
    return risk_order.get(analysis["risk_level"], 3)

sessions.sort(key=sort_key)

for s in sessions:
    analysis = s.get("parsed_analysis")
    sid = s["session_id"]
    src_ip = s["src_ip"]
    num_commands = len(s["commands"])

    if not analysis:
        # Analysis failed for this session entirely
        cards_html += f"""
        <div class="card">
            <div class="card-header">
                <div>
                    <h3>Session {sid}</h3>
                    <p class="meta">Source IP: {src_ip} &nbsp;•&nbsp; {num_commands} commands run</p>
                </div>
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
            <span class="info-icon" title="AI-generated estimate, not a statistically calibrated probability">ⓘ</span>
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
        prediction_block = f"""
        <p class="unavailable">Prediction unavailable — {note}</p>
        """

    cards_html += f"""
    <div class="card">
        <div class="card-header">
            <div>
                <h3>Session {sid}</h3>
                <p class="meta">Source IP: {src_ip} &nbsp;•&nbsp; {num_commands} commands run &nbsp;•&nbsp; Stage: {analysis['current_stage']}</p>
            </div>
            <span class="badge" style="background:{colors[risk]}">{risk} Risk</span>
        </div>
        <div class="analysis" style="border-left-color:{colors[risk]}; background:{colors_bg[risk]}">
            {prediction_block}
        </div>
    </div>
    """

timestamp = datetime.datetime.now().strftime("%B %d, %Y at %I:%M %p")
total = len(sessions)

html_page = f"""
<!DOCTYPE html>
<html>
<head>
<title>Honeypot Attacker Analysis Dashboard</title>
<meta charset="UTF-8">
<style>
    * {{ box-sizing: border-box; }}
    body {{
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        margin: 0; padding: 40px 20px; min-height: 100vh;
    }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    .header {{
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        border-radius: 16px; padding: 32px; color: white; margin-bottom: 24px;
        box-shadow: 0 10px 30px rgba(99,102,241,0.3);
    }}
    .header h1 {{ margin: 0 0 8px 0; font-size: 26px; }}
    .header .status {{ display:flex; justify-content:space-between; align-items:center; margin-top:12px; }}
    .header .badge-monitoring {{ background:rgba(255,255,255,0.2); padding:4px 14px; border-radius:20px; font-size:13px; }}
    .header p {{ margin: 0; opacity: 0.9; font-size: 14px; }}
    .stats {{ display: flex; gap: 16px; margin-bottom: 24px; }}
    .stat-box {{
        flex: 1; background: white; border-radius: 12px; padding: 20px;
        text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }}
    .stat-box .num {{ font-size: 32px; font-weight: bold; }}
    .stat-box .label {{ color: #64748b; font-size: 13px; margin-top: 4px; }}
    .card {{
        background: white; border-radius: 14px; padding: 24px; margin-bottom: 18px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    }}
    .card-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }}
    .card-header h3 {{ margin: 0; font-size: 18px; color: #1e293b; }}
    .meta {{ color: #64748b; font-size: 13px; margin: 6px 0 0 0; }}
    .badge {{
        color: white; padding: 6px 16px; border-radius: 20px;
        font-size: 13px; font-weight: 600; white-space: nowrap;
    }}
    .analysis {{
        padding: 16px; border-radius: 8px; border-left: 4px solid;
        font-size: 14px; line-height: 1.6; color: #334155;
    }}
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
        <h1>🍯 Honeypot Attacker Analysis Dashboard</h1>
        <p>SSH Honeypot — AI-assisted behaviour analysis and next-action prediction</p>
        <div class="status">
            <span class="badge-monitoring">● MONITORING</span>
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

print("Dashboard saved to dashboard.html")
