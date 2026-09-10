import os
import json
from collections import defaultdict
from groq import Groq
from pydantic import BaseModel, ValidationError
from typing import Optional, List

# --- Setup ---
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
LOG_FILE = "/home/miskat/cowrie_latest.json"

# --- Data contract: what a valid analysis result must look like ---
class SessionAnalysis(BaseModel):
    prediction_available: bool
    risk_level: str
    current_stage: str
    predicted_next_action: Optional[str]
    confidence: Optional[int]
    reasoning: List[str]
    prediction_note: Optional[str]

# --- The JSON schema we force Groq to follow ---
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

# --- Step 1: Parse the log file into sessions ---
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

# --- Step 2: Analyze every session that has commands ---
os.makedirs("analyses", exist_ok=True)
output_lines = []

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

    print(f"Analyzing session {sid}...")

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
        print(f"  Warning: could not get valid analysis for {sid}: {e}")

    # Save raw + parsed data for every session, for audit purposes
    with open(f"analyses/{sid}.json", "w") as f:
        json.dump({
            "session_id": sid,
            "src_ip": data["src_ip"],
            "commands": data["commands"],
            "raw_ai_response": raw_response_text,
            "parsed_analysis": analysis.model_dump() if analysis else None
        }, f, indent=2)

    output_lines.append("=" * 60)
    output_lines.append(f"Session: {sid}")
    output_lines.append(f"Source IP: {data['src_ip']}")
    output_lines.append(f"Commands run: {len(data['commands'])}")
    output_lines.append("-" * 60)
    if analysis:
        output_lines.append(f"Risk Level: {analysis.risk_level}")
        output_lines.append(f"Current Stage: {analysis.current_stage}")
        if analysis.prediction_available:
            output_lines.append(f"Predicted Next Action: {analysis.predicted_next_action}")
            output_lines.append(f"Confidence: {analysis.confidence}%")
            output_lines.append("Reasoning:")
            for r in analysis.reasoning:
                output_lines.append(f"  - {r}")
        else:
            note = analysis.prediction_note if analysis.prediction_note else "Not enough activity in this session to predict a next action."
            output_lines.append(f"Prediction unavailable: {note}")
    else:
        output_lines.append("Analysis failed for this session.")
    output_lines.append("")

with open("analysis_results.txt", "w") as f:
    f.write("\n".join(output_lines))

print("\nDone! Results saved to analysis_results.txt and analyses/ folder.")














