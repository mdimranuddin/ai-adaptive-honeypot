# AI-Assisted Adaptive Honeypot for Attacker Behaviour Analysis and Next-Action Prediction

A working proof-of-concept system that deploys a decoy SSH server (honeypot), captures real attacker interactions, and uses an AI model to classify attack behaviour and predict likely next actions — with full explainability and an auditable evidence trail.

## 🔗 Live Dashboard Demo
[View Live Site](https://mdimranuddin.github.io/ai-adaptive-honeypot/dashboard.html) — real analyzed sessions and AI predictions

## What it does

1. **Honeypot** — [Cowrie](https://github.com/cowrie/cowrie) runs in Docker, emulating a realistic Linux SSH server to attract and log attacker activity.
2. **Public exposure** — exposed to the internet via a TCP tunnel, so real (not simulated) attacker traffic reaches it.
3. **Structured logging** — every session (commands, timestamps, file downloads) is captured as structured JSON.
4. **AI analysis** — each session is sent to an LLM (via the Groq API) with a **strict JSON schema**, forcing a reliable, structured response:
   - Risk level (Low / Medium / High)
   - Current attack stage (MITRE ATT&CK-style classification)
   - Predicted next action, with a confidence estimate
   - Itemized reasoning/evidence for the prediction
5. **Validation** — every AI response is validated with Pydantic before use; malformed responses degrade gracefully instead of crashing.
6. **Audit trail** — both the raw AI response and the parsed result are saved per session, so every conclusion is independently verifiable.
7. **Dashboard** — a generated HTML report visualizing all analyzed sessions, sorted by risk.

## Architecture

```
Internet Attacker
      ↓
SSH Honeypot (Cowrie, Docker)
      ↓
Structured JSON Logs
      ↓
Log Parser (Python)
      ↓
AI Model (Groq, strict JSON schema)
      ↓
Validation (Pydantic)
      ↓
Saved Results + Raw Response (audit trail)
      ↓
Dashboard (HTML)
```

## Tech stack

- **Honeypot:** Cowrie, Docker
- **Backend:** Python 3
- **AI:** Groq API (`openai/gpt-oss-120b`), structured JSON schema output
- **Validation:** Pydantic
- **Frontend:** Generated static HTML/CSS dashboard

## Example output

A real captured session (commands included `whoami`, `cat /etc/shadow`, `wget [payload]`) was automatically classified as:

- **Risk Level:** High
- **Stage:** Ingress Tool Transfer
- **Predicted Next Action:** Execute the downloaded payload
- **Confidence:** 85%
- **Reasoning:** 5 itemized behavioural observations drawn directly from the session log

## Setup

1. Clone this repo
2. Install dependencies: `pip3 install groq pydantic`
3. Set your Groq API key as an environment variable (never hardcode it):
```bash
   export GROQ_API_KEY="your_key_here"
```
4. Start the honeypot: `docker run -d --name cowrie -p 2222:2222 cowrie/cowrie`
5. Expose it publicly (e.g. via a TCP tunnel tool of your choice)
6. Run the full pipeline: `python3 run_pipeline.py`
7. Open `dashboard.html` to view results

## Project structure

```
├── analyze_session.py   # Parses logs, sends sessions to AI, validates + saves results
├── run_pipeline.py       # One-command automation: logs → AI → dashboard
├── make_dashboard.py     # Builds the HTML dashboard
├── parse_logs.py         # Standalone log parsing utility
├── analyses/              # Per-session AI audit trail (raw + parsed responses)
└── dashboard.html         # Generated visual report
```

## Known limitations / Future work

- **Attacker geolocation not currently captured** — the tunnel-based exposure method doesn't preserve real source IPs. Resolvable by deploying on a cloud VM with a direct public IP.
- **Adaptive behaviour not yet implemented** — the system currently observes and analyzes but does not yet modify honeypot behaviour based on predictions.
- **Prediction confidence is not statistically calibrated** — it's a self-reported estimate from the language model, treated as a qualitative signal rather than a measured probability.
- **Dataset is currently limited** — most analyzed sessions to date are controlled test sessions; genuine unsolicited attacker traffic is being collected but takes time to accumulate meaningfully.

## Responsible use

This project only analyzes activity on infrastructure the author owns and controls. The AI component is used purely for observational classification and summarization — it is never used to generate exploit code, malware, or offensive tooling.

## License

This project is for educational and research purposes.
