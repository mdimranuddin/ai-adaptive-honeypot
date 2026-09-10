import json
from collections import defaultdict

# Read the raw Cowrie log file (one JSON object per line)
LOG_FILE = "/home/miskat/cowrie_latest.json"

sessions = defaultdict(lambda: {"commands": [], "downloads": [], "connect_time": None, "close_time": None, "src_ip": None})

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
            sessions[sid]["connect_time"] = entry.get("timestamp")
            sessions[sid]["src_ip"] = entry.get("src_ip")
        elif event == "cowrie.command.input":
            sessions[sid]["commands"].append(entry.get("input"))
        elif event == "cowrie.session.file_download":
            sessions[sid]["downloads"].append(entry.get("url"))
        elif event == "cowrie.session.closed":
            sessions[sid]["close_time"] = entry.get("timestamp")

# Print a clean summary per session
for sid, data in sessions.items():
    if not data["commands"]:
        continue  # skip sessions where nobody actually typed anything (pure scanners)
    print("=" * 50)
    print(f"Session: {sid}")
    print(f"Source IP: {data['src_ip']}")
    print(f"Connected: {data['connect_time']}")
    print(f"Closed: {data['close_time']}")
    print(f"Commands run ({len(data['commands'])}):")
    for i, cmd in enumerate(data["commands"], 1):
        print(f"  {i}. {cmd}")
    if data["downloads"]:
        print(f"Files downloaded: {data['downloads']}")
