import json
import os
from datetime import datetime

LOG_FILE = "data/audit_log.json"

def log_transaction(payload: dict):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    payload["timestamp"] = datetime.utcnow().isoformat() + "Z"
    try:
        logs = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    logs = json.loads(content)
        logs.append(payload)
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"Error writing audit logs: {e}")