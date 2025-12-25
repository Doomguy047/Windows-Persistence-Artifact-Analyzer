import json
import os

SUSPICIOUS_PATHS = [
    "\\AppData\\Local\\Temp",
    "\\Users\\Public",
    "\\AppData\\Roaming"
]

def load_json(path):
    with open(path) as f:
        return json.load(f)

def is_suspicious_path(command):
    return any(p.lower() in command.lower() for p in SUSPICIOUS_PATHS)

def analyze_run_keys(run_keys):
    findings = []
    for entry in run_keys:
        if is_suspicious_path(entry["command"]):
            findings.append({
                "artifact": "Registry Run Key",
                "location": entry["key"],
                "name": entry["name"],
                "finding": "Suspicious autorun entry",
                "reason": "Executes from user-writable directory"
            })
    return findings

def analyze_scheduled_tasks(tasks):
    findings = []
    for task in tasks:
        if task["run_as"] == "SYSTEM" and is_suspicious_path(task["command"]):
            findings.append({
                "artifact": "Scheduled Task",
                "name": task["name"],
                "finding": "High-risk scheduled task",
                "reason": "Runs as SYSTEM from user-writable path"
            })
    return findings

def analyze_services(services):
    findings = []
    for svc in services:
        if svc["run_as"] == "LocalSystem" and is_suspicious_path(svc["binary_path"]):
            findings.append({
                "artifact": "Service",
                "name": svc["name"],
                "finding": "Suspicious service binary location",
                "reason": "Service runs as SYSTEM from user-writable directory"
            })
    return findings

if __name__ == "__main__":
    base = "artifacts"

    run_keys = load_json(os.path.join(base, "run_keys.json"))
    tasks = load_json(os.path.join(base, "scheduled_tasks.json"))
    services = load_json(os.path.join(base, "services.json"))

    results = []
    results.extend(analyze_run_keys(run_keys))
    results.extend(analyze_scheduled_tasks(tasks))
    results.extend(analyze_services(services))

    print(json.dumps(results, indent=2))
