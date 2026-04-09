import json
import requests
import os

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
REPO = os.environ["REPO"]

headers = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

def get_existing_titles():
    url = f"https://api.github.com/repos/{REPO}/issues?state=open&per_page=100"
    res = requests.get(url, headers=headers).json()
    return set(issue["title"] for issue in res)

def create_issue(title):
    url = f"https://api.github.com/repos/{REPO}/issues"
    data = {"title": title}
    requests.post(url, headers=headers, json=data)

with open("trivy-results.json") as f:
    data = json.load(f)

existing_titles = get_existing_titles()

seen_vulns = set()
seen_secrets = set()

for result in data.get("Results", []):

    # -----------------------------
    # VULNERABILITIES
    # -----------------------------
    for vuln in result.get("Vulnerabilities", []):

        if vuln["Severity"] not in ["HIGH", "CRITICAL"]:
            continue

        pkg = vuln.get("PkgName", "unknown")
        vuln_id = vuln.get("VulnerabilityID")
        title_text = vuln.get("Title") or vuln_id

        severity = "Critical" if vuln["Severity"] == "CRITICAL" else "High"

        title = f"[VULN] {pkg}: {title_text}\n{severity}"

        key = (vuln_id, pkg)

        if key in seen_vulns:
            continue
        seen_vulns.add(key)

        if title in existing_titles:
            continue

        print("Creating vulnerability issue:", title)
        create_issue(title)

    # -----------------------------
    # SECRETS
    # -----------------------------
    for secret in result.get("Secrets", []):

        rule_id = secret.get("RuleID")
        title_text = secret.get("Title") or rule_id
        file_path = secret.get("Target")

        title = f"[SECRET] {title_text} ({file_path})"

        key = (rule_id, file_path)

        if key in seen_secrets:
            continue
        seen_secrets.add(key)

        if title in existing_titles:
            continue

        print("Creating secret issue:", title)
        create_issue(title)