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
seen = set()

for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):

        if vuln["Severity"] not in ["HIGH", "CRITICAL"]:
            continue

        pkg = vuln["PkgName"]
        title_text = vuln.get("Title") or vuln["VulnerabilityID"]

        severity = "Critical" if vuln["Severity"] == "CRITICAL" else "High"

        title = f"{pkg}: {title_text}\n{severity}"

        key = (vuln["VulnerabilityID"], pkg)

        if key in seen:
            continue
        seen.add(key)

        if title in existing_titles:
            continue

        print("Creating issue:", title)
        create_issue(title)