filename = "safety_detector.py"
repo = "pdi999inc-lang/vibelenz-mvp"
token = "YOUR_GITHUB_PAT_HERE"
branch = "main"

import requests
import base64
import os
import json

filepath = os.path.join(os.path.expanduser("~"), "Documents", filename)

with open(filepath, "rb") as f:
    content = base64.b64encode(f.read()).decode("utf-8")

url = f"https://api.github.com/repos/{repo}/contents/{filename}"
headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github+json",
}

# Get existing file SHA if present
get_resp = requests.get(url, headers=headers, params={"ref": branch})

sha = None
if get_resp.status_code == 200:
    sha = get_resp.json().get("sha")
elif get_resp.status_code != 404:
    print("GET failed:", get_resp.status_code)
    print(get_resp.text)
    raise SystemExit

payload = {
    "message": "deploy safety_detector.py v2",
    "content": content,
    "branch": branch,
}
if sha:
    payload["sha"] = sha

put_resp = requests.put(url, headers=headers, data=json.dumps(payload))

print("PUT status:", put_resp.status_code)
try:
    data = put_resp.json()
    if "commit" in data:
        print("Commit SHA:", data["commit"]["sha"])
        print("Success")
    else:
        print(data)
except Exception:
    print(put_resp.text)
