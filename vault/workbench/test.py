import requests
import os
from dotenv import load_dotenv

load_dotenv()

def get_vt_report(sha256):
    vt_key = os.getenv('VT_KEY')
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"

    headers = {
        "accept": "application/json",
        "x-apikey": vt_key
    }

    response = requests.get(url, headers=headers)
    with open("response.json", "w") as f:
        f.write(response.text)
    return "Completed"

sha256 = "4add51cd45b7fd60dbbd612c464438ae9a0a80e0f7f40b5b6cc4a00a10b916ea"

print(get_vt_report(sha256))
