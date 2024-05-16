import vt
import os
from dotenv import load_dotenv

load_dotenv()

def get_vt_report(sha256):
    # Get the VirusTotal API key from the environment
    vt_key = os.getenv('VT_KEY')
    # Initialize the VirusTotal API client
    vt_client = vt.Client(vt_key)
    try:
        # Retrieve the VirusTotal report for the given SHA256 hash
        file = vt_client.get_object(f"/files/{sha256}")
        vt_client.close()
        return file.last_analysis_stats
    except Exception as e:
        vt_client.close()
        return f"{str(e)}"
    
sha256 = "4add51cd45b7fd60dbbd612c464438ae9a0a80e0f7f40b5b6cc4a00a10b916ea"

# Call the function to get the VirusTotal report
report = get_vt_report(sha256)
print(report)
