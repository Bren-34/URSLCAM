"""
Run once before the demo:  python warmup_sandbox.py
Creates a Daytona sandbox, installs Playwright + Chromium inside it, and runs a test page.
Copy the printed DAYTONA_SANDBOX_ID into .env so the bot reuses it (much faster scans).
"""
from dotenv import load_dotenv

load_dotenv()

from sandbox_probe import get_sandbox, probe_in_daytona

sb = get_sandbox()
print("Testing the sandbox on https://example.com ...")
r = probe_in_daytona("https://example.com")
print("Page loaded:", r.get("ok"), "| title:", r.get("title"), "| error:", r.get("error"))
print(f"\n✅ Add this line to your .env:\nDAYTONA_SANDBOX_ID={sb.id}")
