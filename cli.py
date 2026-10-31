"""Terminal fallback: python cli.py <url>   (saves the screenshot as last_screenshot.jpg)"""
import base64
import sys

from scanner import format_report, scan

if len(sys.argv) < 2:
    sys.exit("usage: python cli.py <url>")
report = scan(sys.argv[1], progress=print)
print("\n" + format_report(report))
if report.get("screenshot_b64"):
    with open("last_screenshot.jpg", "wb") as f:
        f.write(base64.b64decode(report["screenshot_b64"]))
    print("\nScreenshot saved to last_screenshot.jpg")
