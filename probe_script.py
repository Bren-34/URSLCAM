"""
This script runs INSIDE the Daytona sandbox (never on your laptop in normal use).
It opens the target page in a headless browser, READS it, and prints a JSON
summary. It never types into forms and never saves or opens downloaded files:
download attempts are only recorded (file name + URL) and cancelled.

__TARGET_URL__ is replaced with the real URL before the script is sent.
"""
import base64
import json
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

TARGET_URL = __TARGET_URL__

URGENCY = [
    "verify your account", "account suspended", "account has been suspended", "account locked",
    "unusual activity", "suspicious activity", "confirm your identity", "within 24 hours",
    "immediately", "urgent", "final notice", "action required", "your parcel", "delivery failed",
    "update your payment", "payment failed", "you have won", "claim your", "limited time",
    "will be closed", "will be terminated", "re-activate", "reactivate",
]
MONEY = ["bank", "payment", "pay now", "credit card", "debit card", "crypto", "bitcoin", "wallet",
         "refund", "transfer", "paynow", "otp"]
SOCIAL = ["facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com", "youtube.com", "tiktok.com"]


def analyse(html, text, base_url):
    soup = BeautifulSoup(html, "html.parser")
    host = (urlparse(base_url).hostname or "").lower()

    forms = []
    for f in soup.find_all("form"):
        action = (f.get("action") or "").strip()
        full = urljoin(base_url, action) if action else base_url
        forms.append({
            "action": full[:300],
            "method": (f.get("method") or "get").lower(),
            "action_host": (urlparse(full).hostname or "").lower(),
            "scheme": urlparse(full).scheme,
        })

    inputs = []
    for i in soup.find_all(["input", "select", "textarea"]):
        t = (i.get("type") or i.name or "").lower()
        if t in ("submit", "button", "image", "reset", "checkbox", "radio"):
            continue
        label = ""
        if i.get("id"):
            lab = soup.find("label", attrs={"for": i.get("id")})
            if lab:
                label = lab.get_text(" ", strip=True)
        inputs.append({
            "type": t,
            "name": (i.get("name") or "")[:60],
            "id": (i.get("id") or "")[:60],
            "placeholder": (i.get("placeholder") or "")[:60],
            "autocomplete": (i.get("autocomplete") or "")[:40],
            "aria": (i.get("aria-label") or "")[:60],
            "label": label[:60],
        })

    links = []
    for a in soup.find_all("a", href=True):
        href = a.get("href").strip()
        if href.startswith(("javascript:", "#", "mailto:", "tel:")):
            continue
        links.append(urljoin(base_url, href))
    external = [l for l in links if (urlparse(l).hostname or "").lower() not in ("", host)]
    links_l = " ".join(links).lower()
    low = (text or "").lower()

    return {
        "title": soup.title.get_text(strip=True)[:200] if soup.title else "",
        "forms": forms[:20],
        "inputs": inputs[:60],
        "num_password": sum(1 for i in inputs if i["type"] == "password"),
        "num_hidden": sum(1 for i in inputs if i["type"] == "hidden"),
        "num_iframes": len(soup.find_all("iframe")),
        "num_links": len(links),
        "num_external_links": len(external),
        "has_favicon": any("icon" in " ".join(l.get("rel") or []).lower() for l in soup.find_all("link")),
        "has_copyright": ("©" in (text or "")) or ("copyright" in low),
        "has_social": any(s in links_l for s in SOCIAL),
        "urgency_hits": [w for w in URGENCY if w in low],
        "money_hits": [w for w in MONEY if w in low],
        "text_snippet": re.sub(r"\s+", " ", text or "")[:2000],
    }


def main():
    out = {"input_url": TARGET_URL, "ok": False, "error": None, "downloads": [], "navigations": []}
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = browser.new_context(
            accept_downloads=True,
            viewport={"width": 1280, "height": 800},
            user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
        )
        page = ctx.new_page()

        def on_download(d):
            out["downloads"].append({"filename": d.suggested_filename, "url": d.url[:300]})
            try:
                d.cancel()  # never keep or open the file
            except Exception:
                pass

        page.on("download", on_download)
        page.on("dialog", lambda d: d.dismiss())
        page.on("framenavigated", lambda f: out["navigations"].append(f.url[:300]) if f == page.main_frame else None)

        try:
            resp = None
            try:
                resp = page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=20000)
            except Exception as e:
                if "Download is starting" not in str(e):
                    raise
            try:
                page.wait_for_load_state("networkidle", timeout=6000)
            except Exception:
                pass

            chain = []
            r = resp.request if resp else None
            while r is not None:
                chain.append(r.url[:300])
                r = r.redirected_from
            out["redirects"] = list(reversed(chain))
            out["status"] = resp.status if resp else None
            out["final_url"] = page.url

            html = page.content()
            try:
                text = page.inner_text("body", timeout=3000)
            except Exception:
                text = ""
            shot = page.screenshot(type="jpeg", quality=55)
            out["screenshot_b64"] = base64.b64encode(shot).decode()
            out.update(analyse(html, text, page.url))
            out["ok"] = True
        except Exception as e:
            out["error"] = (type(e).__name__ + ": " + str(e))[:300]
        finally:
            browser.close()

    print("__PROBE_RESULT__" + json.dumps(out))


main()
