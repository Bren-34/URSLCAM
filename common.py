"""Shared helpers: domain parsing, brand list, data-type detection, default red flags."""
import ipaddress
import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Red flags (seeded into Neo4j; used as fallback if Neo4j is unreachable).
# Weights are points added to the risk score when the flag is present.
# Based on page/URL features that separate phishing from legit pages in the
# PhiUSIIL phishing dataset (password fields, external form submits, few links,
# missing copyright/social links, bank/pay keywords, title-domain mismatch...).
# ---------------------------------------------------------------------------
DEFAULT_RED_FLAGS = {
    "known_bad_domain":      ("Domain is on a known phishing list or was flagged by an earlier scan", 40),
    "ip_host":               ("Link uses a raw IP address instead of a domain name", 15),
    "suspicious_tld":        ("Domain uses a TLD that is common in scams (.xyz, .top, .icu ...)", 10),
    "no_https":              ("Page is not served over HTTPS", 10),
    "long_or_deep_url":      ("URL is very long or has many subdomains", 5),
    "redirect_offsite":      ("Link redirected to a different website", 10),
    "password_field":        ("Page asks for a password", 15),
    "sensitive_data":        ("Page asks for card / CVV / OTP / NRIC / bank details", 25),
    "external_form":         ("A form sends your data to a different domain", 25),
    "brand_mismatch":        ("Page claims to be a brand but is not on that brand's domain", 25),
    "urgency_language":      ("Page uses urgent or threatening wording", 10),
    "download_attempt":      ("Page tried to make you download a file", 20),
    "many_hidden_fields":    ("Page has many hidden form fields", 5),
    "few_links":             ("Page has inputs but almost no links (typical of phishing kits)", 5),
    "missing_trust_signals": ("No copyright notice or social media links", 5),
    "linked_to_past_scam":   ("Shares a brand or data destination with a previous high-risk scan", 15),
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "buzz", "click", "link", "live", "shop", "rest", "cyou",
    "sbs", "cfd", "zip", "mov", "tk", "ml", "ga", "cf", "gq", "monster", "quest",
    "support", "help", "online", "site", "vip", "win", "bond",
}

# Brand -> tokens that must appear in the real domain
BRANDS = {
    "DBS": ["dbs"], "POSB": ["posb", "dbs"], "OCBC": ["ocbc"], "UOB": ["uob"],
    "SingPost": ["singpost"], "Singpass": ["singpass", "gov.sg"], "IRAS": ["iras", "gov.sg"],
    "CPF": ["cpf", "gov.sg"], "Shopee": ["shopee"], "Lazada": ["lazada"],
    "Carousell": ["carousell"], "Grab": ["grab"], "PayPal": ["paypal"],
    "Apple": ["apple", "icloud"], "Microsoft": ["microsoft", "live.com", "office", "outlook"],
    "Google": ["google", "gmail"], "Netflix": ["netflix"], "Amazon": ["amazon"],
    "Facebook": ["facebook", "fb.com", "meta"], "Instagram": ["instagram"],
    "WhatsApp": ["whatsapp"], "Telegram": ["telegram", "t.me"], "DHL": ["dhl"],
    "FedEx": ["fedex"], "Standard Chartered": ["sc.com", "standardchartered"],
    "HSBC": ["hsbc"], "Citibank": ["citi"],
}

# Data type -> regex matched against an input's name/id/placeholder/label/type
DATA_TYPES = [
    ("Password",        r"password|passwd|\bpwd\b|pass(word)?code"),
    ("OTP / 2FA code",  r"\botp\b|one.?time|verification.?code|\b2fa\b|\btac\b|sms.?code|auth.?code"),
    ("CVV",             r"\bcvv|\bcvc|\bcsc\b|security.?code"),
    ("Card expiry",     r"expir|\bexp\b|mm.?/?.?yy|cc-exp"),
    ("Card number",     r"card|cc-?num|\bpan\b|credit|debit"),
    ("NRIC / ID",       r"nric|\bfin\b|\bic\b|passport|identity|\bssn\b|national.?id"),
    ("Bank account",    r"account.?(no|num)|\bacct|iban|routing|bank"),
    ("PIN",             r"\bpin\b"),
    ("Email",           r"e-?mail"),
    ("Phone number",    r"phone|mobile|\btel\b|handphone"),
    ("Date of birth",   r"\bdob\b|birth"),
    ("Address",         r"address|postal|\bzip\b|street"),
    ("Username",        r"user|login|userid|\buid\b"),
    ("Full name",       r"full.?name|first.?name|last.?name|surname|^name$|\bname\b"),
]
SENSITIVE_TYPES = {"OTP / 2FA code", "CVV", "Card expiry", "Card number", "NRIC / ID", "Bank account", "PIN"}


def ensure_scheme(url: str) -> str:
    url = url.strip().strip("<>()[]\"'")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    return url


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


SHARED_HOSTS = {"appspot.com", "github.io", "vercel.app", "netlify.app", "web.app", "firebaseapp.com",
                "pages.dev", "workers.dev", "herokuapp.com", "blogspot.com", "wixsite.com", "weebly.com",
                "glitch.me", "000webhostapp.com", "webflow.io", "square.site", "godaddysites.com",
                "onrender.com", "replit.app", "ngrok-free.app", "azurewebsites.net", "cloudfront.net"}


def registered_domain(host: str) -> str:
    """Rough 'example.com' / 'example.com.sg' extraction without extra libraries."""
    host = (host or "").lower().strip(".")
    if not host or is_ip(host):
        return host
    parts = host.split(".")
    if ".".join(parts[-2:]) in SHARED_HOSTS and len(parts) >= 3:
        return ".".join(parts[-3:])          # treat each site on shared hosting separately
    if len(parts) >= 3 and parts[-2] in {"com", "gov", "edu", "org", "net", "co", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def tld_of(host: str) -> str:
    return host.rsplit(".", 1)[-1] if "." in host else ""


def detect_brand(title: str, text: str):
    """Return the brand the page claims to be, if any."""
    title_l, text_l = (title or "").lower(), (text or "").lower()
    for brand in BRANDS:
        pat = r"\b" + re.escape(brand.lower()) + r"\b"
        if re.search(pat, title_l) or len(re.findall(pat, text_l)) >= 2:
            return brand
    return None


def brand_matches_domain(brand: str, host: str) -> bool:
    return any(tok in host for tok in BRANDS.get(brand, []))


def classify_input(inp: dict):
    if inp.get("type") == "hidden":
        return None
    if inp.get("type") == "password":
        return "Password"
    if inp.get("type") == "email":
        return "Email"
    if inp.get("type") == "tel":
        return "Phone number"
    blob = " ".join(str(inp.get(k, "")) for k in ("name", "id", "placeholder", "label", "aria", "autocomplete")).lower()
    for dtype, pat in DATA_TYPES:
        if re.search(pat, blob):
            return dtype
    return None


def data_targets(inputs: list) -> list:
    seen = []
    for inp in inputs or []:
        d = classify_input(inp)
        if d and d not in seen:
            seen.append(d)
    return seen