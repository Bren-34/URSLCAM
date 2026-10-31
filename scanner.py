"""Runs both checks, compares page facts to the red flags in Neo4j, asks the LLM, returns a score."""
import json
import os

from dotenv import load_dotenv

load_dotenv()

from common import (SENSITIVE_TYPES, SUSPICIOUS_TLDS, brand_matches_domain, data_targets, detect_brand,
                    ensure_scheme, host_of, is_ip, registered_domain, tld_of)
from graph import Graph
from reputation import check_virustotal, reputation_check, reputation_points
from sandbox_probe import probe

_graph = None


def graph():
    global _graph
    if _graph is None:
        _graph = Graph()
    return _graph


# ---------------------------------------------------------------- red flags
def evaluate_flags(url, probe_res, flags_db, known_bad, related):
    host = host_of(probe_res.get("final_url") or url)
    page_dom = registered_domain(host)
    in_dom = registered_domain(host_of(url))
    hits = []

    def hit(key, detail=""):
        if key in flags_db:
            hits.append({"key": key, "description": flags_db[key]["description"],
                         "weight": flags_db[key]["weight"], "detail": detail})

    if known_bad:
        hit("known_bad_domain", page_dom)
    if is_ip(host):
        hit("ip_host", host)
    if tld_of(host) in SUSPICIOUS_TLDS:
        hit("suspicious_tld", "." + tld_of(host))
    if (probe_res.get("final_url") or url).startswith("http://"):
        hit("no_https")
    if len(url) > 100 or host.count(".") >= 4:
        hit("long_or_deep_url")
    if in_dom and page_dom and in_dom != page_dom:
        hit("redirect_offsite", f"{in_dom} -> {page_dom}")

    if probe_res.get("ok"):
        targets = data_targets(probe_res.get("inputs"))
        if probe_res.get("num_password", 0) > 0:
            hit("password_field")
        sens = [t for t in targets if t in SENSITIVE_TYPES]
        if sens:
            hit("sensitive_data", ", ".join(sens))
        ext = sorted({registered_domain(f["action_host"]) for f in probe_res.get("forms", [])
                      if f.get("action_host") and registered_domain(f["action_host"]) != page_dom})
        if ext:
            hit("external_form", ", ".join(ext))
        brand = detect_brand(probe_res.get("title"), probe_res.get("text_snippet"))
        if brand and not brand_matches_domain(brand, host):
            hit("brand_mismatch", f"looks like {brand}, but domain is {page_dom}")
        if probe_res.get("urgency_hits"):
            hit("urgency_language", ", ".join(probe_res["urgency_hits"][:4]))
        if probe_res.get("num_hidden", 0) >= 4:
            hit("many_hidden_fields", str(probe_res["num_hidden"]))
        if targets and probe_res.get("num_links", 0) < 5:
            hit("few_links", f"{probe_res.get('num_links', 0)} links")
        if not probe_res.get("has_copyright") and not probe_res.get("has_social"):
            hit("missing_trust_signals")
    if probe_res.get("downloads"):
        hit("download_attempt", ", ".join(d["filename"] for d in probe_res["downloads"][:3]))
    if related:
        hit("linked_to_past_scam", f"{len(related)} earlier scan(s)")
    return hits


# ---------------------------------------------------------------- LLM
def llm_assess(url, probe_res, flags, rep_reasons, targets, brand):
    key = os.getenv("LLM_API_KEY", "").strip()
    if not key:
        return None
    from openai import OpenAI

    client = OpenAI(api_key=key, base_url=os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1"))
    facts = {
        "submitted_url": url,
        "final_url": probe_res.get("final_url"),
        "page_loaded": probe_res.get("ok"),
        "load_error": probe_res.get("error"),
        "title": probe_res.get("title"),
        "claimed_brand": brand,
        "data_the_page_asks_for": targets,
        "forms": probe_res.get("forms", [])[:5],
        "downloads_attempted": probe_res.get("downloads", []),
        "reputation_findings": rep_reasons,
        "red_flags_matched": [f"{f['description']} ({f['detail']})" if f["detail"] else f["description"] for f in flags],
        "visible_text_start": (probe_res.get("text_snippet") or "")[:1200],
    }
    prompt = (
        "You are a phishing analyst helping an ordinary user in Singapore. Using ONLY the facts below, "
        "judge how likely this page is a scam/phishing page. Respond with JSON only:\n"
        '{"score": <0-100 likelihood of scam>, "impersonates": <brand or null>, '
        '"after": <short phrase: what the scammer is after, e.g. "bank login + OTP">, '
        '"reasons": [<2-4 short plain-English reasons>], "advice": <one short sentence for the user>}\n\n'
        "FACTS:\n" + json.dumps(facts, ensure_ascii=False)
    )
    try:
        r = client.chat.completions.create(
            model=os.getenv("LLM_MODEL", "llama-3.1-8b-instant"),
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        txt = r.choices[0].message.content
        data = json.loads(txt[txt.find("{"): txt.rfind("}") + 1])
        data["score"] = max(0, min(100, int(data.get("score", 0))))
        return data
    except Exception as e:
        print(f"[llm] failed: {e}")
        return None


def verdict_for(score):
    if score >= 60:
        return "LIKELY SCAM"
    if score >= 30:
        return "SUSPICIOUS"
    return "LIKELY SAFE"


# ---------------------------------------------------------------- main entry
def scan(raw_url: str, progress=lambda msg: None) -> dict:
    url = ensure_scheme(raw_url)
    g = graph()

    progress("🔍 Check 1/2: looking up the link on VirusTotal + Google Safe Browsing...")
    rep = reputation_check(url)

    progress("🧪 Check 2/2: opening the page in an isolated Daytona sandbox...")
    try:
        probe_res = probe(url, log=print)
    except Exception as e:
        probe_res = {"ok": False, "error": f"sandbox error: {e}"[:300]}

    # Any download the page attempted -> check that file's URL too (never opened)
    rep["downloads"] = []
    for d in (probe_res.get("downloads") or [])[:2]:
        rep["downloads"].append({**d, "virustotal": check_virustotal(d["url"], wait_for_new=False)})
    rep_pts, rep_reasons = reputation_points(rep)

    progress("🧠 Comparing the page to known red flags and asking the AI...")
    final_host = host_of(probe_res.get("final_url") or url)
    page_dom = registered_domain(final_host)
    targets = data_targets(probe_res.get("inputs"))
    brand = detect_brand(probe_res.get("title"), probe_res.get("text_snippet")) if probe_res.get("ok") else None
    send_to = sorted({registered_domain(f["action_host"]) for f in probe_res.get("forms", []) if f.get("action_host")})

    flags_db = g.red_flags()
    known_bad = g.is_known_bad(page_dom, registered_domain(host_of(url)), final_host)
    related = g.related_scans(url, brand, send_to)
    flags = evaluate_flags(url, probe_res, flags_db, known_bad, related)

    rule_score = min(100, rep_pts + sum(f["weight"] for f in flags))
    llm = llm_assess(url, probe_res, flags, rep_reasons, targets, brand)
    score = round(0.6 * rule_score + 0.4 * llm["score"]) if llm else rule_score
    if rep_pts >= 50:          # confirmed by a reputation service -> never call it safe
        score = max(score, 85)

    report = {
        "url": url,
        "final_url": probe_res.get("final_url"),
        "domain": page_dom,
        "score": score,
        "verdict": verdict_for(score),
        "rule_score": rule_score,
        "llm": llm,
        "reputation": rep,
        "reputation_reasons": rep_reasons,
        "flags": flags,
        "data_targets": targets,
        "brand": brand if brand and not brand_matches_domain(brand, final_host) else None,
        "send_to_domains": send_to,
        "related": related,
        "page_loaded": probe_res.get("ok", False),
        "page_error": probe_res.get("error"),
        "title": probe_res.get("title"),
        "screenshot_b64": probe_res.get("screenshot_b64"),
        "neo4j_online": g.online,
    }
    g.save_scan(report)
    return report


# ---------------------------------------------------------------- formatting
def format_report(r: dict) -> str:
    icon = {"LIKELY SCAM": "🚨", "SUSPICIOUS": "⚠️", "LIKELY SAFE": "✅"}[r["verdict"]]
    lines = [f"{icon} {r['verdict']} — risk score {r['score']}/100", "", f"🔗 {r['url']}"]
    if r.get("final_url") and r["final_url"].rstrip("/") != r["url"].rstrip("/"):
        lines.append(f"↪️ ended up at: {r['final_url']}")

    llm = r.get("llm") or {}
    if llm.get("impersonates") or r.get("brand"):
        lines.append(f"🎭 Pretends to be: {llm.get('impersonates') or r.get('brand')}")
    if r.get("data_targets"):
        lines.append(f"🎯 Asks for: {', '.join(r['data_targets'])}")
    if llm.get("after"):
        lines.append(f"💰 Likely after: {llm['after']}")

    lines += ["", "Check 1 — known malicious?"]
    vt, sb = r["reputation"]["virustotal"], r["reputation"]["safe_browsing"]
    lines.append(f"• VirusTotal: {vt.get('malicious', 0)} malicious / {vt.get('suspicious', 0)} suspicious"
                 if vt.get("available") else f"• VirusTotal: skipped ({vt.get('note')})")
    if vt.get("note") and vt.get("available"):
        lines[-1] += f" ({vt['note']})"
    lines.append(("• Safe Browsing: FLAGGED " + ", ".join(sb.get("threats", []))) if sb.get("flagged")
                 else ("• Safe Browsing: not listed" if sb.get("available") else f"• Safe Browsing: skipped ({sb.get('note')})"))
    for d in r["reputation"].get("downloads", []):
        lines.append(f"• Download attempted: {d['filename']} (VirusTotal malicious: {d['virustotal'].get('malicious', '?')})")

    lines += ["", "Check 2 — page analysis (Daytona sandbox):"]
    if not r["page_loaded"]:
        lines.append(f"• Page could not be loaded: {r.get('page_error')}")
    if r["flags"]:
        for f in sorted(r["flags"], key=lambda x: -x["weight"]):
            lines.append(f"• +{f['weight']} {f['description']}" + (f" ({f['detail']})" if f["detail"] else ""))
    else:
        lines.append("• No red flags matched")
    if r.get("related"):
        lines.append(f"• 🕸️ Linked to {len(r['related'])} earlier high-risk scan(s) in our graph")

    if llm.get("reasons"):
        lines += ["", "🧠 Why (AI analysis):"] + [f"• {x}" for x in llm["reasons"][:4]]
    if llm.get("advice"):
        lines += ["", f"👉 {llm['advice']}"]
    lines += ["", f"(rules {r['rule_score']}" + (f" · AI {llm['score']}" if llm else "") + ")"]
    return "\n".join(lines)[:4000]
