# Phish Checker 🎣🚨

Telegram bot: send a suspicious link → get a scam-risk score, what data it's after, and why.

## How it works
1. **Check 1 – known malicious?** VirusTotal + Google Safe Browsing look up the link (and any file the page tries to download).
2. **Check 2 – page analysis.** The page is opened in an isolated **Daytona sandbox** with a headless browser. It reads the forms, input fields (password, OTP, card, NRIC…), redirects, brand vs domain, and urgent wording, and records download attempts without opening them. It takes a screenshot.
3. The page facts are compared with the **red flags stored in Neo4j**, plus known phishing domains (OpenPhish) and earlier scans (shared brand or data destination = same campaign).
4. **Llama 3.1** (Groq or Nosana) explains it. Final score = 60% rules + 40% AI. A hit from a reputation service forces 85+.

## Setup (in order)
```bash
pip install -r requirements.txt
cp .env.example .env        # fill in the keys
python seed_neo4j.py        # once: loads red flags + known-bad domains
python warmup_sandbox.py    # once: prepares the sandbox, prints DAYTONA_SANDBOX_ID for .env
python bot.py               # run the bot
```
Terminal fallback: `python cli.py https://some-link`

Testing without Daytona: set `PROBE_MODE=local` (runs the page on your laptop; use test pages only).

## Demo: safe test URLs
- `https://testsafebrowsing.appspot.com/s/phishing.html` (Google's official phishing test page)
- `https://example.com` (should come out safe)
- Your own fake page (see `demo_page.html`) hosted anywhere, e.g. GitHub Pages
