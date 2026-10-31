"""Check 2a: open the page inside a Daytona sandbox and collect facts about it."""
import json
import os
import subprocess
import sys
from pathlib import Path

PROBE_SRC = (Path(__file__).parent / "probe_script.py").read_text()
MARKER = "__PROBE_RESULT__"
READY_FLAG = "/tmp/.probe_ready"

_daytona = None
_sandbox = None


def _build_script(url: str) -> str:
    return PROBE_SRC.replace("TARGET_URL = __TARGET_URL__", "TARGET_URL = " + json.dumps(url), 1)


def _parse(output: str) -> dict:
    for line in reversed((output or "").splitlines()):
        if line.startswith(MARKER):
            return json.loads(line[len(MARKER):])
    return {"ok": False, "error": "Probe returned no result. Output tail: " + (output or "")[-400:]}


def _exec(sb, cmd, timeout=600):
    r = sb.process.exec(cmd, timeout=timeout)
    return getattr(r, "exit_code", 0), getattr(r, "result", "") or ""


def _setup(sb, log=print):
    code, _ = _exec(sb, f"test -f {READY_FLAG}", timeout=30)
    if code == 0:
        return
    log("Installing Playwright + Chromium in the sandbox (one-time, ~1-3 min)...")
    code, out = _exec(sb, "python3 -m pip install -q playwright beautifulsoup4")
    if code != 0:
        raise RuntimeError("pip install failed in sandbox: " + out[-500:])
    # System libraries for Chromium (needs sudo; ignore if not available)
    _exec(sb, "sudo -n python3 -m playwright install-deps chromium || true", timeout=900)
    code, out = _exec(sb, "python3 -m playwright install chromium", timeout=900)
    if code != 0:
        raise RuntimeError("playwright install failed in sandbox: " + out[-500:])
    _exec(sb, f"touch {READY_FLAG}", timeout=30)


def get_sandbox(log=print):
    """Create (or reuse) one sandbox for the whole bot session."""
    global _daytona, _sandbox
    if _sandbox is not None:
        return _sandbox
    from daytona import Daytona, DaytonaConfig

    _daytona = Daytona(DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"]))
    sid = os.getenv("DAYTONA_SANDBOX_ID", "").strip()
    sb = None
    if sid:
        try:
            sb = _daytona.get(sid)
            try:
                sb.start()  # no-op / error if already running
            except Exception:
                pass
            log(f"Reusing sandbox {sid}")
        except Exception as e:
            log(f"Could not reuse sandbox {sid} ({e}); creating a new one")
            sb = None
    if sb is None:
        sb = _daytona.create()
        log(f"Created sandbox {sb.id}  (put DAYTONA_SANDBOX_ID={sb.id} in .env to reuse it)")
    _setup(sb, log)
    _sandbox = sb
    return sb


def probe_in_daytona(url: str, log=print) -> dict:
    sb = get_sandbox(log)
    resp = sb.process.code_run(_build_script(url), timeout=90)
    return _parse(getattr(resp, "result", "") or "")


def probe_locally(url: str) -> dict:
    """TESTING ONLY: runs the same probe on this machine (no isolation)."""
    r = subprocess.run([sys.executable, "-c", _build_script(url)], capture_output=True, text=True, timeout=120)
    return _parse(r.stdout + "\n" + r.stderr)


def probe(url: str, log=print) -> dict:
    if os.getenv("PROBE_MODE", "daytona").lower() == "local":
        log("PROBE_MODE=local -> running probe on this machine (testing only, not isolated)")
        return probe_locally(url)
    return probe_in_daytona(url, log)
