#!/usr/bin/env python3
"""Qwen Cloud Account Auto-Register + API Key harvester.

Rotates proxy + Gmail dot aliases, calls qwencloud_full.py per account,
and stores results in accounts.json / api_keys.txt.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import logger
from tui import TUI, mask_email, mask_key

SCRIPT = "qwencloud_full.py"
PROXY_FILE = Path("proxy.txt")
USED_PROXY_FILE = Path("used_proxy.txt")
EMAIL_LIST_FILE = Path("email_list.txt")
ACCOUNTS_FILE = Path("accounts.json")
BASE_KEYS_FILE = Path("api_keys.txt")
BASE_OPENAI_URL = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
API_KEYS_FILE = BASE_KEYS_FILE

STUCK_TIMEOUT = 30
MAX_TOTAL = 300


def load_proxies():
    if not PROXY_FILE.exists():
        logger.error(f"{PROXY_FILE} not found")
        sys.exit(1)
    return [p.strip() for p in PROXY_FILE.read_text().splitlines() if p.strip()]


def mark_proxy_used(proxy: str):
    with USED_PROXY_FILE.open("a") as f:
        f.write(proxy + "\n")
    lines = PROXY_FILE.read_text().splitlines()
    lines = [l for l in lines if l.strip() != proxy]
    PROXY_FILE.write_text("\n".join(lines) + ("\n" if lines else ""))


def to_proxy_url(p: str) -> str:
    p = p.strip()
    if "://" in p:
        p = p.split("://", 1)[1]
    if "@" in p:
        return p
    parts = p.split(":")
    if len(parts) == 4:
        h, port, u, pw = parts
        return f"{u}:{pw}@{h}:{port}"
    return p


def probe_proxy(proxy: str, timeout: int = 5) -> str:
    import base64 as _b
    import socket as _s

    try:
        if "@" in proxy:
            auth, server = proxy.rsplit("@", 1)
            user, pw = auth.split(":", 1)
        else:
            server = proxy
            user = pw = ""
        host, port = server.rsplit(":", 1)
        s = _s.create_connection((host, int(port)), timeout=timeout)
        token = _b.b64encode(f"{user}:{pw}".encode()).decode()
        req = f"CONNECT api.ipify.org:443 HTTP/1.1\r\nHost: api.ipify.org\r\nProxy-Authorization: Basic {token}\r\n\r\n"
        s.sendall(req.encode())
        resp = s.recv(64).decode(errors="ignore")
        s.close()
        if "200" in resp:
            return "ok"
        if "407" in resp:
            return "auth-failed"
        return f"unknown: {resp[:40]}"
    except Exception as e:
        return f"unreachable: {str(e)[:50]}"


def load_accounts() -> dict:
    if not ACCOUNTS_FILE.exists():
        return {}
    try:
        return json.loads(ACCOUNTS_FILE.read_text())
    except Exception:
        return {}


def is_account_done(email: str, resume: bool = False) -> bool:
    """True if account should be skipped.
    Auto-resume handles unexpected already-registered (login to harvest key).
    already-registered in accounts.json = already processed, skip.
    """
    db = load_accounts()
    entry = db.get(email)
    if not entry:
        return False  # Unknown → try signup (auto-resume if already-registered)
    status = entry.get("status")
    if status == "success" and entry.get("api_key"):
        return True
    if status in ("locked", "wrong-password", "success-no-key", "already-registered"):
        return True
    return False
    return False


def mark_account(email: str, status: str, **extra):
    db = load_accounts()
    entry = db.get(email) or {}
    entry["email"] = email
    entry["status"] = status
    entry.update(extra)
    entry["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    db[email] = entry
    tmp = ACCOUNTS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(db, indent=2))
    tmp.replace(ACCOUNTS_FILE)


def append_api_key(email: str, api_key: str, base_url_openai: str = ""):
    with API_KEYS_FILE.open("a") as f:
        f.write(f"{email}|{api_key}\n")
    # Store base URLs as the first entry in accounts.json (only once)
    db = load_accounts()
    if "_endpoints" not in db:
        db["_endpoints"] = {
            "openai": base_url_openai or BASE_OPENAI_URL,
            "anthropic": "https://dashscope-intl.aliyuncs.com/apps/anthropic",
        }
        tmp = ACCOUNTS_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(db, indent=2))
        tmp.replace(ACCOUNTS_FILE)


def parse_result(output: str) -> dict:
    for line in output.splitlines():
        if "__RESULT__" in line:
            try:
                return json.loads(line.split("__RESULT__", 1)[1].strip())
            except Exception:
                pass
    return {}


def classify_output(output: str, parsed: dict) -> str:
    status = parsed.get("status", "").lower()
    if status == "success":
        return "success"
    if status == "success-no-key":
        return "success-no-key"
    if status in ("already-registered", "wrong-password", "locked"):
        return status
    if status == "login-ok":
        return "login-ok"
    if status == "access-denied":
        return "access-denied"
    low = output.lower()
    if any(k in low for k in ("rate-limited", "too many requests")):
        return "rate-limited"
    if "access denied" in low or "access+denied" in low:
        return "access-denied"
    proxy_errors = (
        "err_no_supported_proxies",
        "err_proxy_auth_unsupported",
        "err_invalid_auth_credentials",
        "err_tunnel_connection_failed",
        "err_proxy_connection_failed",
        "traffic_exhausted",
        " 407 ",
        "proxy_auth",
    )
    if any(k in low for k in proxy_errors):
        return "proxy-dead"
    return "error"


def mask_email_local(email: str) -> str:
    """Legacy alias for tui.mask_email."""
    return mask_email(email)


def run_one(email: str, proxy: str, idx: int, total: int, headless: bool = False, args_resume: bool = False, worker_id: int = 0, censor: bool = False, verbose: bool = False, tui: TUI = None, self_mode: bool = False, nyx_mode: bool = False) -> str:
    start = time.time()
    display_email = mask_email(email) if censor else email
    if tui:
        tui.update_worker(worker_id, "RUNNING", display_email, "signup...")
    cmd = ["python3", SCRIPT, "--email", email]
    if not self_mode and not nyx_mode:
        proxy_url = to_proxy_url(proxy)
        probe = probe_proxy(proxy_url)
        if probe != "ok":
            logger.warn(f"proxy probe failed: {proxy[:40]}... → {probe}")
            mark_proxy_used(proxy)
            return "proxy-dead"
        cmd.extend(["--proxy", proxy_url])
    elif nyx_mode:
        proxy_url = to_proxy_url(proxy)
        cmd.extend(["--proxy", proxy_url])
    if args_resume:
        cmd.append("--resume")
    if headless:
        cmd.append("--headless")
    env = {**os.environ}
    if not env.get("DISPLAY"):
        env["DISPLAY"] = ":1"

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    out = ""
    last_progress = time.time()
    start = time.time()
    while True:
        line = proc.stdout.readline() if proc.stdout else ""
        if line:
            out += line
            last_progress = time.time()
            # Parse subprocess output to update TUI with current page/status
            if tui:
                line_stripped = line.strip()
                if "landing:" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "landing")
                elif "starting signup" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "signup")
                elif "starting login" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "login")
                elif "Send Code clicked" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "sending OTP")
                elif "verification code found" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "OTP found")
                elif "OTP values" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "typing OTP")
                elif "selecting country" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "selecting country")
                elif "agreement checkbox" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "checkbox")
                elif "dashboard reached" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "dashboard")
                elif "navigating to API keys" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "goto api-keys")
                elif "API key extracted" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "key extracted")
                elif "already-registered" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "already-reg, login")
                elif "SSO redirect" in line_stripped:
                    tui.update_worker(worker_id, "RUNNING", display_email, "SSO redirect")
            if verbose and any(tag in line for tag in ("INFO", "WARN", "ERR", "__RESULT__")):
                print(f"  {logger.dim('│')} {line.rstrip()}", flush=True)
        if proc.poll() is not None:
            try:
                rest = proc.stdout.read() if proc.stdout else ""
                if rest:
                    out += rest
            except Exception:
                pass
            break
        if time.time() - last_progress > STUCK_TIMEOUT:
            if self_mode or nyx_mode:
                logger.warn(f"no progress for {STUCK_TIMEOUT}s, killing process")
            else:
                logger.warn(f"no progress for {STUCK_TIMEOUT}s, killing + rotating proxy")
                mark_proxy_used(proxy)
            proc.kill()
            return "stuck"
        if time.time() - start > MAX_TOTAL:
            logger.warn(f"total {MAX_TOTAL}s timeout, killing process")
            proc.kill()
            return "timeout"
        time.sleep(0.5)

    parsed = parse_result(out)
    status = parsed.get("status", "")

    if status != "success" and verbose:
        tail = out[-1200:]
        if tail.strip():
            print(f"  {logger.dim('└─ last output:')}", file=sys.stderr, flush=True)
            for ln in tail.splitlines()[-8:]:
                print(f"    {logger.dim(ln[:160])}", file=sys.stderr, flush=True)

    elapsed = time.time() - start
    if status == "success":
        api_key = parsed.get("api_key", "")
        base_url_openai = parsed.get("base_url_openai", "")
        country = parsed.get("country", "")
        mark_account(email, "success", api_key=api_key, base_url_openai=base_url_openai, country=country)
        append_api_key(email, api_key, base_url_openai)
        if tui:
            tui.update_worker(worker_id, "SUCCESS", display_email, mask_key(api_key), elapsed)
        return "success"

    if status == "success-no-key":
        mark_account(email, "success-no-key")
        if tui:
            tui.update_worker(worker_id, "BURNT", display_email, "no key", elapsed)
        return "success-no-key"

    if status == "login-ok":
        api_key = parsed.get("api_key", "")
        if api_key:
            base_url_openai = parsed.get("base_url_openai", BASE_OPENAI_URL)
            mark_account(email, "success", api_key=api_key, base_url_openai=base_url_openai)
            append_api_key(email, api_key, base_url_openai)
            if tui:
                tui.update_worker(worker_id, "SUCCESS", display_email, mask_key(api_key), elapsed)
            return "success"
        mark_account(email, "success-no-key")
        if tui:
            tui.update_worker(worker_id, "BURNT", display_email, "login no key", elapsed)
        return "success-no-key"

    if status in ("already-registered", "wrong-password", "locked"):
        mark_account(email, status)
        if tui:
            tui.update_worker(worker_id, "INFO", display_email, status, elapsed)
        return status

    result = classify_output(out, parsed)
    if tui:
        tui.update_worker(worker_id, "FAILED", display_email, result, elapsed)
    return result


def main():
    logger.banner()
    ap = argparse.ArgumentParser(description="Qwen Cloud Account Auto-Register + API Key harvester")
    ap.add_argument("target", nargs="?", type=int, default=5, help="Number of successful API keys to harvest (default: 5)")
    ap.add_argument("--headless", action="store_true", help="Run via Xvfb wrapper (browser stays headed)")
    ap.add_argument("--resume", action="store_true", help="Retry already-registered accounts via login to harvest API key")
    ap.add_argument("-t", "--threads", type=int, default=1, help="Number of concurrent threads (default: 1)")
    ap.add_argument("-c", "--censor", action="store_true", help="Censor email (show only @gmail.com) and mask API key")
    ap.add_argument("--log", action="store_true", help="Show full subprocess logs (default: dashboard only)")
    ap.add_argument("--self", action="store_true", help="Run without proxy (use own IP)")
    ap.add_argument("--nyx", metavar="PROXY", default="", help="Use NyxProxy rotating proxy (format: user:pass@host:port or host:port:user:pass). IP rotates automatically per request.")
    args = ap.parse_args()
    target = args.target
    self_mode = args.self
    nyx_proxy = args.nyx
    nyx_mode = bool(nyx_proxy)

    if args.headless and not os.environ.get("QWENCLOUD_HIDDEN"):
        if sys.platform == "win32":
            logger.warn("--headless (Xvfb wrapper) is only supported on Linux; ignoring")
        else:
            logger.info("headless requested → spawning Xvfb wrapper (run_hidden.sh)")
            cmd = ["./run_hidden.sh", str(target)]
            if args.resume:
                cmd.append("--resume")
            if args.threads > 1:
                cmd.extend(["-t", str(args.threads)])
            if args.censor:
                cmd.append("-c")
            if args.log:
                cmd.append("--log")
            if self_mode:
                cmd.append("--self")
            if nyx_mode:
                cmd.extend(["--nyx", nyx_proxy])
            os.execvp(cmd[0], cmd)

    headless = args.headless if not os.environ.get("QWENCLOUD_HIDDEN") else False

    if not EMAIL_LIST_FILE.exists():
        logger.error(f"{EMAIL_LIST_FILE} not found. Generate it first: python3 generate_email_list.py")
        sys.exit(1)
    emails = [e.strip() for e in EMAIL_LIST_FILE.read_text().splitlines() if e.strip()]
    proxies = load_proxies() if not self_mode and not nyx_mode else []
    n_threads = args.threads
    censor = args.censor
    verbose = args.log

    # Create TUI (skip if --log mode for raw output)
    tui = None
    if not verbose:
        tui = TUI(target=target, total_emails=len(emails), total_proxies=len(proxies),
                  n_threads=n_threads, headless=headless, censor=censor, verbose=verbose)
        tui.start()
    else:
        logger.info(f"target: {logger.bold(str(target))} | emails: {logger.bold(str(len(emails)))} | proxies: {logger.bold(str(len(proxies)))} | threads: {logger.bold(str(n_threads))} | censor: {'ON' if censor else 'OFF'} | log: {'ON' if verbose else 'OFF'}")

    # Thread-safe state
    email_lock = threading.Lock()
    proxy_lock = threading.Lock()
    count_lock = threading.Lock()
    email_idx = [0]
    success = [0]
    skipped = [0]
    attempted = [0]

    def claim_email():
        with email_lock:
            while email_idx[0] < len(emails):
                email = emails[email_idx[0]]
                email_idx[0] += 1
                if not is_account_done(email):
                    return email
                skipped[0] += 1
            return None

    def claim_proxy():
        with proxy_lock:
            if not proxies:
                return None
            proxy = proxies[0]
            proxies.pop(0)
            mark_proxy_used(proxy)
            return proxy

    def worker(wid=0):
        while True:
            with count_lock:
                if success[0] >= target:
                    return
            email = claim_email()
            if not email:
                return
            if self_mode:
                proxy = ""
            elif nyx_mode:
                proxy = nyx_proxy
            else:
                proxy = claim_proxy()
                if not proxy:
                    logger.error("no proxies left")
                    return
            with count_lock:
                attempted[0] += 1
                idx = attempted[0]
            result = run_one(email, proxy, idx, target, headless=headless, args_resume=True, worker_id=wid, censor=censor, verbose=verbose, tui=tui, self_mode=self_mode, nyx_mode=nyx_mode)
            if tui:
                tui.update_stats(success=success[0], failed=sum(1 for _ in []), attempted=attempted[0], remaining_proxies=len(proxies))
            else:
                print(logger.result(result, email), flush=True)
            if result == "success":
                with count_lock:
                    success[0] += 1
                if tui:
                    tui.update_stats(success=success[0])

    # Signal handler for Ctrl+C — clean shutdown
    shutting_down = [False]
    def signal_handler(sig, frame):
        if shutting_down[0]:
            return
        shutting_down[0] = True
        if tui:
            tui.update_worker(0, "INFO", "", "Ctrl+C received, shutting down...")
        sys.stderr.write("\n\nShutting down...\n")
        # ThreadPoolExecutor will be cancelled by context manager exit
        os._exit(0)

    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if n_threads <= 1:
            worker(1)
        else:
            with ThreadPoolExecutor(max_workers=n_threads) as pool:
                futures = [pool.submit(worker, i + 1) for i in range(n_threads)]
                for f in as_completed(futures):
                    f.result()
    except KeyboardInterrupt:
        pass
    finally:
        if tui:
            tui.stop()
            tui.print_summary()
        else:
            logger.summary(success[0], target, skipped[0], attempted[0])


if __name__ == "__main__":
    main()
