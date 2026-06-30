"""
Bulk Email Verification Engine
================================
Implements three-tier verification:
  1. Syntax validation (regex, RFC-ish)
  2. Domain & MX record lookup (DNS)
  3. Deep SMTP verification (HELO/MAIL FROM/RCPT TO) + catch-all detection

Designed to run thousands of emails concurrently using a thread pool
(SMTP/DNS calls are blocking, network-bound -> threads are the right tool,
not asyncio, since smtplib/dnspython are sync libraries).
"""

import re
import csv
import socket
import smtplib
import time
import random
import string
import threading
import uuid
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import Optional, Callable

import dns.resolver
import dns.exception

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

EMAIL_REGEX = re.compile(
    r"^(?!\.)[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+(?<!\.)@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)

DNS_TIMEOUT = 5.0
SMTP_TIMEOUT = 10.0
MAX_WORKERS = 30                 # global thread pool size
PER_DOMAIN_DELAY = 1.2           # seconds between SMTP hits to the same domain (rate limiting)
SENDER_DOMAIN = "verifier.example.com"
SENDER_LOCAL = "checker"

STATUS_VALID = "Valid"
STATUS_BOUNCE = "Bounce"
STATUS_CATCH_ALL = "Catch-All"
STATUS_UNKNOWN = "Unknown/Error"

# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class VerifyResult:
    email: str
    status: str
    reason: str = ""
    mx_host: str = ""


# --------------------------------------------------------------------------
# Per-domain rate limiter (simple token bucket / last-hit timestamp map)
# --------------------------------------------------------------------------

class DomainThrottle:
    def __init__(self, delay: float = PER_DOMAIN_DELAY):
        self.delay = delay
        self._last_hit = defaultdict(float)
        self._lock = threading.Lock()

    def wait(self, domain: str):
        with self._lock:
            now = time.time()
            elapsed = now - self._last_hit[domain]
            wait_for = self.delay - elapsed
            if wait_for > 0:
                # release lock while sleeping would be nicer, but keeping it
                # simple/safe is fine at this scale; sleep is short.
                pass
            self._last_hit[domain] = max(now, self._last_hit[domain] + self.delay)
        if wait_for > 0:
            time.sleep(wait_for)


_throttle = DomainThrottle()
_mx_cache = {}
_mx_cache_lock = threading.Lock()
_catch_all_cache = {}
_catch_all_lock = threading.Lock()


# --------------------------------------------------------------------------
# Tier 1: Syntax
# --------------------------------------------------------------------------

def check_syntax(email: str) -> bool:
    if not email or len(email) > 254 or " " in email:
        return False
    if email.count("@") != 1:
        return False
    local_part = email.split("@", 1)[0]
    if ".." in local_part:
        return False
    return bool(EMAIL_REGEX.match(email))


# --------------------------------------------------------------------------
# Tier 2: Domain & MX
# --------------------------------------------------------------------------

def get_mx_records(domain: str):
    """Return sorted list of MX hostnames (by priority) for a domain, with caching."""
    domain = domain.lower()
    with _mx_cache_lock:
        if domain in _mx_cache:
            return _mx_cache[domain]

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    hosts = []
    try:
        answers = resolver.resolve(domain, "MX")
        hosts = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0],
        )
        hosts = [h for _, h in hosts]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # No MX -> fall back to A record (some domains accept mail directly)
        try:
            resolver.resolve(domain, "A")
            hosts = [domain]
        except Exception:
            hosts = []
    except dns.exception.DNSException:
        hosts = []

    with _mx_cache_lock:
        _mx_cache[domain] = hosts
    return hosts


# --------------------------------------------------------------------------
# Tier 3: SMTP RCPT TO probe
# --------------------------------------------------------------------------

def _random_local_part(n=20):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _smtp_probe(mx_host: str, rcpt_email: str):
    """
    Connects to mx_host, runs HELO/MAIL FROM/RCPT TO, returns the RCPT TO
    (code, message). Always issues QUIT, never sends DATA.
    Raises on connection-level failure.
    """
    server = smtplib.SMTP(timeout=SMTP_TIMEOUT)
    try:
        server.connect(mx_host, 25)
        server.helo(SENDER_DOMAIN)
        server.mail(f"{SENDER_LOCAL}@{SENDER_DOMAIN}")
        code, message = server.rcpt(rcpt_email)
        return code, message.decode(errors="ignore") if isinstance(message, bytes) else str(message)
    finally:
        try:
            server.quit()
        except Exception:
            try:
                server.close()
            except Exception:
                pass


def _is_catch_all(domain: str, mx_host: str) -> Optional[bool]:
    """Probe a random, almost-certainly-nonexistent mailbox on the domain.
    True => server accepts everything (catch-all). False => normal rejection
    behavior. None => couldn't determine (treat as unknown)."""
    with _catch_all_lock:
        if domain in _catch_all_cache:
            return _catch_all_cache[domain]

    fake = f"{_random_local_part()}@{domain}"
    result = None
    try:
        _throttle.wait(domain)
        code, _ = _smtp_probe(mx_host, fake)
        result = (code == 250)
    except Exception:
        result = None

    with _catch_all_lock:
        _catch_all_cache[domain] = result
    return result


def verify_smtp(email: str, mx_hosts: list) -> VerifyResult:
    domain = email.split("@", 1)[1].lower()

    last_error = "No reachable MX host"
    for mx_host in mx_hosts:
        try:
            _throttle.wait(domain)
            code, message = _smtp_probe(mx_host, email)

            if code == 250:
                catch_all = _is_catch_all(domain, mx_host)
                if catch_all is True:
                    return VerifyResult(email, STATUS_CATCH_ALL,
                                         "Server accepts all recipients for this domain",
                                         mx_host)
                return VerifyResult(email, STATUS_VALID,
                                     f"SMTP accepted (250): {message}", mx_host)

            if code in (550, 551, 553, 501, 554):
                return VerifyResult(email, STATUS_BOUNCE,
                                     f"SMTP rejected ({code}): {message}", mx_host)

            if code in (450, 451, 452):
                # greylisting / temporary failure
                return VerifyResult(email, STATUS_UNKNOWN,
                                     f"Greylisted / temporary failure ({code}): {message}", mx_host)

            return VerifyResult(email, STATUS_UNKNOWN,
                                 f"Unexpected SMTP code {code}: {message}", mx_host)

        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError,
                socket.timeout, ConnectionRefusedError, OSError) as e:
            last_error = f"{mx_host}: {e}"
            continue  # try next MX host
        except smtplib.SMTPException as e:
            last_error = f"{mx_host}: {e}"
            continue

    return VerifyResult(email, STATUS_UNKNOWN,
                         f"Could not complete SMTP check ({last_error}). "
                         f"Likely Port 25 is blocked by your network/host.", "")


# --------------------------------------------------------------------------
# Full pipeline for one address
# --------------------------------------------------------------------------

def verify_one(email: str, do_smtp: bool = True) -> VerifyResult:
    email = email.strip()

    if not check_syntax(email):
        return VerifyResult(email, STATUS_BOUNCE, "Invalid syntax")

    domain = email.split("@", 1)[1].lower()
    mx_hosts = get_mx_records(domain)
    if not mx_hosts:
        return VerifyResult(email, STATUS_BOUNCE, "No MX/A records found for domain")

    if not do_smtp:
        return VerifyResult(email, STATUS_VALID, "Syntax+MX OK (SMTP check skipped)", mx_hosts[0])

    return verify_smtp(email, mx_hosts)


# --------------------------------------------------------------------------
# Bulk job runner
# --------------------------------------------------------------------------

class VerificationJob:
    """Tracks progress/results for one bulk verification run."""

    def __init__(self, emails: list, do_smtp: bool = True, max_workers: int = MAX_WORKERS):
        self.id = str(uuid.uuid4())
        self.emails = [e.strip() for e in emails if e.strip()]
        self.total = len(self.emails)
        self.done = 0
        self.results: list[VerifyResult] = []
        self.status_counts = defaultdict(int)
        self.state = "pending"   # pending -> running -> finished
        self.do_smtp = do_smtp
        self.max_workers = max_workers
        self._lock = threading.Lock()
        self.started_at = None
        self.finished_at = None

    def _on_result(self, result: VerifyResult):
        with self._lock:
            self.results.append(result)
            self.status_counts[result.status] += 1
            self.done += 1

    def run(self):
        self.state = "running"
        self.started_at = time.time()
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(verify_one, email, self.do_smtp): email
                for email in self.emails
            }
            for fut in as_completed(futures):
                email = futures[fut]
                try:
                    result = fut.result()
                except Exception as e:
                    result = VerifyResult(email, STATUS_UNKNOWN, f"Internal error: {e}")
                self._on_result(result)
        self.state = "finished"
        self.finished_at = time.time()

    def progress(self):
        with self._lock:
            return {
                "job_id": self.id,
                "state": self.state,
                "total": self.total,
                "done": self.done,
                "percent": round((self.done / self.total) * 100, 1) if self.total else 100,
                "status_counts": dict(self.status_counts),
            }

    def results_csv_rows(self):
        with self._lock:
            ordered = sorted(self.results, key=lambda r: self.emails.index(r.email) if r.email in self.emails else 0)
            return [{"EmailAddress": r.email, "Status": r.status, "Reason": r.reason} for r in ordered]


def parse_uploaded_file(filename: str, content: bytes) -> list:
    text = content.decode("utf-8", errors="ignore")
    emails = []
    if filename.lower().endswith(".csv"):
        reader = csv.reader(text.splitlines())
        for row in reader:
            if not row:
                continue
            candidate = row[0].strip()
            if candidate and "@" in candidate and candidate.lower() not in ("email", "emailaddress", "email_address"):
                emails.append(candidate)
    else:
        for line in text.splitlines():
            line = line.strip()
            if line:
                emails.append(line)
    return emails
