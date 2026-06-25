# Polluxa - Bulk Email Verification System

Polluxa is a high-performance, asynchronous bulk email verification web application built using **FastAPI** (Python) and a clean, responsive frontend. The system evaluates lists of email addresses provided via text or CSV uploads and determines whether they are authentic or will result in a bounce—all without ever sending an actual email to the recipient.

## 🚀 Live Application URL
* **Frontend Dashboard:** `https://polluxa-verifier.onrender.com` *(Replace with your exact Render Static Site URL)*
* **Backend API Endpoint:** `https://polluxa.onrender.com`

---

## 🛠️ Architecture & Core Requirements

The system processes email validation efficiently through a strict **Three-Tier Verification Pipeline** to minimize network calls and handle bulk workloads asynchronously:

1. **Syntax Validation (Tier 1):** Uses optimized Regular Expressions (Regex) to instantly filter out malformed email strings failing standard IETF compliance formats.
2. **Domain & MX Record Verification (Tier 2):** Queries DNS servers to confirm the domain exists and retrieves active Mail Exchange (MX) records to verify the domain is configured to receive inbound mail.
3. **Deep SMTP Verification / Bounce Prediction (Tier 3):** Establishes an asynchronous connection directly to the target MX server over Port 25. It simulates a handshake via `HELO`, sets a sender via `MAIL FROM`, and tests the recipient with `RCPT TO`. It analyzes status codes (e.g., `250 OK` for valid, `550` for bounce) and promptly terminates the session via `QUIT` before transferring any mail data.

### Performance Design
* **Asynchronous I/O:** Built natively on Python’s `asyncio` and `aiosmtplib` to execute multiple verification workers concurrently, meeting bulk performance constraints (handling 1,000+ emails smoothly).
* **Defensive Timeouts:** Employs a strict connection timeout limit (10s) to gracefully mitigate gray-listing, rate limits, and server-side connection drops.

---

## 📁 Repository Structure

```text
Polluxa/
│
├── index.html          # Frontend UI Dashboard (Render Static Site)
├── main.py             # FastAPI Server & API Endpoints (Render Web Service)
├── Verifier.py         # 3-Tier Asynchronous Verification Logic Engine
├── requirements.txt    # Production Python Dependency Definitions
└── README.md           # Documentation
