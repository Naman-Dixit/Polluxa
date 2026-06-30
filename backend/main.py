"""
FastAPI backend for the Bulk Email Verification System.

Endpoints
---------
POST /api/upload         -> upload a .csv/.txt file, starts a background job, returns job_id
GET  /api/status/{job_id}-> polling endpoint for progress + live status counts
GET  /api/results/{job_id}-> JSON results (paginated-free, fine for a few thousand rows)
GET  /api/download/{job_id}-> downloadable CSV of results
POST /api/verify-single  -> quick single-email check (used by the UI's "Quick Check" box)
"""

import csv
import io
import threading
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from verifier import VerificationJob, parse_uploaded_file, verify_one

app = FastAPI(title="Bulk Email Verifier API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

JOBS: dict[str, VerificationJob] = {}
JOBS_LOCK = threading.Lock()

MAX_EMAILS_PER_JOB = 10000


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), smtp_check: bool = Form(True)):
    content = await file.read()
    emails = parse_uploaded_file(file.filename, content)

    if not emails:
        raise HTTPException(400, "No valid-looking email addresses found in the file.")
    if len(emails) > MAX_EMAILS_PER_JOB:
        raise HTTPException(400, f"Too many emails ({len(emails)}). Limit is {MAX_EMAILS_PER_JOB} per job.")

    job = VerificationJob(emails, do_smtp=smtp_check)
    with JOBS_LOCK:
        JOBS[job.id] = job

    thread = threading.Thread(target=job.run, daemon=True)
    thread.start()

    return {"job_id": job.id, "total": job.total}


def _get_job(job_id: str) -> VerificationJob:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@app.get("/api/status/{job_id}")
def status(job_id: str):
    return _get_job(job_id).progress()


@app.get("/api/results/{job_id}")
def results(job_id: str):
    job = _get_job(job_id)
    rows = job.results_csv_rows()
    return {"job_id": job_id, "state": job.state, "count": len(rows), "rows": rows}


@app.get("/api/download/{job_id}")
def download(job_id: str):
    job = _get_job(job_id)
    rows = job.results_csv_rows()

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["EmailAddress", "Status", "Reason"])
    writer.writeheader()
    writer.writerows(rows)
    buf.seek(0)

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=verification_results_{job_id[:8]}.csv"},
    )


@app.post("/api/verify-single")
def verify_single(email: str = Form(...), smtp_check: bool = Form(True)):
    result = verify_one(email, do_smtp=smtp_check)
    return {"email": result.email, "status": result.status, "reason": result.reason}


# Serve the frontend
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
