import io
import csv
import asyncio
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from verifier import process_single_email

app = FastAPI(title="Bulk Email Verification System API")

# Enable Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For local production/testing environments
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def run_concurrent_tasks(emails: list) -> list:
    """
    Pack calculations into parallel execution contexts using asyncio.gather
    """
    tasks = [process_single_email(email) for email in emails]
    return await asyncio.gather(*tasks)

@app.post("/verify-csv/")
async def verify_csv(file: UploadFile = File(...)):
    # Validate input type extensions
    if not file.filename.endswith(('.csv', '.txt')):
        raise HTTPException(status_code=400, detail="Invalid extension. Upload .csv or .txt records.")

    try:
        contents = await file.read()
        lines = contents.decode("utf-8").splitlines()
        
        # Parse inputs while discarding blank space rows
        emails = []
        for line in lines:
            cleaned = line.strip()
            if cleaned:
                # Handle standard comma-separated lines if processing CSV sheets
                email_candidate = cleaned.split(',')[0].strip()
                # Clean enclosing quotes if present in raw text/CSV rows
                email_candidate = email_candidate.replace('"', '').replace("'", "")
                if email_candidate and "@" in email_candidate:
                    emails.append(email_candidate)
                    
        if not emails:
            raise HTTPException(status_code=400, detail="The uploaded file contains no recognizable data rows.")
            
        # Constrain payload boundary limits to maintain stable execution states
        if len(emails) > 5000:
            raise HTTPException(status_code=400, detail="Max concurrent batches limited to 5,000 files per run.")

        # Dispatch async queues concurrently
        results = await run_concurrent_tasks(emails)
        
        # Build out memory buffered dynamic output stream 
        output_buffer = io.StringIO()
        writer = csv.writer(output_buffer)
        writer.writerow(["EmailAddress", "Status"])  # Write CSV Headers
        
        for email, status in zip(emails, results):
            writer.writerow([email, status])
            
        output_buffer.seek(0)
        
        # Stream computed records straight back into client application interface
        return StreamingResponse(
            io.BytesIO(output_buffer.getvalue().encode('utf-8')),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=verified_list.csv"}
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Processing Failure: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)