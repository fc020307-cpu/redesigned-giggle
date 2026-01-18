from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import re
import dns.resolver
import smtplib
import socket
import csv
import io
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone
from enum import Enum

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Disposable email domains list
DISPOSABLE_DOMAINS = {
    "tempmail.com", "throwaway.email", "guerrillamail.com", "mailinator.com",
    "10minutemail.com", "temp-mail.org", "fakeinbox.com", "trashmail.com",
    "getnada.com", "mohmal.com", "maildrop.cc", "yopmail.com", "dispostable.com",
    "sharklasers.com", "spam4.me", "grr.la", "guerrillamailblock.com",
    "tempail.com", "tmpmail.org", "tmpeml.com", "emailondeck.com"
}

# Enums
class EmailStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    RISKY = "risky"
    UNKNOWN = "unknown"

class JobStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

# Models
class EmailResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    email: str
    status: EmailStatus
    format_valid: bool
    domain_valid: bool
    mx_valid: bool
    is_disposable: bool
    smtp_valid: Optional[bool] = None
    reason: str

class ValidationJob(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: JobStatus = JobStatus.PENDING
    total_emails: int = 0
    processed_emails: int = 0
    valid_count: int = 0
    invalid_count: int = 0
    risky_count: int = 0
    unknown_count: int = 0
    results: List[EmailResult] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None

class BulkValidateRequest(BaseModel):
    emails: List[str]

# Email validation functions
def validate_email_format(email: str) -> bool:
    """Validate email format using regex"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email.strip().lower()))

def extract_domain(email: str) -> Optional[str]:
    """Extract domain from email"""
    try:
        return email.strip().lower().split('@')[1]
    except IndexError:
        return None

def validate_domain(domain: str) -> bool:
    """Check if domain exists"""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def get_mx_records(domain: str) -> List[str]:
    """Get MX records for domain"""
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return [str(record.exchange).rstrip('.') for record in records]
    except Exception:
        return []

def is_disposable_email(domain: str) -> bool:
    """Check if email domain is disposable"""
    return domain.lower() in DISPOSABLE_DOMAINS

def verify_smtp(email: str, mx_host: str, timeout: int = 10) -> tuple[Optional[bool], str]:
    """
    Verify email via SMTP - returns (status, detail)
    - (True, reason) if valid
    - (False, reason) if definitely invalid
    - (None, reason) if uncertain
    """
    try:
        smtp = smtplib.SMTP(timeout=timeout)
        smtp.connect(mx_host)
        smtp.helo('verify.local')
        smtp.mail('noreply@verify.local')
        code, message = smtp.rcpt(email)
        smtp.quit()
        
        message_str = message.decode() if isinstance(message, bytes) else str(message)
        
        # 250 = OK, mailbox exists
        if code == 250:
            return True, "Mailbox exists"
        
        # 550 = Mailbox not found (but some servers always return this)
        # 551 = User not local
        # 552 = Mailbox full
        # 553 = Mailbox name not allowed
        # 554 = Transaction failed
        elif code in [550, 551, 553]:
            return False, f"Mailbox rejected (code {code})"
        
        # 552 = Mailbox full - still valid but full
        elif code == 552:
            return True, "Mailbox exists but full"
        
        # 450, 451, 452 = Temporary failures - treat as uncertain
        elif code in [450, 451, 452]:
            return None, "Temporary server error"
        
        # Other codes - uncertain
        else:
            return None, f"Uncertain response (code {code})"
            
    except smtplib.SMTPServerDisconnected:
        return None, "Server disconnected (anti-spam)"
    except smtplib.SMTPConnectError:
        return None, "Could not connect to mail server"
    except socket.timeout:
        return None, "Connection timeout"
    except Exception as e:
        logger.warning(f"SMTP verification failed for {email}: {str(e)}")
        return None, str(e)

def validate_single_email(email: str) -> EmailResult:
    """Perform full validation on a single email"""
    email = email.strip().lower()
    
    # Format validation
    format_valid = validate_email_format(email)
    if not format_valid:
        return EmailResult(
            email=email,
            status=EmailStatus.INVALID,
            format_valid=False,
            domain_valid=False,
            mx_valid=False,
            is_disposable=False,
            smtp_valid=None,
            reason="Invalid email format"
        )
    
    # Domain extraction
    domain = extract_domain(email)
    if not domain:
        return EmailResult(
            email=email,
            status=EmailStatus.INVALID,
            format_valid=True,
            domain_valid=False,
            mx_valid=False,
            is_disposable=False,
            smtp_valid=None,
            reason="Could not extract domain"
        )
    
    # Domain validation
    domain_valid = validate_domain(domain)
    if not domain_valid:
        return EmailResult(
            email=email,
            status=EmailStatus.INVALID,
            format_valid=True,
            domain_valid=False,
            mx_valid=False,
            is_disposable=False,
            smtp_valid=None,
            reason="Domain does not exist"
        )
    
    # Disposable check
    is_disposable = is_disposable_email(domain)
    
    # MX record check
    mx_records = get_mx_records(domain)
    mx_valid = len(mx_records) > 0
    
    if not mx_valid:
        return EmailResult(
            email=email,
            status=EmailStatus.INVALID,
            format_valid=True,
            domain_valid=True,
            mx_valid=False,
            is_disposable=is_disposable,
            smtp_valid=None,
            reason="No MX records found"
        )
    
    # SMTP verification
    smtp_valid = None
    if mx_records:
        for mx_host in mx_records[:2]:  # Try first 2 MX records
            smtp_valid = verify_smtp(email, mx_host)
            if smtp_valid is not None:
                break
    
    # Determine final status
    if smtp_valid is False:
        status = EmailStatus.INVALID
        reason = "Mailbox does not exist"
    elif is_disposable:
        status = EmailStatus.RISKY
        reason = "Disposable email address"
    elif smtp_valid is True:
        status = EmailStatus.VALID
        reason = "Email is valid and deliverable"
    elif smtp_valid is None and mx_valid:
        status = EmailStatus.RISKY
        reason = "Could not verify mailbox (server unreachable)"
    else:
        status = EmailStatus.UNKNOWN
        reason = "Could not determine email validity"
    
    return EmailResult(
        email=email,
        status=status,
        format_valid=True,
        domain_valid=True,
        mx_valid=mx_valid,
        is_disposable=is_disposable,
        smtp_valid=smtp_valid,
        reason=reason
    )

async def process_validation_job(job_id: str, emails: List[str]):
    """Background task to process email validation"""
    try:
        # Update job status to processing
        await db.validation_jobs.update_one(
            {"id": job_id},
            {"$set": {"status": JobStatus.PROCESSING}}
        )
        
        results = []
        valid_count = 0
        invalid_count = 0
        risky_count = 0
        unknown_count = 0
        
        for i, email in enumerate(emails):
            result = validate_single_email(email)
            results.append(result.model_dump())
            
            # Update counts
            if result.status == EmailStatus.VALID:
                valid_count += 1
            elif result.status == EmailStatus.INVALID:
                invalid_count += 1
            elif result.status == EmailStatus.RISKY:
                risky_count += 1
            else:
                unknown_count += 1
            
            # Update progress every 10 emails
            if (i + 1) % 10 == 0 or i == len(emails) - 1:
                await db.validation_jobs.update_one(
                    {"id": job_id},
                    {"$set": {
                        "processed_emails": i + 1,
                        "valid_count": valid_count,
                        "invalid_count": invalid_count,
                        "risky_count": risky_count,
                        "unknown_count": unknown_count,
                        "results": results
                    }}
                )
        
        # Mark job as completed
        await db.validation_jobs.update_one(
            {"id": job_id},
            {"$set": {
                "status": JobStatus.COMPLETED,
                "completed_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        logger.info(f"Job {job_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Job {job_id} failed: {str(e)}")
        await db.validation_jobs.update_one(
            {"id": job_id},
            {"$set": {"status": JobStatus.FAILED}}
        )

# API Routes
@api_router.get("/")
async def root():
    return {"message": "Email Validator API"}

@api_router.post("/validate/single")
async def validate_single(email: str):
    """Validate a single email address"""
    result = validate_single_email(email)
    return result.model_dump()

@api_router.post("/validate/bulk")
async def validate_bulk(request: BulkValidateRequest, background_tasks: BackgroundTasks):
    """Start bulk email validation job"""
    emails = [e.strip() for e in request.emails if e.strip()]
    
    if not emails:
        raise HTTPException(status_code=400, detail="No valid emails provided")
    
    if len(emails) > 10000:
        raise HTTPException(status_code=400, detail="Maximum 10,000 emails per batch")
    
    # Create job
    job = ValidationJob(
        total_emails=len(emails),
        results=[]
    )
    
    job_doc = job.model_dump()
    job_doc['created_at'] = job_doc['created_at'].isoformat()
    await db.validation_jobs.insert_one(job_doc)
    
    # Start background processing
    background_tasks.add_task(process_validation_job, job.id, emails)
    
    return {
        "job_id": job.id,
        "total_emails": len(emails),
        "status": job.status
    }

@api_router.post("/validate/upload")
async def validate_upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Upload CSV file for bulk validation"""
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are supported")
    
    content = await file.read()
    content_str = content.decode('utf-8')
    
    # Parse CSV
    emails = []
    reader = csv.reader(io.StringIO(content_str))
    for row in reader:
        for cell in row:
            cell = cell.strip()
            if '@' in cell and validate_email_format(cell):
                emails.append(cell)
    
    if not emails:
        raise HTTPException(status_code=400, detail="No valid emails found in CSV")
    
    if len(emails) > 10000:
        raise HTTPException(status_code=400, detail="Maximum 10,000 emails per file")
    
    # Create job
    job = ValidationJob(
        total_emails=len(emails),
        results=[]
    )
    
    job_doc = job.model_dump()
    job_doc['created_at'] = job_doc['created_at'].isoformat()
    await db.validation_jobs.insert_one(job_doc)
    
    # Start background processing
    background_tasks.add_task(process_validation_job, job.id, emails)
    
    return {
        "job_id": job.id,
        "total_emails": len(emails),
        "status": job.status
    }

@api_router.get("/validate/job/{job_id}")
async def get_job_status(job_id: str):
    """Get validation job status and results"""
    job = await db.validation_jobs.find_one({"id": job_id}, {"_id": 0})
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return job

@api_router.get("/validate/job/{job_id}/export")
async def export_job_results(job_id: str, status_filter: Optional[str] = None):
    """Export job results as CSV"""
    job = await db.validation_jobs.find_one({"id": job_id}, {"_id": 0})
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job['status'] != JobStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Job is not completed yet")
    
    results = job.get('results', [])
    
    # Filter if requested
    if status_filter:
        results = [r for r in results if r['status'] == status_filter]
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Email', 'Status', 'Format Valid', 'Domain Valid', 'MX Valid', 'Disposable', 'SMTP Valid', 'Reason'])
    
    for result in results:
        writer.writerow([
            result['email'],
            result['status'],
            result['format_valid'],
            result['domain_valid'],
            result['mx_valid'],
            result['is_disposable'],
            result['smtp_valid'],
            result['reason']
        ])
    
    output.seek(0)
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=email_validation_{job_id}.csv"}
    )

@api_router.get("/validate/jobs")
async def get_all_jobs(limit: int = 20):
    """Get all validation jobs"""
    jobs = await db.validation_jobs.find({}, {"_id": 0, "results": 0}).sort("created_at", -1).to_list(limit)
    return jobs

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
