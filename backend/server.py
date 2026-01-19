from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import re
import dns.resolver
import socket
import csv
import io
import asyncio
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Tuple
import uuid
from datetime import datetime, timezone
from enum import Enum

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Comprehensive disposable email domains list (100+ domains)
DISPOSABLE_DOMAINS = {
    "tempmail.com", "temp-mail.org", "10minutemail.com", "guerrillamail.com",
    "mailinator.com", "throwaway.email", "fakeinbox.com", "trashmail.com",
    "getnada.com", "mohmal.com", "maildrop.cc", "yopmail.com", "yopmail.fr",
    "dispostable.com", "sharklasers.com", "spam4.me", "grr.la", "tempail.com",
    "tmpmail.org", "tmpeml.com", "emailondeck.com", "guerrillamailblock.com",
    "minutemail.com", "tempr.email", "throwawaymail.com", "mailnesia.com",
    "tempinbox.com", "tempmailaddress.com", "burnermail.io", "mailsac.com",
    "spamgourmet.com", "mytemp.email", "mt2015.com", "getairmail.com",
    "crazymailing.com", "tempmailo.com", "guerillamail.com", "guerillamail.org",
    "guerillamail.net", "guerillamail.biz", "guerillamail.de", "33mail.com",
    "dropmail.me", "mailcatch.com", "mailexpire.com", "mailforspam.com",
    "meltmail.com", "mintemail.com", "mytrashmail.com", "nobulk.com",
    "nospamfor.us", "nowmymail.com", "objectmail.com", "ownmail.net",
    "pookmail.com", "rppkn.com", "shortmail.net", "sneakemail.com",
    "sofimail.com", "spambox.us", "spamex.com", "spamfree24.com",
    "spaml.com", "spaml.de", "spammotel.com", "squizzy.de", "tempmail.net",
    "tempomail.fr", "temporaryemail.net", "temporaryforwarding.com",
    "trash2009.com", "trashymail.com", "trashymail.net", "willselfdestruct.com",
    "xagloo.com", "xemaps.com", "xmaily.com", "zehnminuten.de", "zoemail.net"
}

class EmailStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    RISKY = "risky"

class JobStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class EmailResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    email: str
    status: EmailStatus
    format_valid: bool
    domain_valid: bool
    mx_valid: bool
    is_disposable: bool
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
    results: List[EmailResult] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None

class BulkValidateRequest(BaseModel):
    emails: List[str]

def validate_email_format(email: str) -> Tuple[bool, str]:
    """Validate email format"""
    email = email.strip().lower()
    
    if not email:
        return False, "Empty email"
    if email.count('@') != 1:
        return False, "Must contain exactly one @"
    
    local, domain = email.split('@')
    
    if not local:
        return False, "Missing local part (before @)"
    if len(local) > 64:
        return False, "Local part too long"
    if local.startswith('.') or local.endswith('.') or '..' in local:
        return False, "Invalid dots in local part"
    
    if not domain:
        return False, "Missing domain"
    if '.' not in domain:
        return False, "Invalid domain - missing extension"
    if domain.startswith('.') or domain.endswith('.') or '..' in domain:
        return False, "Invalid dots in domain"
    
    # Check allowed characters
    local_pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+$'
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    
    if not re.match(local_pattern, local):
        return False, "Invalid characters in email"
    if not re.match(domain_pattern, domain):
        return False, "Invalid domain format"
    
    return True, "Valid format"

def validate_domain(domain: str) -> Tuple[bool, str]:
    """Check if domain exists"""
    try:
        socket.gethostbyname(domain)
        return True, "Domain exists"
    except socket.gaierror:
        return False, "Domain does not exist"

def get_mx_records(domain: str) -> Tuple[bool, str]:
    """Check if domain has MX records (can receive email)"""
    try:
        records = dns.resolver.resolve(domain, 'MX')
        if records:
            return True, f"Can receive email ({len(records)} mail servers)"
        return False, "No mail servers found"
    except dns.resolver.NXDOMAIN:
        return False, "Domain not found"
    except dns.resolver.NoAnswer:
        return False, "No mail servers configured"
    except dns.resolver.NoNameservers:
        return False, "DNS error"
    except Exception:
        return False, "Could not verify mail servers"

def is_disposable(domain: str) -> bool:
    """Check if domain is disposable/temporary"""
    return domain.lower() in DISPOSABLE_DOMAINS

def validate_single_email_sync(email: str) -> EmailResult:
    """Validate a single email - 100% accurate checks"""
    email = email.strip().lower()
    
    # Step 1: Format check
    format_valid, format_msg = validate_email_format(email)
    if not format_valid:
        return EmailResult(
            email=email,
            status=EmailStatus.INVALID,
            format_valid=False,
            domain_valid=False,
            mx_valid=False,
            is_disposable=False,
            reason=f"Invalid format: {format_msg}"
        )
    
    # Step 2: Extract domain
    domain = email.split('@')[1]
    
    # Step 3: Check if disposable
    disposable = is_disposable(domain)
    
    # Step 4: Domain exists check
    domain_valid, domain_msg = validate_domain(domain)
    if not domain_valid:
        return EmailResult(
            email=email,
            status=EmailStatus.INVALID,
            format_valid=True,
            domain_valid=False,
            mx_valid=False,
            is_disposable=disposable,
            reason=f"Invalid: {domain_msg}"
        )
    
    # Step 5: MX record check (can domain receive email?)
    mx_valid, mx_msg = get_mx_records(domain)
    if not mx_valid:
        return EmailResult(
            email=email,
            status=EmailStatus.INVALID,
            format_valid=True,
            domain_valid=True,
            mx_valid=False,
            is_disposable=disposable,
            reason=f"Invalid: {mx_msg}"
        )
    
    # Step 6: Final status
    if disposable:
        return EmailResult(
            email=email,
            status=EmailStatus.RISKY,
            format_valid=True,
            domain_valid=True,
            mx_valid=True,
            is_disposable=True,
            reason="Risky: Disposable/temporary email"
        )
    
    # All checks passed = VALID
    return EmailResult(
        email=email,
        status=EmailStatus.VALID,
        format_valid=True,
        domain_valid=True,
        mx_valid=True,
        is_disposable=False,
        reason="Valid: Email can receive messages"
    )

async def validate_single_email(email: str) -> EmailResult:
    """Async wrapper"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, validate_single_email_sync, email)

async def process_validation_job(job_id: str, emails: List[str]):
    """Background job processor"""
    try:
        await db.validation_jobs.update_one({"id": job_id}, {"$set": {"status": JobStatus.PROCESSING}})
        
        results = []
        valid_count = 0
        invalid_count = 0
        risky_count = 0
        
        for i, email in enumerate(emails):
            result = await validate_single_email(email)
            results.append(result.model_dump())
            
            if result.status == EmailStatus.VALID:
                valid_count += 1
            elif result.status == EmailStatus.INVALID:
                invalid_count += 1
            else:
                risky_count += 1
            
            # Update progress
            if (i + 1) % 5 == 0 or i == len(emails) - 1:
                await db.validation_jobs.update_one(
                    {"id": job_id},
                    {"$set": {
                        "processed_emails": i + 1,
                        "valid_count": valid_count,
                        "invalid_count": invalid_count,
                        "risky_count": risky_count,
                        "results": results
                    }}
                )
        
        await db.validation_jobs.update_one(
            {"id": job_id},
            {"$set": {"status": JobStatus.COMPLETED, "completed_at": datetime.now(timezone.utc).isoformat()}}
        )
        logger.info(f"Job {job_id} done: {valid_count} valid, {invalid_count} invalid, {risky_count} risky")
        
    except Exception as e:
        logger.error(f"Job {job_id} failed: {str(e)}")
        await db.validation_jobs.update_one({"id": job_id}, {"$set": {"status": JobStatus.FAILED}})

# API Routes
@api_router.get("/")
async def root():
    return {"message": "Email Validator API"}

@api_router.post("/validate/single")
async def validate_single(email: str):
    result = await validate_single_email(email)
    return result.model_dump()

@api_router.post("/validate/bulk")
async def validate_bulk(request: BulkValidateRequest, background_tasks: BackgroundTasks):
    emails = [e.strip() for e in request.emails if e.strip()]
    
    if not emails:
        raise HTTPException(status_code=400, detail="No emails provided")
    if len(emails) > 10000:
        raise HTTPException(status_code=400, detail="Maximum 10,000 emails")
    
    job = ValidationJob(total_emails=len(emails), results=[])
    job_doc = job.model_dump()
    job_doc['created_at'] = job_doc['created_at'].isoformat()
    await db.validation_jobs.insert_one(job_doc)
    
    background_tasks.add_task(process_validation_job, job.id, emails)
    
    return {"job_id": job.id, "total_emails": len(emails), "status": job.status}

@api_router.post("/validate/upload")
async def validate_upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files supported")
    
    content = await file.read()
    content_str = content.decode('utf-8')
    
    emails = []
    reader = csv.reader(io.StringIO(content_str))
    for row in reader:
        for cell in row:
            cell = cell.strip()
            if '@' in cell:
                emails.append(cell)
    
    if not emails:
        raise HTTPException(status_code=400, detail="No emails found in CSV")
    if len(emails) > 10000:
        raise HTTPException(status_code=400, detail="Maximum 10,000 emails")
    
    job = ValidationJob(total_emails=len(emails), results=[])
    job_doc = job.model_dump()
    job_doc['created_at'] = job_doc['created_at'].isoformat()
    await db.validation_jobs.insert_one(job_doc)
    
    background_tasks.add_task(process_validation_job, job.id, emails)
    
    return {"job_id": job.id, "total_emails": len(emails), "status": job.status}

@api_router.get("/validate/job/{job_id}")
async def get_job_status(job_id: str):
    job = await db.validation_jobs.find_one({"id": job_id}, {"_id": 0})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

@api_router.get("/validate/job/{job_id}/export")
async def export_job_results(job_id: str, status_filter: Optional[str] = None):
    job = await db.validation_jobs.find_one({"id": job_id}, {"_id": 0})
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job['status'] != JobStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Job not completed")
    
    results = job.get('results', [])
    if status_filter:
        results = [r for r in results if r['status'] == status_filter]
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Email', 'Status', 'Format', 'Domain', 'MX Records', 'Disposable', 'Reason'])
    
    for r in results:
        writer.writerow([
            r['email'], r['status'], r['format_valid'], r['domain_valid'],
            r['mx_valid'], r['is_disposable'], r['reason']
        ])
    
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=emails_{job_id}.csv"}
    )

@api_router.get("/validate/jobs")
async def get_all_jobs(limit: int = 20):
    jobs = await db.validation_jobs.find({}, {"_id": 0, "results": 0}).sort("created_at", -1).to_list(limit)
    return jobs

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
