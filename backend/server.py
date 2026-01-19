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
import asyncio
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Tuple
import uuid
from datetime import datetime, timezone
from enum import Enum

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disposable email domains
DISPOSABLE_DOMAINS = {
    "tempmail.com", "temp-mail.org", "10minutemail.com", "guerrillamail.com",
    "mailinator.com", "throwaway.email", "fakeinbox.com", "trashmail.com",
    "getnada.com", "mohmal.com", "maildrop.cc", "yopmail.com", "yopmail.fr",
    "dispostable.com", "sharklasers.com", "spam4.me", "grr.la", "tempail.com",
    "tmpmail.org", "tmpeml.com", "emailondeck.com", "guerrillamailblock.com",
    "minutemail.com", "tempr.email", "throwawaymail.com", "mailnesia.com",
    "tempinbox.com", "tempmailaddress.com", "burnermail.io", "mailsac.com",
    "spamgourmet.com", "mytemp.email", "getairmail.com", "tempmailo.com",
    "guerillamail.com", "guerillamail.org", "guerillamail.net", "33mail.com",
    "dropmail.me", "mailcatch.com", "mailexpire.com", "meltmail.com",
    "mintemail.com", "mytrashmail.com", "spambox.us", "spamex.com",
    "trashymail.com", "trashymail.net", "tempmail.net", "zehnminuten.de"
}

# Providers that ALLOW SMTP mailbox verification (we can check if username exists)
SMTP_VERIFIABLE_PROVIDERS = {
    "gmail.com", "googlemail.com"  # Gmail tells us if mailbox exists
}

# Providers that block SMTP or are catch-all (can't verify username)
SMTP_BLOCKED_PROVIDERS = {
    "yahoo.com", "yahoo.co.uk", "yahoo.fr",  # Catch-all
    "outlook.com", "hotmail.com", "live.com", "msn.com",  # Blocks connection
    "icloud.com", "me.com", "mac.com",
    "aol.com", "protonmail.com", "proton.me",
    "comcast.net", "verizon.net", "att.net", "sbcglobal.net",
    "zoho.com", "mail.com", "gmx.com"
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
    mailbox_verified: Optional[bool] = None
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
    email = email.strip().lower()
    if not email:
        return False, "Empty email"
    if email.count('@') != 1:
        return False, "Must contain exactly one @"
    
    local, domain = email.split('@')
    
    if not local or len(local) > 64:
        return False, "Invalid local part"
    if local.startswith('.') or local.endswith('.') or '..' in local:
        return False, "Invalid dots in local part"
    if not domain or '.' not in domain:
        return False, "Invalid domain"
    if domain.startswith('.') or domain.endswith('.') or '..' in domain:
        return False, "Invalid domain format"
    
    local_pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+$'
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    
    if not re.match(local_pattern, local):
        return False, "Invalid characters"
    if not re.match(domain_pattern, domain):
        return False, "Invalid domain format"
    
    return True, "Valid"

def validate_domain(domain: str) -> Tuple[bool, str]:
    try:
        socket.gethostbyname(domain)
        return True, "Domain exists"
    except socket.gaierror:
        return False, "Domain does not exist"

def get_mx_records(domain: str) -> Tuple[List[str], str]:
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_list = [str(r.exchange).rstrip('.') for r in sorted(records, key=lambda x: x.preference)]
        return mx_list, "MX records found"
    except dns.resolver.NXDOMAIN:
        return [], "Domain not found"
    except dns.resolver.NoAnswer:
        return [], "No mail servers"
    except Exception:
        return [], "DNS error"

def verify_mailbox_smtp(email: str, mx_host: str) -> Tuple[Optional[bool], str]:
    """
    Verify if mailbox exists via SMTP
    Returns: (True=exists, False=doesn't exist, None=couldn't verify), reason
    """
    try:
        smtp = smtplib.SMTP(timeout=10)
        smtp.connect(mx_host)
        smtp.helo('verify.local')
        smtp.mail('verify@verify.local')
        code, message = smtp.rcpt(email)
        smtp.quit()
        
        msg_str = message.decode() if isinstance(message, bytes) else str(message)
        
        if code == 250:
            return True, "Mailbox exists"
        elif code == 550:
            if "does not exist" in msg_str.lower() or "user unknown" in msg_str.lower() or "no such user" in msg_str.lower():
                return False, "Mailbox does not exist"
            return False, "Mailbox rejected"
        elif code in [450, 451, 452]:
            return None, "Server busy"
        else:
            return None, f"Unknown response ({code})"
            
    except smtplib.SMTPServerDisconnected:
        return None, "Server disconnected"
    except socket.timeout:
        return None, "Timeout"
    except Exception as e:
        return None, str(e)[:30]

def is_disposable(domain: str) -> bool:
    return domain.lower() in DISPOSABLE_DOMAINS

def validate_single_email_sync(email: str) -> EmailResult:
    email = email.strip().lower()
    
    # Step 1: Format validation
    format_valid, format_msg = validate_email_format(email)
    if not format_valid:
        return EmailResult(
            email=email, status=EmailStatus.INVALID,
            format_valid=False, domain_valid=False, mx_valid=False,
            mailbox_verified=None, is_disposable=False,
            reason=f"Invalid: {format_msg}"
        )
    
    domain = email.split('@')[1]
    disposable = is_disposable(domain)
    
    # Step 2: Domain validation
    domain_valid, domain_msg = validate_domain(domain)
    if not domain_valid:
        return EmailResult(
            email=email, status=EmailStatus.INVALID,
            format_valid=True, domain_valid=False, mx_valid=False,
            mailbox_verified=None, is_disposable=disposable,
            reason=f"Invalid: {domain_msg}"
        )
    
    # Step 3: MX record check
    mx_records, mx_msg = get_mx_records(domain)
    if not mx_records:
        return EmailResult(
            email=email, status=EmailStatus.INVALID,
            format_valid=True, domain_valid=True, mx_valid=False,
            mailbox_verified=None, is_disposable=disposable,
            reason=f"Invalid: {mx_msg}"
        )
    
    # Step 4: SMTP mailbox verification (only for supported providers)
    mailbox_verified = None
    mailbox_reason = ""
    
    if domain in SMTP_VERIFIABLE_PROVIDERS:
        # Gmail - we CAN verify if username exists
        for mx_host in mx_records[:2]:
            mailbox_verified, mailbox_reason = verify_mailbox_smtp(email, mx_host)
            if mailbox_verified is not None:
                break
        
        if mailbox_verified is False:
            return EmailResult(
                email=email, status=EmailStatus.INVALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_verified=False, is_disposable=disposable,
                reason=f"Invalid: {mailbox_reason}"
            )
        elif mailbox_verified is True:
            if disposable:
                return EmailResult(
                    email=email, status=EmailStatus.RISKY,
                    format_valid=True, domain_valid=True, mx_valid=True,
                    mailbox_verified=True, is_disposable=True,
                    reason="Risky: Disposable email (mailbox verified)"
                )
            return EmailResult(
                email=email, status=EmailStatus.VALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_verified=True, is_disposable=False,
                reason="Valid: Mailbox verified to exist"
            )
    
    # Step 5: For providers we can't verify mailbox
    if disposable:
        return EmailResult(
            email=email, status=EmailStatus.RISKY,
            format_valid=True, domain_valid=True, mx_valid=True,
            mailbox_verified=None, is_disposable=True,
            reason="Risky: Disposable/temporary email"
        )
    
    # Valid domain that can receive email
    if domain in SMTP_BLOCKED_PROVIDERS:
        reason = f"Valid: {domain} can receive email"
    else:
        # Try SMTP for unknown providers
        for mx_host in mx_records[:1]:
            mailbox_verified, mailbox_reason = verify_mailbox_smtp(email, mx_host)
            if mailbox_verified is False:
                return EmailResult(
                    email=email, status=EmailStatus.INVALID,
                    format_valid=True, domain_valid=True, mx_valid=True,
                    mailbox_verified=False, is_disposable=False,
                    reason=f"Invalid: {mailbox_reason}"
                )
            elif mailbox_verified is True:
                return EmailResult(
                    email=email, status=EmailStatus.VALID,
                    format_valid=True, domain_valid=True, mx_valid=True,
                    mailbox_verified=True, is_disposable=False,
                    reason="Valid: Mailbox verified"
                )
        reason = "Valid: Domain can receive email"
    
    return EmailResult(
        email=email, status=EmailStatus.VALID,
        format_valid=True, domain_valid=True, mx_valid=True,
        mailbox_verified=mailbox_verified, is_disposable=False,
        reason=reason
    )

async def validate_single_email(email: str) -> EmailResult:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, validate_single_email_sync, email)

async def process_validation_job(job_id: str, emails: List[str]):
    try:
        await db.validation_jobs.update_one({"id": job_id}, {"$set": {"status": JobStatus.PROCESSING}})
        
        results = []
        valid_count = invalid_count = risky_count = 0
        
        for i, email in enumerate(emails):
            result = await validate_single_email(email)
            results.append(result.model_dump())
            
            if result.status == EmailStatus.VALID:
                valid_count += 1
            elif result.status == EmailStatus.INVALID:
                invalid_count += 1
            else:
                risky_count += 1
            
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
        logger.info(f"Job {job_id}: {valid_count} valid, {invalid_count} invalid, {risky_count} risky")
        
    except Exception as e:
        logger.error(f"Job {job_id} failed: {str(e)}")
        await db.validation_jobs.update_one({"id": job_id}, {"$set": {"status": JobStatus.FAILED}})

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
        raise HTTPException(status_code=400, detail="Max 10,000 emails")
    
    job = ValidationJob(total_emails=len(emails), results=[])
    job_doc = job.model_dump()
    job_doc['created_at'] = job_doc['created_at'].isoformat()
    await db.validation_jobs.insert_one(job_doc)
    background_tasks.add_task(process_validation_job, job.id, emails)
    return {"job_id": job.id, "total_emails": len(emails), "status": job.status}

@api_router.post("/validate/upload")
async def validate_upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files")
    
    content = await file.read()
    emails = []
    reader = csv.reader(io.StringIO(content.decode('utf-8')))
    for row in reader:
        for cell in row:
            if '@' in cell.strip():
                emails.append(cell.strip())
    
    if not emails:
        raise HTTPException(status_code=400, detail="No emails in CSV")
    if len(emails) > 10000:
        raise HTTPException(status_code=400, detail="Max 10,000 emails")
    
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
    writer.writerow(['Email', 'Status', 'Format', 'Domain', 'MX', 'Mailbox Verified', 'Disposable', 'Reason'])
    for r in results:
        writer.writerow([r['email'], r['status'], r['format_valid'], r['domain_valid'], 
                        r['mx_valid'], r.get('mailbox_verified', ''), r['is_disposable'], r['reason']])
    
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                            headers={"Content-Disposition": f"attachment; filename=emails_{job_id}.csv"})

@api_router.get("/validate/jobs")
async def get_all_jobs(limit: int = 20):
    return await db.validation_jobs.find({}, {"_id": 0, "results": 0}).sort("created_at", -1).to_list(limit)

app.include_router(api_router)
app.add_middleware(CORSMiddleware, allow_credentials=True,
                   allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
                   allow_methods=["*"], allow_headers=["*"])

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
