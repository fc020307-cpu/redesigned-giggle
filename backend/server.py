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

# Comprehensive disposable email domains list
DISPOSABLE_DOMAINS = {
    # Popular disposable services
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
    "spamfree24.de", "spamfree24.eu", "spamfree24.info", "spamfree24.net",
    "spamfree24.org", "spaml.com", "spaml.de", "spammotel.com", "squizzy.de",
    "teleosaurs.xyz", "tempemail.net", "tempinbox.co.uk", "tempmail.net",
    "tempomail.fr", "temporaryemail.net", "temporaryforwarding.com",
    "thankyou2010.com", "thisisnotmyrealemail.com", "trash2009.com",
    "trashymail.com", "trashymail.net", "wh4f.org", "willselfdestruct.com",
    "xagloo.com", "xemaps.com", "xmaily.com", "yogamaven.com", "yuurok.com",
    "zehnminuten.de", "zoemail.net", "zoemail.org"
}

# Role-based email prefixes (often not real users)
ROLE_PREFIXES = {
    "admin", "administrator", "webmaster", "postmaster", "hostmaster",
    "info", "contact", "support", "help", "sales", "marketing",
    "abuse", "noc", "security", "billing", "accounts", "hr",
    "jobs", "careers", "press", "media", "legal", "compliance",
    "no-reply", "noreply", "no_reply", "donotreply", "do-not-reply",
    "mailer-daemon", "mailerdaemon", "daemon", "root", "null"
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
    smtp_valid: Optional[bool] = None
    is_disposable: bool
    is_role_email: bool = False
    is_free_email: bool = False
    quality_score: float = 0.0
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

# Free email providers (legitimate but free)
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.fr",
    "yahoo.de", "yahoo.es", "yahoo.it", "hotmail.com", "outlook.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me", "zoho.com", "mail.com", "gmx.com",
    "gmx.de", "yandex.com", "yandex.ru", "mail.ru", "inbox.com",
    "fastmail.com", "tutanota.com", "hey.com"
}

# Email validation functions
def validate_email_format(email: str) -> Tuple[bool, str]:
    """Validate email format with detailed checks"""
    email = email.strip().lower()
    
    # Basic checks
    if not email:
        return False, "Empty email"
    
    if email.count('@') != 1:
        return False, "Invalid format - must contain exactly one @"
    
    local, domain = email.split('@')
    
    # Local part checks
    if not local:
        return False, "Missing local part (before @)"
    if len(local) > 64:
        return False, "Local part too long (max 64 chars)"
    if local.startswith('.') or local.endswith('.'):
        return False, "Local part cannot start or end with dot"
    if '..' in local:
        return False, "Local part cannot have consecutive dots"
    
    # Domain checks
    if not domain:
        return False, "Missing domain (after @)"
    if len(domain) > 253:
        return False, "Domain too long"
    if '.' not in domain:
        return False, "Invalid domain - missing TLD"
    if domain.startswith('.') or domain.endswith('.'):
        return False, "Domain cannot start or end with dot"
    if '..' in domain:
        return False, "Domain cannot have consecutive dots"
    
    # Regex for allowed characters
    local_pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+$'
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    
    if not re.match(local_pattern, local):
        return False, "Invalid characters in local part"
    if not re.match(domain_pattern, domain):
        return False, "Invalid domain format"
    
    return True, "Valid format"

def extract_domain(email: str) -> Optional[str]:
    """Extract domain from email"""
    try:
        return email.strip().lower().split('@')[1]
    except IndexError:
        return None

def get_local_part(email: str) -> Optional[str]:
    """Extract local part from email"""
    try:
        return email.strip().lower().split('@')[0]
    except IndexError:
        return None

def is_role_email(email: str) -> bool:
    """Check if email is a role-based address"""
    local = get_local_part(email)
    if not local:
        return False
    # Check exact match and common patterns
    return local in ROLE_PREFIXES or any(local.startswith(prefix + ".") or local.startswith(prefix + "-") for prefix in ROLE_PREFIXES)

def is_disposable_email(domain: str) -> bool:
    """Check if email domain is disposable"""
    return domain.lower() in DISPOSABLE_DOMAINS

def is_free_email(domain: str) -> bool:
    """Check if email is from a free provider"""
    return domain.lower() in FREE_EMAIL_PROVIDERS

def validate_domain(domain: str) -> Tuple[bool, str]:
    """Check if domain exists and can receive email"""
    try:
        socket.gethostbyname(domain)
        return True, "Domain exists"
    except socket.gaierror:
        return False, "Domain does not exist"

def get_mx_records(domain: str) -> Tuple[List[str], str]:
    """Get MX records for domain"""
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_hosts = [str(record.exchange).rstrip('.') for record in sorted(records, key=lambda x: x.preference)]
        return mx_hosts, f"Found {len(mx_hosts)} MX record(s)"
    except dns.resolver.NXDOMAIN:
        return [], "Domain not found in DNS"
    except dns.resolver.NoAnswer:
        return [], "No MX records configured"
    except dns.resolver.NoNameservers:
        return [], "No nameservers available"
    except Exception as e:
        return [], f"DNS lookup failed: {str(e)}"

def verify_smtp(email: str, mx_host: str, timeout: int = 10) -> Tuple[Optional[bool], str]:
    """
    Verify email via SMTP
    Returns: (status, reason)
    - True: Mailbox definitely exists
    - False: Mailbox definitely doesn't exist
    - None: Cannot determine
    """
    try:
        smtp = smtplib.SMTP(timeout=timeout)
        smtp.connect(mx_host)
        smtp.helo('verify.check')
        smtp.mail('verify@verify.check')
        code, message = smtp.rcpt(email)
        smtp.quit()
        
        message_str = message.decode() if isinstance(message, bytes) else str(message)
        
        if code == 250:
            return True, "Mailbox exists (SMTP verified)"
        elif code in [550, 551, 552, 553, 554]:
            # Check if it's a catch-all rejection or real rejection
            lower_msg = message_str.lower()
            if "user unknown" in lower_msg or "does not exist" in lower_msg or "no such user" in lower_msg:
                return False, "Mailbox does not exist"
            elif "rejected" in lower_msg or "denied" in lower_msg:
                return None, "Server rejected verification attempt"
            return False, f"Mailbox rejected (code {code})"
        elif code in [450, 451, 452]:
            return None, "Temporary server issue"
        else:
            return None, f"Uncertain (code {code})"
            
    except smtplib.SMTPServerDisconnected:
        return None, "Server blocks verification"
    except smtplib.SMTPConnectError:
        return None, "Could not connect to mail server"
    except socket.timeout:
        return None, "Connection timeout"
    except Exception as e:
        return None, f"SMTP error: {str(e)[:50]}"

def calculate_quality_score(result: dict) -> float:
    """Calculate email quality score (0.0 to 1.0)"""
    score = 0.0
    
    # Format validation (20%)
    if result.get('format_valid'):
        score += 0.20
    
    # Domain validation (20%)
    if result.get('domain_valid'):
        score += 0.20
    
    # MX records (25%)
    if result.get('mx_valid'):
        score += 0.25
    
    # SMTP verification (25%)
    smtp = result.get('smtp_valid')
    if smtp is True:
        score += 0.25
    elif smtp is None:
        score += 0.10  # Partial credit if uncertain
    
    # Penalties
    if result.get('is_disposable'):
        score -= 0.30
    if result.get('is_role_email'):
        score -= 0.10
    
    return max(0.0, min(1.0, score))

def validate_single_email_sync(email: str) -> EmailResult:
    """Perform comprehensive validation on a single email"""
    email = email.strip().lower()
    
    # Step 1: Format validation
    format_valid, format_reason = validate_email_format(email)
    if not format_valid:
        return EmailResult(
            email=email,
            status=EmailStatus.INVALID,
            format_valid=False,
            domain_valid=False,
            mx_valid=False,
            smtp_valid=None,
            is_disposable=False,
            is_role_email=False,
            is_free_email=False,
            quality_score=0.0,
            reason=format_reason
        )
    
    # Step 2: Extract domain and local part
    domain = extract_domain(email)
    if not domain:
        return EmailResult(
            email=email,
            status=EmailStatus.INVALID,
            format_valid=True,
            domain_valid=False,
            mx_valid=False,
            smtp_valid=None,
            is_disposable=False,
            is_role_email=False,
            is_free_email=False,
            quality_score=0.1,
            reason="Could not extract domain"
        )
    
    # Step 3: Check disposable and role-based
    disposable = is_disposable_email(domain)
    role_email = is_role_email(email)
    free_email = is_free_email(domain)
    
    # Step 4: Domain validation
    domain_valid, domain_reason = validate_domain(domain)
    if not domain_valid:
        return EmailResult(
            email=email,
            status=EmailStatus.INVALID,
            format_valid=True,
            domain_valid=False,
            mx_valid=False,
            smtp_valid=None,
            is_disposable=disposable,
            is_role_email=role_email,
            is_free_email=free_email,
            quality_score=0.2,
            reason=f"Invalid domain: {domain_reason}"
        )
    
    # Step 5: MX record lookup
    mx_records, mx_reason = get_mx_records(domain)
    mx_valid = len(mx_records) > 0
    
    if not mx_valid:
        return EmailResult(
            email=email,
            status=EmailStatus.INVALID,
            format_valid=True,
            domain_valid=True,
            mx_valid=False,
            smtp_valid=None,
            is_disposable=disposable,
            is_role_email=role_email,
            is_free_email=free_email,
            quality_score=0.3,
            reason=f"Cannot receive email: {mx_reason}"
        )
    
    # Step 6: SMTP verification (try up to 2 MX servers)
    smtp_valid = None
    smtp_reason = "Not checked"
    
    for mx_host in mx_records[:2]:
        smtp_valid, smtp_reason = verify_smtp(email, mx_host)
        if smtp_valid is not None:
            break
    
    # Step 7: Determine final status
    result_data = {
        'format_valid': True,
        'domain_valid': True,
        'mx_valid': True,
        'smtp_valid': smtp_valid,
        'is_disposable': disposable,
        'is_role_email': role_email,
        'is_free_email': free_email
    }
    
    quality_score = calculate_quality_score(result_data)
    
    # Determine status and reason
    if disposable:
        status = EmailStatus.RISKY
        reason = "Disposable/temporary email address"
    elif smtp_valid is False:
        status = EmailStatus.INVALID
        reason = f"Mailbox does not exist: {smtp_reason}"
    elif smtp_valid is True:
        if role_email:
            status = EmailStatus.RISKY
            reason = "Role-based email (valid but may not reach a person)"
        else:
            status = EmailStatus.VALID
            reason = "Email verified - mailbox exists"
    elif smtp_valid is None:
        # SMTP couldn't verify - make decision based on other factors
        if quality_score >= 0.6:
            status = EmailStatus.VALID
            reason = f"Likely valid (MX verified, {smtp_reason})"
        else:
            status = EmailStatus.RISKY
            reason = f"Could not verify mailbox: {smtp_reason}"
    else:
        status = EmailStatus.UNKNOWN
        reason = "Could not determine validity"
    
    return EmailResult(
        email=email,
        status=status,
        format_valid=True,
        domain_valid=True,
        mx_valid=True,
        smtp_valid=smtp_valid,
        is_disposable=disposable,
        is_role_email=role_email,
        is_free_email=free_email,
        quality_score=round(quality_score, 2),
        reason=reason
    )

async def validate_single_email(email: str) -> EmailResult:
    """Async wrapper for email validation"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, validate_single_email_sync, email)

async def process_validation_job(job_id: str, emails: List[str]):
    """Background task to process email validation"""
    try:
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
            result = await validate_single_email(email)
            results.append(result.model_dump())
            
            if result.status == EmailStatus.VALID:
                valid_count += 1
            elif result.status == EmailStatus.INVALID:
                invalid_count += 1
            elif result.status == EmailStatus.RISKY:
                risky_count += 1
            else:
                unknown_count += 1
            
            # Update progress every 5 emails
            if (i + 1) % 5 == 0 or i == len(emails) - 1:
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
        
        await db.validation_jobs.update_one(
            {"id": job_id},
            {"$set": {
                "status": JobStatus.COMPLETED,
                "completed_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        logger.info(f"Job {job_id} completed: {valid_count} valid, {invalid_count} invalid, {risky_count} risky")
        
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
    result = await validate_single_email(email)
    return result.model_dump()

@api_router.post("/validate/bulk")
async def validate_bulk(request: BulkValidateRequest, background_tasks: BackgroundTasks):
    """Start bulk email validation job"""
    emails = [e.strip() for e in request.emails if e.strip()]
    
    if not emails:
        raise HTTPException(status_code=400, detail="No valid emails provided")
    
    if len(emails) > 10000:
        raise HTTPException(status_code=400, detail="Maximum 10,000 emails per batch")
    
    job = ValidationJob(total_emails=len(emails), results=[])
    
    job_doc = job.model_dump()
    job_doc['created_at'] = job_doc['created_at'].isoformat()
    await db.validation_jobs.insert_one(job_doc)
    
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
    
    emails = []
    reader = csv.reader(io.StringIO(content_str))
    for row in reader:
        for cell in row:
            cell = cell.strip()
            if '@' in cell:
                format_valid, _ = validate_email_format(cell)
                if format_valid:
                    emails.append(cell)
    
    if not emails:
        raise HTTPException(status_code=400, detail="No valid emails found in CSV")
    
    if len(emails) > 10000:
        raise HTTPException(status_code=400, detail="Maximum 10,000 emails per file")
    
    job = ValidationJob(total_emails=len(emails), results=[])
    
    job_doc = job.model_dump()
    job_doc['created_at'] = job_doc['created_at'].isoformat()
    await db.validation_jobs.insert_one(job_doc)
    
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
    
    if status_filter:
        results = [r for r in results if r['status'] == status_filter]
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Email', 'Status', 'Quality Score', 'MX Valid', 'SMTP Valid', 'Disposable', 'Role Email', 'Free Email', 'Reason'])
    
    for result in results:
        writer.writerow([
            result['email'],
            result['status'],
            result.get('quality_score', 0),
            result['mx_valid'],
            result.get('smtp_valid', ''),
            result['is_disposable'],
            result.get('is_role_email', False),
            result.get('is_free_email', False),
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
