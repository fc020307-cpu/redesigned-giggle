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
import random
import string
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Tuple, Dict
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

# ============================================
# PROVIDER CLASSIFICATION
# ============================================

# Providers where we CAN verify if username/mailbox exists (SMTP returns 550 for non-existent)
VERIFIABLE_PROVIDERS = {
    "gmail.com", "googlemail.com",  # Google
    "icloud.com", "me.com", "mac.com",  # Apple
    "protonmail.com", "proton.me", "pm.me",  # Proton
    "zoho.com", "zohomail.com",  # Zoho
    "fastmail.com", "fastmail.fm",  # Fastmail
    "tutanota.com", "tutanota.de", "tutamail.com",  # Tutanota
    "hey.com",  # Basecamp Hey
    "runbox.com",  # Runbox
    "posteo.de", "posteo.net",  # Posteo
    "mailbox.org",  # Mailbox.org
}

# Providers that are CATCH-ALL (accept everything - can't verify username)
CATCHALL_PROVIDERS = {
    "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.es", "yahoo.it", "ymail.com",
    "aol.com", "aim.com",
    "att.net", "sbcglobal.net", "bellsouth.net", "pacbell.net", "ameritech.net", "flash.net",
    "verizon.net",
    "cox.net",
    "charter.net", "spectrum.net",
    "earthlink.net",
    "juno.com", "netzero.com",
}

# Providers that BLOCK SMTP verification entirely
BLOCKING_PROVIDERS = {
    "outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.uk", "hotmail.fr",
    "gmx.com", "gmx.de", "gmx.net",
    "mail.com",
    "comcast.net", "xfinity.com",
    "mail.ru", "inbox.ru", "list.ru", "bk.ru",
    "yandex.com", "yandex.ru", "ya.ru",
    "163.com", "126.com", "qq.com",  # Chinese providers
    "web.de",
    "t-online.de",
    "orange.fr", "wanadoo.fr",
    "libero.it", "virgilio.it",
}

# Disposable email domains (expanded list)
DISPOSABLE_DOMAINS = {
    "tempmail.com", "temp-mail.org", "10minutemail.com", "10minutemail.net",
    "guerrillamail.com", "guerrillamail.org", "guerrillamail.net", "guerrillamail.biz",
    "mailinator.com", "mailinator2.com", "mailinator.net",
    "throwaway.email", "throwawaymail.com",
    "fakeinbox.com", "trashmail.com", "trashmail.net",
    "getnada.com", "nada.email",
    "mohmal.com", "maildrop.cc", "mailnesia.com",
    "yopmail.com", "yopmail.fr", "yopmail.net",
    "dispostable.com", "sharklasers.com", "spam4.me", "grr.la",
    "tempail.com", "tmpmail.org", "tmpeml.com",
    "emailondeck.com", "minutemail.com",
    "tempr.email", "tempinbox.com", "tempmailaddress.com",
    "burnermail.io", "mailsac.com", "spamgourmet.com",
    "mytemp.email", "getairmail.com", "tempmailo.com",
    "33mail.com", "dropmail.me", "mailcatch.com",
    "mailexpire.com", "meltmail.com", "mintemail.com",
    "mytrashmail.com", "spambox.us", "spamex.com",
    "trashymail.com", "zehnminuten.de", "20minutemail.com",
    "mailnull.com", "e4ward.com", "spamcowboy.com",
    "fakemailgenerator.com", "armyspy.com", "cuvox.de",
    "dayrep.com", "einrot.com", "fleckens.hu", "gustr.com",
    "jourrapide.com", "rhyta.com", "superrito.com", "teleworm.us",
}

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

class EmailResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    email: str
    status: EmailStatus
    format_valid: bool
    domain_valid: bool
    mx_valid: bool
    mailbox_status: str  # "verified", "not_found", "catch_all", "blocked", "unknown"
    is_disposable: bool
    provider_type: str  # "verifiable", "catch_all", "blocked", "unknown"
    confidence: int  # 0-100%
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

# ============================================
# VALIDATION FUNCTIONS
# ============================================

def validate_email_format(email: str) -> Tuple[bool, str]:
    """Strict email format validation"""
    email = email.strip().lower()
    
    if not email:
        return False, "Empty email"
    if len(email) > 254:
        return False, "Email too long"
    if email.count('@') != 1:
        return False, "Must have exactly one @"
    
    local, domain = email.split('@')
    
    # Local part validation
    if not local:
        return False, "Missing username"
    if len(local) > 64:
        return False, "Username too long"
    if local.startswith('.') or local.endswith('.'):
        return False, "Username can't start/end with dot"
    if '..' in local:
        return False, "Username has consecutive dots"
    
    # Domain validation
    if not domain:
        return False, "Missing domain"
    if len(domain) > 253:
        return False, "Domain too long"
    if '.' not in domain:
        return False, "Invalid domain"
    if domain.startswith('.') or domain.endswith('.'):
        return False, "Invalid domain format"
    if domain.startswith('-') or domain.endswith('-'):
        return False, "Invalid domain format"
    
    # Regex validation
    local_pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+$'
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    
    if not re.match(local_pattern, local):
        return False, "Invalid characters in username"
    if not re.match(domain_pattern, domain):
        return False, "Invalid domain format"
    
    return True, "Valid format"

def validate_domain_exists(domain: str) -> Tuple[bool, str]:
    """Check if domain exists in DNS"""
    try:
        socket.gethostbyname(domain)
        return True, "Domain exists"
    except socket.gaierror:
        # Try MX lookup as fallback
        try:
            dns.resolver.resolve(domain, 'MX')
            return True, "Domain exists (MX)"
        except:
            return False, "Domain not found"

def get_mx_records(domain: str) -> Tuple[List[str], str]:
    """Get MX records sorted by priority"""
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_list = [str(r.exchange).rstrip('.') for r in sorted(records, key=lambda x: x.preference)]
        return mx_list, f"{len(mx_list)} mail server(s)"
    except dns.resolver.NXDOMAIN:
        return [], "Domain not found"
    except dns.resolver.NoAnswer:
        return [], "No mail servers"
    except dns.resolver.NoNameservers:
        return [], "DNS error"
    except Exception as e:
        return [], f"DNS error: {str(e)[:20]}"

def check_if_catchall(domain: str, mx_host: str) -> Optional[bool]:
    """
    Check if domain is catch-all by testing with random non-existent address
    Returns: True=catch-all, False=not catch-all, None=couldn't determine
    """
    random_user = ''.join(random.choices(string.ascii_lowercase + string.digits, k=25))
    fake_email = f"nonexistent_{random_user}@{domain}"
    
    try:
        smtp = smtplib.SMTP(timeout=10)
        smtp.connect(mx_host)
        smtp.ehlo_or_helo_if_needed()
        smtp.mail('test@verifier.local')
        code, _ = smtp.rcpt(fake_email)
        smtp.quit()
        
        # If accepts random address = catch-all
        return code == 250
    except:
        return None

def verify_mailbox_smtp(email: str, mx_host: str) -> Tuple[Optional[bool], str]:
    """
    Verify mailbox via SMTP RCPT TO command
    Returns: (True=exists, False=doesn't exist, None=unknown), reason
    """
    try:
        smtp = smtplib.SMTP(timeout=12)
        smtp.connect(mx_host)
        smtp.ehlo_or_helo_if_needed()
        smtp.mail('verify@mailverifier.local')
        code, message = smtp.rcpt(email)
        smtp.quit()
        
        msg_str = message.decode() if isinstance(message, bytes) else str(message)
        msg_lower = msg_str.lower()
        
        if code == 250:
            return True, "Mailbox exists"
        elif code == 550:
            # Check for specific rejection messages
            if any(x in msg_lower for x in ["does not exist", "user unknown", "no such user", 
                                            "recipient rejected", "mailbox not found", "invalid recipient",
                                            "unknown user", "user not found", "no mailbox"]):
                return False, "Mailbox does not exist"
            return False, "Mailbox rejected"
        elif code == 551:
            return False, "User not local"
        elif code == 552:
            return True, "Mailbox full (but exists)"
        elif code == 553:
            return False, "Invalid mailbox"
        elif code in [450, 451, 452]:
            return None, "Server busy, try later"
        elif code == 421:
            return None, "Server unavailable"
        else:
            return None, f"Unknown response ({code})"
            
    except smtplib.SMTPServerDisconnected:
        return None, "Server disconnected"
    except smtplib.SMTPConnectError:
        return None, "Connection refused"
    except socket.timeout:
        return None, "Timeout"
    except socket.gaierror:
        return None, "DNS error"
    except Exception as e:
        return None, str(e)[:30]

def get_provider_type(domain: str) -> str:
    """Classify the email provider"""
    domain = domain.lower()
    
    if domain in VERIFIABLE_PROVIDERS:
        return "verifiable"
    elif domain in CATCHALL_PROVIDERS:
        return "catch_all"
    elif domain in BLOCKING_PROVIDERS:
        return "blocked"
    else:
        return "unknown"

def is_disposable(domain: str) -> bool:
    """Check if domain is disposable"""
    return domain.lower() in DISPOSABLE_DOMAINS

def validate_single_email_sync(email: str) -> EmailResult:
    """
    Comprehensive email validation with confidence scoring
    """
    email = email.strip().lower()
    
    # Step 1: Format validation
    format_valid, format_msg = validate_email_format(email)
    if not format_valid:
        return EmailResult(
            email=email, status=EmailStatus.INVALID,
            format_valid=False, domain_valid=False, mx_valid=False,
            mailbox_status="invalid_format", is_disposable=False,
            provider_type="unknown", confidence=100,
            reason=f"Invalid: {format_msg}"
        )
    
    domain = email.split('@')[1]
    disposable = is_disposable(domain)
    provider_type = get_provider_type(domain)
    
    # Step 2: Domain validation
    domain_valid, domain_msg = validate_domain_exists(domain)
    if not domain_valid:
        return EmailResult(
            email=email, status=EmailStatus.INVALID,
            format_valid=True, domain_valid=False, mx_valid=False,
            mailbox_status="domain_not_found", is_disposable=disposable,
            provider_type=provider_type, confidence=100,
            reason=f"Invalid: {domain_msg}"
        )
    
    # Step 3: MX record validation
    mx_records, mx_msg = get_mx_records(domain)
    if not mx_records:
        return EmailResult(
            email=email, status=EmailStatus.INVALID,
            format_valid=True, domain_valid=True, mx_valid=False,
            mailbox_status="no_mx_records", is_disposable=disposable,
            provider_type=provider_type, confidence=100,
            reason=f"Invalid: {mx_msg}"
        )
    
    # Step 4: Handle disposable emails
    if disposable:
        return EmailResult(
            email=email, status=EmailStatus.RISKY,
            format_valid=True, domain_valid=True, mx_valid=True,
            mailbox_status="disposable", is_disposable=True,
            provider_type=provider_type, confidence=95,
            reason="Risky: Disposable/temporary email"
        )
    
    # Step 5: Provider-specific validation
    mx_host = mx_records[0]
    
    if provider_type == "verifiable":
        # These providers tell us if mailbox exists
        mailbox_exists, mailbox_reason = verify_mailbox_smtp(email, mx_host)
        
        if mailbox_exists is True:
            return EmailResult(
                email=email, status=EmailStatus.VALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="verified", is_disposable=False,
                provider_type=provider_type, confidence=99,
                reason="Valid: Mailbox verified to exist"
            )
        elif mailbox_exists is False:
            return EmailResult(
                email=email, status=EmailStatus.INVALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="not_found", is_disposable=False,
                provider_type=provider_type, confidence=99,
                reason=f"Invalid: {mailbox_reason}"
            )
        else:
            # Couldn't verify but it's a known verifiable provider
            return EmailResult(
                email=email, status=EmailStatus.UNKNOWN,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="unknown", is_disposable=False,
                provider_type=provider_type, confidence=70,
                reason=f"Unknown: Could not verify ({mailbox_reason})"
            )
    
    elif provider_type == "catch_all":
        # These providers accept everything - can't verify username
        return EmailResult(
            email=email, status=EmailStatus.VALID,
            format_valid=True, domain_valid=True, mx_valid=True,
            mailbox_status="catch_all", is_disposable=False,
            provider_type=provider_type, confidence=75,
            reason=f"Valid: {domain} accepts all addresses (catch-all)"
        )
    
    elif provider_type == "blocked":
        # These providers block SMTP verification
        return EmailResult(
            email=email, status=EmailStatus.VALID,
            format_valid=True, domain_valid=True, mx_valid=True,
            mailbox_status="blocked", is_disposable=False,
            provider_type=provider_type, confidence=80,
            reason=f"Valid: {domain} can receive email"
        )
    
    else:
        # Unknown provider - try SMTP verification
        # First check if it's catch-all
        is_catchall = check_if_catchall(domain, mx_host)
        
        if is_catchall is True:
            return EmailResult(
                email=email, status=EmailStatus.VALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="catch_all", is_disposable=False,
                provider_type="catch_all", confidence=75,
                reason=f"Valid: {domain} accepts all addresses (catch-all)"
            )
        
        # Try SMTP verification
        mailbox_exists, mailbox_reason = verify_mailbox_smtp(email, mx_host)
        
        if mailbox_exists is True:
            if is_catchall is False:
                confidence = 95
                mailbox_status = "verified"
            else:
                confidence = 80
                mailbox_status = "accepted"
            
            return EmailResult(
                email=email, status=EmailStatus.VALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status=mailbox_status, is_disposable=False,
                provider_type="unknown", confidence=confidence,
                reason="Valid: Mailbox exists"
            )
        elif mailbox_exists is False:
            return EmailResult(
                email=email, status=EmailStatus.INVALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="not_found", is_disposable=False,
                provider_type="unknown", confidence=90,
                reason=f"Invalid: {mailbox_reason}"
            )
        else:
            # Couldn't verify - mark as valid with lower confidence
            return EmailResult(
                email=email, status=EmailStatus.VALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="unverified", is_disposable=False,
                provider_type="unknown", confidence=70,
                reason=f"Valid: Domain can receive email ({mailbox_reason})"
            )

async def validate_single_email(email: str) -> EmailResult:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, validate_single_email_sync, email)

async def process_validation_job(job_id: str, emails: List[str]):
    try:
        await db.validation_jobs.update_one({"id": job_id}, {"$set": {"status": JobStatus.PROCESSING}})
        
        results = []
        valid_count = invalid_count = risky_count = unknown_count = 0
        
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
            {"$set": {"status": JobStatus.COMPLETED, "completed_at": datetime.now(timezone.utc).isoformat()}}
        )
        logger.info(f"Job {job_id}: {valid_count} valid, {invalid_count} invalid, {risky_count} risky, {unknown_count} unknown")
        
    except Exception as e:
        logger.error(f"Job {job_id} failed: {str(e)}")
        await db.validation_jobs.update_one({"id": job_id}, {"$set": {"status": JobStatus.FAILED}})

# ============================================
# API ROUTES
# ============================================

@api_router.get("/")
async def root():
    return {"message": "Email Validator API v2.0"}

@api_router.post("/validate/single")
async def validate_single(email: str):
    result = await validate_single_email(email)
    return result.model_dump()

@api_router.post("/validate/bulk")
async def validate_bulk(request: BulkValidateRequest, background_tasks: BackgroundTasks):
    emails = [e.strip() for e in request.emails if e.strip()]
    if not emails:
        raise HTTPException(status_code=400, detail="No emails")
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
        raise HTTPException(status_code=400, detail="CSV only")
    
    content = await file.read()
    emails = [cell.strip() for row in csv.reader(io.StringIO(content.decode('utf-8'))) 
              for cell in row if '@' in cell.strip()]
    
    if not emails:
        raise HTTPException(status_code=400, detail="No emails in file")
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
        raise HTTPException(status_code=404, detail="Not found")
    return job

@api_router.get("/validate/job/{job_id}/export")
async def export_job_results(job_id: str, status_filter: Optional[str] = None):
    job = await db.validation_jobs.find_one({"id": job_id}, {"_id": 0})
    if not job:
        raise HTTPException(status_code=404, detail="Not found")
    if job['status'] != JobStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Not completed")
    
    results = job.get('results', [])
    if status_filter:
        results = [r for r in results if r['status'] == status_filter]
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Email', 'Status', 'Confidence', 'Mailbox Status', 'Provider Type', 'Disposable', 'Reason'])
    for r in results:
        writer.writerow([r['email'], r['status'], f"{r['confidence']}%", 
                        r['mailbox_status'], r['provider_type'], r['is_disposable'], r['reason']])
    
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
