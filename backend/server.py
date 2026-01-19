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
import ssl
import csv
import io
import asyncio
import random
import string
import time
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

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================
# PROVIDER CLASSIFICATION (Expanded)
# ============================================

# Providers where SMTP verification works reliably
VERIFIABLE_PROVIDERS = {
    # Google
    "gmail.com", "googlemail.com", "google.com",
    # Apple  
    "icloud.com", "me.com", "mac.com",
    # Proton
    "protonmail.com", "proton.me", "pm.me",
    # Other verifiable
    "zoho.com", "zohomail.com",
    "fastmail.com", "fastmail.fm",
    "tutanota.com", "tutanota.de", "tutamail.com",
    "hey.com", "runbox.com",
    "posteo.de", "posteo.net",
    "mailbox.org",
    "migadu.com",
    "soverin.net",
    "disroot.org",
    "riseup.net",
}

# Catch-all providers (accept everything)
CATCHALL_PROVIDERS = {
    "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.es", "yahoo.it", "ymail.com", "rocketmail.com",
    "aol.com", "aim.com", "love.com", "ygm.com", "games.com",
    "att.net", "sbcglobal.net", "bellsouth.net", "pacbell.net", "ameritech.net", "flash.net", "nvbell.net",
    "verizon.net", "frontier.com", "windstream.net",
    "cox.net", "charter.net", "spectrum.net", "brighthouse.com",
    "earthlink.net", "mindspring.com",
    "juno.com", "netzero.com", "peoplepc.com",
}

# Providers that block SMTP
BLOCKING_PROVIDERS = {
    "outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.uk", "hotmail.fr", "hotmail.de", "outlook.co.uk",
    "gmx.com", "gmx.de", "gmx.net", "gmx.at", "gmx.ch",
    "mail.com", "email.com", "usa.com", "post.com",
    "comcast.net", "xfinity.com",
    "mail.ru", "inbox.ru", "list.ru", "bk.ru",
    "yandex.com", "yandex.ru", "ya.ru",
    "163.com", "126.com", "qq.com", "sina.com", "sohu.com",
    "web.de", "freenet.de",
    "t-online.de", "vodafone.de",
    "orange.fr", "wanadoo.fr", "free.fr", "sfr.fr", "laposte.net",
    "libero.it", "virgilio.it", "tin.it", "alice.it",
    "uol.com.br", "bol.com.br", "terra.com.br",
}

# Disposable domains (100+)
DISPOSABLE_DOMAINS = {
    "tempmail.com", "temp-mail.org", "10minutemail.com", "10minutemail.net", "10minmail.com",
    "guerrillamail.com", "guerrillamail.org", "guerrillamail.net", "guerrillamail.biz", "guerrillamail.de",
    "mailinator.com", "mailinator2.com", "mailinator.net", "mailinator.org",
    "throwaway.email", "throwawaymail.com", "throw-away.email",
    "fakeinbox.com", "trashmail.com", "trashmail.net", "trashmail.org",
    "getnada.com", "nada.email", "tempinbox.com",
    "mohmal.com", "maildrop.cc", "mailnesia.com",
    "yopmail.com", "yopmail.fr", "yopmail.net", "cool.fr.nf",
    "dispostable.com", "sharklasers.com", "spam4.me", "grr.la",
    "tempail.com", "tmpmail.org", "tmpeml.com",
    "emailondeck.com", "minutemail.com", "20minutemail.com",
    "tempr.email", "tempmailaddress.com",
    "burnermail.io", "mailsac.com", "spamgourmet.com",
    "mytemp.email", "getairmail.com", "tempmailo.com",
    "33mail.com", "dropmail.me", "mailcatch.com",
    "mailexpire.com", "meltmail.com", "mintemail.com",
    "mytrashmail.com", "spambox.us", "spamex.com",
    "trashymail.com", "trashymail.net", "zehnminuten.de",
    "mailnull.com", "e4ward.com", "spamcowboy.com",
    "fakemailgenerator.com", "armyspy.com", "cuvox.de",
    "dayrep.com", "einrot.com", "fleckens.hu", "gustr.com",
    "jourrapide.com", "rhyta.com", "superrito.com", "teleworm.us",
    "discard.email", "discardmail.com", "disposableemailaddresses.com",
    "emailsensei.com", "fakemailgenerator.net", "imgof.com",
    "jetable.org", "kasmail.com", "mailcatch.com", "mailseal.de",
    "nospam.ze.tc", "nowmymail.com", "spamfree24.org",
    "spamobox.com", "tempemail.co.za", "tempemail.com",
    "tempemailgen.com", "tempsky.com", "trashemail.de",
    "wegwerfmail.de", "wegwerfmail.net", "willhackforfood.biz",
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
    mailbox_status: str
    is_disposable: bool
    provider_type: str
    confidence: int
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
# ADVANCED SMTP VERIFICATION
# ============================================

def get_mx_records(domain: str) -> List[str]:
    """Get MX records sorted by priority"""
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return [str(r.exchange).rstrip('.') for r in sorted(records, key=lambda x: x.preference)]
    except:
        return []

def smtp_verify_advanced(email: str, mx_host: str, retry_count: int = 2) -> Tuple[Optional[bool], str, int]:
    """
    Advanced SMTP verification with multiple techniques
    Returns: (exists, reason, response_code)
    """
    helo_domains = [
        'mail.google.com',
        'mx.outlook.com', 
        'mail.yahoo.com',
        'smtp.verify.net',
    ]
    
    from_addresses = [
        'postmaster@gmail.com',
        'mailer-daemon@outlook.com',
        'verify@yahoo.com',
        f'check@{email.split("@")[1]}',
    ]
    
    last_code = 0
    last_msg = ""
    
    for attempt in range(retry_count):
        for use_tls in [False, True]:
            try:
                smtp = smtplib.SMTP(timeout=12)
                smtp.connect(mx_host, 25)
                
                # Use random HELO domain
                helo = random.choice(helo_domains)
                smtp.helo(helo)
                
                # Try STARTTLS
                if use_tls:
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        smtp.starttls(context=context)
                        smtp.helo(helo)
                    except:
                        pass
                
                # Use random FROM address
                from_addr = random.choice(from_addresses)
                smtp.mail(from_addr)
                
                code, message = smtp.rcpt(email)
                smtp.quit()
                
                last_code = code
                last_msg = message.decode() if isinstance(message, bytes) else str(message)
                
                # Analyze response
                msg_lower = last_msg.lower()
                
                # Definite exists
                if code == 250:
                    return True, "Mailbox exists", code
                
                # Definite not exists
                if code == 550:
                    not_exist_phrases = [
                        "does not exist", "doesn't exist", "user unknown", "no such user",
                        "mailbox not found", "recipient rejected", "invalid recipient",
                        "user not found", "no mailbox", "unknown user", "invalid address",
                        "undeliverable", "not found", "disabled", "deactivated"
                    ]
                    if any(phrase in msg_lower for phrase in not_exist_phrases):
                        return False, "Mailbox does not exist", code
                
                # Rate limited or greylisted - retry
                if code in [450, 451, 452, 421]:
                    time.sleep(1)
                    continue
                
                # Mailbox full = exists
                if code == 552:
                    return True, "Mailbox exists (full)", code
                
                # Other 5xx errors
                if code >= 500:
                    return False, f"Rejected ({code})", code
                    
            except smtplib.SMTPServerDisconnected:
                last_msg = "Server disconnected"
            except smtplib.SMTPConnectError:
                last_msg = "Connection refused"
            except socket.timeout:
                last_msg = "Timeout"
            except Exception as e:
                last_msg = str(e)[:50]
    
    return None, last_msg, last_code

def check_catchall(domain: str, mx_host: str) -> Optional[bool]:
    """Check if domain accepts all emails (catch-all)"""
    random_user = ''.join(random.choices(string.ascii_lowercase + string.digits, k=30))
    fake_email = f"doesnotexist_{random_user}@{domain}"
    
    try:
        smtp = smtplib.SMTP(timeout=8)
        smtp.connect(mx_host, 25)
        smtp.helo('mail.checker.net')
        smtp.mail('test@checker.net')
        code, _ = smtp.rcpt(fake_email)
        smtp.quit()
        return code == 250
    except:
        return None

# ============================================
# VALIDATION FUNCTIONS
# ============================================

def validate_format(email: str) -> Tuple[bool, str]:
    """Strict format validation"""
    email = email.strip().lower()
    
    if not email or len(email) > 254:
        return False, "Invalid length"
    if email.count('@') != 1:
        return False, "Must have exactly one @"
    
    local, domain = email.split('@')
    
    if not local or len(local) > 64:
        return False, "Invalid username"
    if local[0] in '.-' or local[-1] in '.-' or '..' in local:
        return False, "Invalid username format"
    if not domain or '.' not in domain or len(domain) > 253:
        return False, "Invalid domain"
    if domain[0] in '-.' or domain[-1] in '-.' or '..' in domain:
        return False, "Invalid domain format"
    
    # Regex check
    if not re.match(r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+$', local):
        return False, "Invalid characters"
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', domain):
        return False, "Invalid domain"
    
    return True, "Valid"

def domain_exists(domain: str) -> bool:
    """Check if domain exists"""
    try:
        socket.gethostbyname(domain)
        return True
    except:
        try:
            dns.resolver.resolve(domain, 'MX')
            return True
        except:
            return False

def get_provider_type(domain: str) -> str:
    """Classify provider"""
    d = domain.lower()
    if d in VERIFIABLE_PROVIDERS:
        return "verifiable"
    if d in CATCHALL_PROVIDERS:
        return "catch_all"
    if d in BLOCKING_PROVIDERS:
        return "blocked"
    return "unknown"

def is_disposable(domain: str) -> bool:
    return domain.lower() in DISPOSABLE_DOMAINS

def validate_email_sync(email: str) -> EmailResult:
    """Full email validation"""
    email = email.strip().lower()
    
    # Format check
    format_ok, format_msg = validate_format(email)
    if not format_ok:
        return EmailResult(
            email=email, status=EmailStatus.INVALID,
            format_valid=False, domain_valid=False, mx_valid=False,
            mailbox_status="invalid_format", is_disposable=False,
            provider_type="unknown", confidence=100,
            reason=f"Invalid: {format_msg}"
        )
    
    domain = email.split('@')[1]
    disposable = is_disposable(domain)
    provider = get_provider_type(domain)
    
    # Domain check
    if not domain_exists(domain):
        return EmailResult(
            email=email, status=EmailStatus.INVALID,
            format_valid=True, domain_valid=False, mx_valid=False,
            mailbox_status="domain_invalid", is_disposable=disposable,
            provider_type=provider, confidence=100,
            reason="Invalid: Domain does not exist"
        )
    
    # MX check
    mx_records = get_mx_records(domain)
    if not mx_records:
        return EmailResult(
            email=email, status=EmailStatus.INVALID,
            format_valid=True, domain_valid=True, mx_valid=False,
            mailbox_status="no_mx", is_disposable=disposable,
            provider_type=provider, confidence=100,
            reason="Invalid: No mail servers found"
        )
    
    # Disposable check
    if disposable:
        return EmailResult(
            email=email, status=EmailStatus.RISKY,
            format_valid=True, domain_valid=True, mx_valid=True,
            mailbox_status="disposable", is_disposable=True,
            provider_type=provider, confidence=95,
            reason="Risky: Disposable/temporary email"
        )
    
    mx_host = mx_records[0]
    
    # Provider-specific handling
    if provider == "verifiable":
        # Try SMTP verification
        exists, reason, code = smtp_verify_advanced(email, mx_host)
        
        if exists is True:
            return EmailResult(
                email=email, status=EmailStatus.VALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="verified", is_disposable=False,
                provider_type=provider, confidence=99,
                reason="Valid: Mailbox verified"
            )
        elif exists is False:
            return EmailResult(
                email=email, status=EmailStatus.INVALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="not_found", is_disposable=False,
                provider_type=provider, confidence=99,
                reason=f"Invalid: {reason}"
            )
        else:
            # Couldn't verify - rate limited or connection issue
            return EmailResult(
                email=email, status=EmailStatus.VALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="unverified", is_disposable=False,
                provider_type=provider, confidence=85,
                reason=f"Valid: {domain} can receive email"
            )
    
    elif provider == "catch_all":
        return EmailResult(
            email=email, status=EmailStatus.VALID,
            format_valid=True, domain_valid=True, mx_valid=True,
            mailbox_status="catch_all", is_disposable=False,
            provider_type=provider, confidence=75,
            reason=f"Valid: {domain} accepts all addresses"
        )
    
    elif provider == "blocked":
        return EmailResult(
            email=email, status=EmailStatus.VALID,
            format_valid=True, domain_valid=True, mx_valid=True,
            mailbox_status="blocked", is_disposable=False,
            provider_type=provider, confidence=80,
            reason=f"Valid: {domain} can receive email"
        )
    
    else:
        # Unknown provider - try verification
        # First check catch-all
        is_catchall = check_catchall(domain, mx_host)
        
        if is_catchall is True:
            return EmailResult(
                email=email, status=EmailStatus.VALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="catch_all", is_disposable=False,
                provider_type="catch_all", confidence=75,
                reason=f"Valid: {domain} accepts all addresses"
            )
        
        # Try SMTP
        exists, reason, code = smtp_verify_advanced(email, mx_host)
        
        if exists is True:
            conf = 95 if is_catchall is False else 80
            return EmailResult(
                email=email, status=EmailStatus.VALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="verified", is_disposable=False,
                provider_type="unknown", confidence=conf,
                reason="Valid: Mailbox verified"
            )
        elif exists is False:
            return EmailResult(
                email=email, status=EmailStatus.INVALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="not_found", is_disposable=False,
                provider_type="unknown", confidence=90,
                reason=f"Invalid: {reason}"
            )
        else:
            return EmailResult(
                email=email, status=EmailStatus.VALID,
                format_valid=True, domain_valid=True, mx_valid=True,
                mailbox_status="unverified", is_disposable=False,
                provider_type="unknown", confidence=70,
                reason=f"Valid: Domain can receive email"
            )

async def validate_email(email: str) -> EmailResult:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, validate_email_sync, email)

async def process_job(job_id: str, emails: List[str]):
    try:
        await db.validation_jobs.update_one({"id": job_id}, {"$set": {"status": JobStatus.PROCESSING}})
        
        results = []
        counts = {"valid": 0, "invalid": 0, "risky": 0, "unknown": 0}
        
        for i, email in enumerate(emails):
            result = await validate_email(email)
            results.append(result.model_dump())
            counts[result.status.value] += 1
            
            if (i + 1) % 5 == 0 or i == len(emails) - 1:
                await db.validation_jobs.update_one(
                    {"id": job_id},
                    {"$set": {
                        "processed_emails": i + 1,
                        "valid_count": counts["valid"],
                        "invalid_count": counts["invalid"],
                        "risky_count": counts["risky"],
                        "unknown_count": counts["unknown"],
                        "results": results
                    }}
                )
        
        await db.validation_jobs.update_one(
            {"id": job_id},
            {"$set": {"status": JobStatus.COMPLETED, "completed_at": datetime.now(timezone.utc).isoformat()}}
        )
        logger.info(f"Job {job_id} done: {counts}")
    except Exception as e:
        logger.error(f"Job {job_id} failed: {e}")
        await db.validation_jobs.update_one({"id": job_id}, {"$set": {"status": JobStatus.FAILED}})

# ============================================
# API ROUTES
# ============================================

@api_router.get("/")
async def root():
    return {"message": "Email Validator API v3.0 - Advanced"}

@api_router.post("/validate/single")
async def validate_single(email: str):
    return (await validate_email(email)).model_dump()

@api_router.post("/validate/bulk")
async def validate_bulk(request: BulkValidateRequest, background_tasks: BackgroundTasks):
    emails = list(set(e.strip() for e in request.emails if e.strip() and '@' in e))
    if not emails:
        raise HTTPException(400, "No valid emails")
    if len(emails) > 10000:
        raise HTTPException(400, "Max 10,000 emails")
    
    job = ValidationJob(total_emails=len(emails))
    doc = job.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.validation_jobs.insert_one(doc)
    background_tasks.add_task(process_job, job.id, emails)
    return {"job_id": job.id, "total_emails": len(emails), "status": job.status}

@api_router.post("/validate/upload")
async def validate_upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(400, "CSV only")
    
    content = await file.read()
    emails = list(set(
        cell.strip().lower() 
        for row in csv.reader(io.StringIO(content.decode('utf-8'))) 
        for cell in row 
        if '@' in cell.strip()
    ))
    
    if not emails:
        raise HTTPException(400, "No emails found")
    if len(emails) > 10000:
        raise HTTPException(400, "Max 10,000")
    
    job = ValidationJob(total_emails=len(emails))
    doc = job.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.validation_jobs.insert_one(doc)
    background_tasks.add_task(process_job, job.id, emails)
    return {"job_id": job.id, "total_emails": len(emails), "status": job.status}

@api_router.get("/validate/job/{job_id}")
async def get_job(job_id: str):
    job = await db.validation_jobs.find_one({"id": job_id}, {"_id": 0})
    if not job:
        raise HTTPException(404, "Not found")
    return job

@api_router.get("/validate/job/{job_id}/export")
async def export_job(job_id: str, status_filter: Optional[str] = None):
    job = await db.validation_jobs.find_one({"id": job_id}, {"_id": 0})
    if not job:
        raise HTTPException(404, "Not found")
    if job['status'] != JobStatus.COMPLETED:
        raise HTTPException(400, "Not completed")
    
    results = job.get('results', [])
    if status_filter:
        results = [r for r in results if r['status'] == status_filter]
    
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(['Email', 'Status', 'Confidence', 'Mailbox', 'Provider', 'Disposable', 'Reason'])
    for r in results:
        w.writerow([r['email'], r['status'], f"{r['confidence']}%", r['mailbox_status'], 
                   r['provider_type'], r['is_disposable'], r['reason']])
    
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                            headers={"Content-Disposition": f"attachment; filename=validation_{job_id}.csv"})

@api_router.get("/validate/jobs")
async def list_jobs(limit: int = 20):
    return await db.validation_jobs.find({}, {"_id": 0, "results": 0}).sort("created_at", -1).to_list(limit)

app.include_router(api_router)
app.add_middleware(CORSMiddleware, allow_credentials=True,
                   allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
                   allow_methods=["*"], allow_headers=["*"])

@app.on_event("shutdown")
async def shutdown():
    client.close()
