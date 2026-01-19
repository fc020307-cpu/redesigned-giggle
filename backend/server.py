from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, BackgroundTasks, Depends, Request
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from emergentintegrations.payments.stripe.checkout import StripeCheckout, CheckoutSessionRequest
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
import jwt
import bcrypt
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional, Tuple
import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_SECRET = os.environ.get('JWT_SECRET', 'default_secret_key')
STRIPE_API_KEY = os.environ.get('STRIPE_API_KEY', '')

app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================
# PRICING PLANS
# ============================================
PLANS = {
    "free": {"name": "Free", "price": 0, "verifications_per_month": 50, "features": ["50 verifications/month", "Basic support"]},
    "basic": {"name": "Basic", "price": 5.00, "verifications_per_month": 1000, "features": ["1,000 verifications/month", "Email support", "CSV export"]},
    "pro": {"name": "Pro", "price": 15.00, "verifications_per_month": 5000, "features": ["5,000 verifications/month", "Priority support", "API access", "Bulk upload"]},
}

# ============================================
# PROVIDER CLASSIFICATION
# ============================================
VERIFIABLE_PROVIDERS = {
    "gmail.com", "googlemail.com", "google.com",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me", "pm.me",
    "zoho.com", "zohomail.com",
    "fastmail.com", "fastmail.fm",
    "tutanota.com", "tutanota.de", "tutamail.com",
    "hey.com", "runbox.com", "posteo.de", "posteo.net", "mailbox.org",
}

CATCHALL_PROVIDERS = {
    "yahoo.com", "yahoo.co.uk", "yahoo.fr", "ymail.com", "rocketmail.com",
    "aol.com", "aim.com",
    "att.net", "sbcglobal.net", "bellsouth.net",
    "verizon.net", "cox.net", "charter.net", "spectrum.net",
    "earthlink.net", "juno.com", "netzero.com",
}

BLOCKING_PROVIDERS = {
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "gmx.com", "gmx.de", "mail.com",
    "comcast.net", "xfinity.com",
    "mail.ru", "yandex.com", "yandex.ru",
    "163.com", "126.com", "qq.com",
}

DISPOSABLE_DOMAINS = {
    "tempmail.com", "temp-mail.org", "10minutemail.com", "guerrillamail.com",
    "mailinator.com", "throwaway.email", "fakeinbox.com", "trashmail.com",
    "getnada.com", "mohmal.com", "maildrop.cc", "yopmail.com",
    "dispostable.com", "sharklasers.com", "spam4.me", "grr.la",
    "tempail.com", "tmpmail.org", "emailondeck.com", "minutemail.com",
    "tempr.email", "tempinbox.com", "burnermail.io", "mailsac.com",
    "mytemp.email", "getairmail.com", "dropmail.me", "mailcatch.com",
    "trashymail.com", "zehnminuten.de", "spambox.us",
}

# ============================================
# MODELS
# ============================================
class EmailStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    RISKY = "risky"

class JobStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

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

class BulkValidateRequest(BaseModel):
    emails: List[str]

class CheckoutRequest(BaseModel):
    plan_id: str
    origin_url: str

# ============================================
# AUTH HELPERS
# ============================================
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_token(user_id: str, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return None
    payload = decode_token(credentials.credentials)
    if not payload:
        return None
    user = await db.users.find_one({"_id": payload["user_id"]}, {"password": 0})
    return user

async def require_auth(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(401, "Authentication required")
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(401, "Invalid token")
    user = await db.users.find_one({"_id": payload["user_id"]}, {"password": 0})
    if not user:
        raise HTTPException(401, "User not found")
    return user

# ============================================
# EMAIL VALIDATION FUNCTIONS
# ============================================
def get_mx_records(domain: str) -> List[str]:
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return [str(r.exchange).rstrip('.') for r in sorted(records, key=lambda x: x.preference)]
    except:
        return []

def smtp_verify(email: str, mx_host: str) -> Tuple[Optional[bool], str]:
    helo_domains = ['mail.google.com', 'mx.outlook.com', 'smtp.verify.net']
    try:
        smtp = smtplib.SMTP(timeout=12)
        smtp.connect(mx_host, 25)
        smtp.helo(random.choice(helo_domains))
        smtp.mail('verify@verifier.local')
        code, message = smtp.rcpt(email)
        smtp.quit()
        
        msg = message.decode() if isinstance(message, bytes) else str(message)
        
        if code == 250:
            return True, "Mailbox exists"
        elif code == 550:
            not_exist = ["does not exist", "user unknown", "no such user", "mailbox not found", "invalid recipient"]
            if any(p in msg.lower() for p in not_exist):
                return False, "Mailbox does not exist"
            return False, "Mailbox rejected"
        elif code == 552:
            return True, "Mailbox exists (full)"
        return None, f"Unknown ({code})"
    except:
        return None, "Connection failed"

def validate_format(email: str) -> Tuple[bool, str]:
    email = email.strip().lower()
    if not email or len(email) > 254 or email.count('@') != 1:
        return False, "Invalid format"
    local, domain = email.split('@')
    if not local or len(local) > 64 or not domain or '.' not in domain:
        return False, "Invalid format"
    if not re.match(r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+$', local):
        return False, "Invalid characters"
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', domain):
        return False, "Invalid domain"
    return True, "Valid"

def domain_exists(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False

def get_provider_type(domain: str) -> str:
    d = domain.lower()
    if d in VERIFIABLE_PROVIDERS: return "verifiable"
    if d in CATCHALL_PROVIDERS: return "catch_all"
    if d in BLOCKING_PROVIDERS: return "blocked"
    return "unknown"

def validate_email_sync(email: str) -> EmailResult:
    email = email.strip().lower()
    
    format_ok, format_msg = validate_format(email)
    if not format_ok:
        return EmailResult(email=email, status=EmailStatus.INVALID, format_valid=False, domain_valid=False, mx_valid=False, mailbox_status="invalid_format", is_disposable=False, provider_type="unknown", confidence=100, reason=f"Invalid: {format_msg}")
    
    domain = email.split('@')[1]
    disposable = domain in DISPOSABLE_DOMAINS
    provider = get_provider_type(domain)
    
    if not domain_exists(domain):
        return EmailResult(email=email, status=EmailStatus.INVALID, format_valid=True, domain_valid=False, mx_valid=False, mailbox_status="domain_invalid", is_disposable=disposable, provider_type=provider, confidence=100, reason="Invalid: Domain does not exist")
    
    mx_records = get_mx_records(domain)
    if not mx_records:
        return EmailResult(email=email, status=EmailStatus.INVALID, format_valid=True, domain_valid=True, mx_valid=False, mailbox_status="no_mx", is_disposable=disposable, provider_type=provider, confidence=100, reason="Invalid: No mail servers")
    
    if disposable:
        return EmailResult(email=email, status=EmailStatus.RISKY, format_valid=True, domain_valid=True, mx_valid=True, mailbox_status="disposable", is_disposable=True, provider_type=provider, confidence=95, reason="Risky: Disposable email")
    
    mx_host = mx_records[0]
    
    if provider == "verifiable":
        exists, reason = smtp_verify(email, mx_host)
        if exists is True:
            return EmailResult(email=email, status=EmailStatus.VALID, format_valid=True, domain_valid=True, mx_valid=True, mailbox_status="verified", is_disposable=False, provider_type=provider, confidence=99, reason="Valid: Mailbox verified")
        elif exists is False:
            return EmailResult(email=email, status=EmailStatus.INVALID, format_valid=True, domain_valid=True, mx_valid=True, mailbox_status="not_found", is_disposable=False, provider_type=provider, confidence=99, reason=f"Invalid: {reason}")
        return EmailResult(email=email, status=EmailStatus.VALID, format_valid=True, domain_valid=True, mx_valid=True, mailbox_status="unverified", is_disposable=False, provider_type=provider, confidence=85, reason=f"Valid: {domain} can receive email")
    
    elif provider == "catch_all":
        return EmailResult(email=email, status=EmailStatus.VALID, format_valid=True, domain_valid=True, mx_valid=True, mailbox_status="catch_all", is_disposable=False, provider_type=provider, confidence=75, reason=f"Valid: {domain} accepts all")
    
    elif provider == "blocked":
        return EmailResult(email=email, status=EmailStatus.VALID, format_valid=True, domain_valid=True, mx_valid=True, mailbox_status="blocked", is_disposable=False, provider_type=provider, confidence=80, reason=f"Valid: {domain} can receive email")
    
    else:
        exists, reason = smtp_verify(email, mx_host)
        if exists is True:
            return EmailResult(email=email, status=EmailStatus.VALID, format_valid=True, domain_valid=True, mx_valid=True, mailbox_status="verified", is_disposable=False, provider_type="unknown", confidence=90, reason="Valid: Mailbox verified")
        elif exists is False:
            return EmailResult(email=email, status=EmailStatus.INVALID, format_valid=True, domain_valid=True, mx_valid=True, mailbox_status="not_found", is_disposable=False, provider_type="unknown", confidence=90, reason=f"Invalid: {reason}")
        return EmailResult(email=email, status=EmailStatus.VALID, format_valid=True, domain_valid=True, mx_valid=True, mailbox_status="unverified", is_disposable=False, provider_type="unknown", confidence=70, reason="Valid: Domain can receive email")

async def validate_email(email: str) -> EmailResult:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, validate_email_sync, email)

async def process_job(job_id: str, emails: List[str], user_id: Optional[str] = None):
    try:
        await db.validation_jobs.update_one({"id": job_id}, {"$set": {"status": JobStatus.PROCESSING}})
        results = []
        counts = {"valid": 0, "invalid": 0, "risky": 0}
        
        for i, email in enumerate(emails):
            result = await validate_email(email)
            results.append(result.model_dump())
            counts[result.status.value] += 1
            
            if (i + 1) % 5 == 0 or i == len(emails) - 1:
                await db.validation_jobs.update_one({"id": job_id}, {"$set": {"processed_emails": i + 1, "valid_count": counts["valid"], "invalid_count": counts["invalid"], "risky_count": counts["risky"], "results": results}})
        
        await db.validation_jobs.update_one({"id": job_id}, {"$set": {"status": JobStatus.COMPLETED, "completed_at": datetime.now(timezone.utc).isoformat()}})
        
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"verifications_used": len(emails)}})
    except Exception as e:
        logger.error(f"Job {job_id} failed: {e}")
        await db.validation_jobs.update_one({"id": job_id}, {"$set": {"status": JobStatus.FAILED}})

# ============================================
# AUTH ROUTES
# ============================================
@api_router.post("/auth/register")
async def register(data: UserRegister):
    existing = await db.users.find_one({"email": data.email.lower()})
    if existing:
        raise HTTPException(400, "Email already registered")
    
    user_id = str(uuid.uuid4())
    user = {
        "_id": user_id,
        "email": data.email.lower(),
        "name": data.name,
        "password": hash_password(data.password),
        "plan": "free",
        "verifications_used": 0,
        "verifications_limit": PLANS["free"]["verifications_per_month"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "billing_cycle_start": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(user)
    
    token = create_token(user_id, data.email)
    return {"token": token, "user": {"id": user_id, "email": data.email, "name": data.name, "plan": "free"}}

@api_router.post("/auth/login")
async def login(data: UserLogin):
    user = await db.users.find_one({"email": data.email.lower()})
    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(401, "Invalid credentials")
    
    token = create_token(user["_id"], user["email"])
    return {"token": token, "user": {"id": user["_id"], "email": user["email"], "name": user["name"], "plan": user["plan"], "verifications_used": user["verifications_used"], "verifications_limit": user["verifications_limit"]}}

@api_router.get("/auth/me")
async def get_me(user=Depends(require_auth)):
    return {"id": user["_id"], "email": user["email"], "name": user["name"], "plan": user["plan"], "verifications_used": user["verifications_used"], "verifications_limit": user["verifications_limit"]}

# ============================================
# PAYMENT ROUTES
# ============================================
@api_router.get("/plans")
async def get_plans():
    return PLANS

@api_router.post("/checkout/create")
async def create_checkout(data: CheckoutRequest, request: Request, user=Depends(require_auth)):
    if data.plan_id not in PLANS or data.plan_id == "free":
        raise HTTPException(400, "Invalid plan")
    
    plan = PLANS[data.plan_id]
    
    host_url = str(request.base_url).rstrip('/')
    webhook_url = f"{host_url}/api/webhook/stripe"
    stripe_checkout = StripeCheckout(api_key=STRIPE_API_KEY, webhook_url=webhook_url)
    
    success_url = f"{data.origin_url}/payment/success?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{data.origin_url}/pricing"
    
    checkout_request = CheckoutSessionRequest(
        amount=plan["price"],
        currency="usd",
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={"user_id": user["_id"], "plan_id": data.plan_id, "user_email": user["email"]}
    )
    
    session = await stripe_checkout.create_checkout_session(checkout_request)
    
    await db.payment_transactions.insert_one({
        "_id": str(uuid.uuid4()),
        "user_id": user["_id"],
        "session_id": session.session_id,
        "plan_id": data.plan_id,
        "amount": plan["price"],
        "currency": "usd",
        "payment_status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    
    return {"url": session.url, "session_id": session.session_id}

@api_router.get("/checkout/status/{session_id}")
async def checkout_status(session_id: str, request: Request, user=Depends(require_auth)):
    host_url = str(request.base_url).rstrip('/')
    webhook_url = f"{host_url}/api/webhook/stripe"
    stripe_checkout = StripeCheckout(api_key=STRIPE_API_KEY, webhook_url=webhook_url)
    
    status = await stripe_checkout.get_checkout_status(session_id)
    
    tx = await db.payment_transactions.find_one({"session_id": session_id})
    if tx and tx["payment_status"] != status.payment_status:
        await db.payment_transactions.update_one({"session_id": session_id}, {"$set": {"payment_status": status.payment_status, "updated_at": datetime.now(timezone.utc).isoformat()}})
        
        if status.payment_status == "paid" and tx["payment_status"] != "paid":
            plan_id = tx["plan_id"]
            plan = PLANS[plan_id]
            await db.users.update_one({"_id": user["_id"]}, {"$set": {"plan": plan_id, "verifications_limit": plan["verifications_per_month"], "verifications_used": 0, "billing_cycle_start": datetime.now(timezone.utc).isoformat()}})
    
    return {"status": status.status, "payment_status": status.payment_status}

@api_router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("Stripe-Signature")
    
    host_url = str(request.base_url).rstrip('/')
    webhook_url = f"{host_url}/api/webhook/stripe"
    stripe_checkout = StripeCheckout(api_key=STRIPE_API_KEY, webhook_url=webhook_url)
    
    try:
        event = await stripe_checkout.handle_webhook(body, signature)
        
        if event.payment_status == "paid":
            tx = await db.payment_transactions.find_one({"session_id": event.session_id})
            if tx and tx["payment_status"] != "paid":
                await db.payment_transactions.update_one({"session_id": event.session_id}, {"$set": {"payment_status": "paid"}})
                plan_id = event.metadata.get("plan_id")
                user_id = event.metadata.get("user_id")
                if plan_id and user_id:
                    plan = PLANS[plan_id]
                    await db.users.update_one({"_id": user_id}, {"$set": {"plan": plan_id, "verifications_limit": plan["verifications_per_month"], "verifications_used": 0}})
        
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return {"status": "error"}

# ============================================
# VALIDATION ROUTES
# ============================================
@api_router.get("/")
async def root():
    return {"message": "Email Validator API v4.0"}

@api_router.post("/validate/single")
async def validate_single(email: str, user=Depends(get_current_user)):
    if user:
        if user["verifications_used"] >= user["verifications_limit"]:
            raise HTTPException(403, "Verification limit reached. Please upgrade your plan.")
        await db.users.update_one({"_id": user["_id"]}, {"$inc": {"verifications_used": 1}})
    
    result = await validate_email(email)
    return result.model_dump()

@api_router.post("/validate/bulk")
async def validate_bulk(request_data: BulkValidateRequest, background_tasks: BackgroundTasks, user=Depends(get_current_user)):
    emails = list(set(e.strip() for e in request_data.emails if e.strip() and '@' in e))
    if not emails:
        raise HTTPException(400, "No valid emails")
    if len(emails) > 10000:
        raise HTTPException(400, "Max 10,000 emails")
    
    user_id = None
    if user:
        remaining = user["verifications_limit"] - user["verifications_used"]
        if len(emails) > remaining:
            raise HTTPException(403, f"Only {remaining} verifications remaining. Please upgrade.")
        user_id = user["_id"]
    else:
        if len(emails) > 10:
            raise HTTPException(403, "Sign up for free to validate more than 10 emails")
    
    job_id = str(uuid.uuid4())
    job = {"id": job_id, "user_id": user_id, "status": JobStatus.PENDING, "total_emails": len(emails), "processed_emails": 0, "valid_count": 0, "invalid_count": 0, "risky_count": 0, "results": [], "created_at": datetime.now(timezone.utc).isoformat()}
    await db.validation_jobs.insert_one(job)
    background_tasks.add_task(process_job, job_id, emails, user_id)
    return {"job_id": job_id, "total_emails": len(emails), "status": JobStatus.PENDING}

@api_router.post("/validate/upload")
async def validate_upload(background_tasks: BackgroundTasks, file: UploadFile = File(...), user=Depends(get_current_user)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(400, "CSV only")
    
    content = await file.read()
    emails = list(set(cell.strip().lower() for row in csv.reader(io.StringIO(content.decode('utf-8'))) for cell in row if '@' in cell.strip()))
    
    if not emails:
        raise HTTPException(400, "No emails")
    if len(emails) > 10000:
        raise HTTPException(400, "Max 10,000")
    
    user_id = None
    if user:
        remaining = user["verifications_limit"] - user["verifications_used"]
        if len(emails) > remaining:
            raise HTTPException(403, f"Only {remaining} verifications remaining")
        user_id = user["_id"]
    else:
        if len(emails) > 10:
            raise HTTPException(403, "Sign up for free to validate more")
    
    job_id = str(uuid.uuid4())
    job = {"id": job_id, "user_id": user_id, "status": JobStatus.PENDING, "total_emails": len(emails), "processed_emails": 0, "valid_count": 0, "invalid_count": 0, "risky_count": 0, "results": [], "created_at": datetime.now(timezone.utc).isoformat()}
    await db.validation_jobs.insert_one(job)
    background_tasks.add_task(process_job, job_id, emails, user_id)
    return {"job_id": job_id, "total_emails": len(emails), "status": JobStatus.PENDING}

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
        w.writerow([r['email'], r['status'], f"{r['confidence']}%", r['mailbox_status'], r['provider_type'], r['is_disposable'], r['reason']])
    
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=validation_{job_id}.csv"})

@api_router.get("/validate/jobs")
async def list_jobs(user=Depends(require_auth)):
    jobs = await db.validation_jobs.find({"user_id": user["_id"]}, {"_id": 0, "results": 0}).sort("created_at", -1).to_list(20)
    return jobs

app.include_router(api_router)
app.add_middleware(CORSMiddleware, allow_credentials=True, allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','), allow_methods=["*"], allow_headers=["*"])

@app.on_event("shutdown")
async def shutdown():
    client.close()
