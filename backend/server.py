from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import re
import csv
import io
import httpx
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

# Abstract API configuration
ABSTRACT_API_KEY = os.environ.get('ABSTRACT_API_KEY', '')
ABSTRACT_API_URL = "https://emailvalidation.abstractapi.com/v1"

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
    is_free_email: bool = False
    is_catchall: bool = False
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

# Email validation functions
def validate_email_format(email: str) -> bool:
    """Validate email format using regex"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email.strip().lower()))

async def validate_with_abstract_api(email: str) -> Optional[dict]:
    """Validate email using Abstract API for accurate results"""
    if not ABSTRACT_API_KEY:
        logger.warning("Abstract API key not configured")
        return None
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                ABSTRACT_API_URL,
                params={
                    "api_key": ABSTRACT_API_KEY,
                    "email": email
                }
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                logger.warning("Abstract API rate limit exceeded")
                return None
            else:
                logger.error(f"Abstract API error: {response.status_code}")
                return None
                
    except Exception as e:
        logger.error(f"Abstract API request failed: {str(e)}")
        return None

def parse_abstract_api_response(email: str, api_result: dict) -> EmailResult:
    """Parse Abstract API response into our EmailResult format"""
    deliverability = api_result.get("deliverability", "UNKNOWN")
    quality_score = api_result.get("quality_score", 0) or 0
    
    # Extract boolean fields safely
    is_valid_format = api_result.get("is_valid_format", {})
    format_valid = is_valid_format.get("value", False) if isinstance(is_valid_format, dict) else bool(is_valid_format)
    
    is_mx_found = api_result.get("is_mx_found", {})
    mx_valid = is_mx_found.get("value", False) if isinstance(is_mx_found, dict) else bool(is_mx_found)
    
    is_smtp_valid = api_result.get("is_smtp_valid", {})
    smtp_valid = is_smtp_valid.get("value", None) if isinstance(is_smtp_valid, dict) else is_smtp_valid
    
    is_disposable = api_result.get("is_disposable_email", {})
    disposable = is_disposable.get("value", False) if isinstance(is_disposable, dict) else bool(is_disposable)
    
    is_free = api_result.get("is_free_email", {})
    free_email = is_free.get("value", False) if isinstance(is_free, dict) else bool(is_free)
    
    is_catchall = api_result.get("is_catchall_email", {})
    catchall = is_catchall.get("value", False) if isinstance(is_catchall, dict) else bool(is_catchall)
    
    # Determine status based on deliverability
    if deliverability == "DELIVERABLE":
        if disposable:
            status = EmailStatus.RISKY
            reason = "Disposable/temporary email - deliverable but risky"
        elif catchall:
            status = EmailStatus.RISKY
            reason = "Catch-all domain - cannot confirm mailbox exists"
        else:
            status = EmailStatus.VALID
            reason = "Email verified - deliverable"
    elif deliverability == "UNDELIVERABLE":
        status = EmailStatus.INVALID
        reason = "Email undeliverable - mailbox does not exist"
    elif deliverability == "RISKY":
        status = EmailStatus.RISKY
        reason = "Risky email - may have deliverability issues"
    else:  # UNKNOWN
        if quality_score >= 0.7:
            status = EmailStatus.RISKY
            reason = "Could not fully verify - likely valid based on quality score"
        else:
            status = EmailStatus.UNKNOWN
            reason = "Could not determine email validity"
    
    return EmailResult(
        email=email,
        status=status,
        format_valid=format_valid,
        domain_valid=mx_valid,  # If MX exists, domain is valid
        mx_valid=mx_valid,
        smtp_valid=smtp_valid,
        is_disposable=disposable,
        is_free_email=free_email,
        is_catchall=catchall,
        quality_score=quality_score,
        reason=reason
    )

async def validate_single_email(email: str) -> EmailResult:
    """Perform full validation on a single email using Abstract API"""
    email = email.strip().lower()
    
    # Basic format check first
    if not validate_email_format(email):
        return EmailResult(
            email=email,
            status=EmailStatus.INVALID,
            format_valid=False,
            domain_valid=False,
            mx_valid=False,
            smtp_valid=None,
            is_disposable=False,
            is_free_email=False,
            is_catchall=False,
            quality_score=0.0,
            reason="Invalid email format"
        )
    
    # Use Abstract API for accurate validation
    api_result = await validate_with_abstract_api(email)
    
    if api_result:
        return parse_abstract_api_response(email, api_result)
    else:
        # Fallback: return unknown if API unavailable
        return EmailResult(
            email=email,
            status=EmailStatus.UNKNOWN,
            format_valid=True,
            domain_valid=False,
            mx_valid=False,
            smtp_valid=None,
            is_disposable=False,
            is_free_email=False,
            is_catchall=False,
            quality_score=0.0,
            reason="Could not validate - API unavailable. Please check API key."
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
            result = await validate_single_email(email)
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
            
            # Update progress every 5 emails or at the end
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
    writer.writerow(['Email', 'Status', 'Quality Score', 'Format Valid', 'MX Valid', 'SMTP Valid', 'Disposable', 'Free Email', 'Catch-all', 'Reason'])
    
    for result in results:
        writer.writerow([
            result['email'],
            result['status'],
            result.get('quality_score', 0),
            result['format_valid'],
            result['mx_valid'],
            result.get('smtp_valid', ''),
            result['is_disposable'],
            result.get('is_free_email', False),
            result.get('is_catchall', False),
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
