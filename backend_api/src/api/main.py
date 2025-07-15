"""
FastAPI Backend API for Event Impact Insights SaaS Platform

Features:
- User registration, login/authentication (JWT)
- CRUD for Users, Venues, Events, Sustainability Metrics, Event Data
- Sustainability metric submission
- Impact report generation endpoint
- OpenAPI schema with rich descriptions

All endpoints prefixed with tags, docstrings, and Pydantic schemas.
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from src.api.database import get_db
from src.api.models import orm_models
from src.api.models.pydantic_schemas import (
    UserCreate, UserRead,
    VenueCreate, VenueRead,
    EventCreate, EventRead,
    SustainabilityMetricCreate, SustainabilityMetricRead,
    EventSustainabilityDataCreate, EventSustainabilityDataRead,
    ImpactReportCreate, ImpactReportRead
)

import os

# Project-level JWT secret (recommend storing as environment variable for production)
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-key")
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 120

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# FastAPI app config
app = FastAPI(
    title="Event Impact Insights API",
    description="REST API for event venues to manage sustainability data and generate impact reports.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Authentication", "description": "User signup, login and JWT authentication."},
        {"name": "Users", "description": "Manage platform users."},
        {"name": "Venues", "description": "Manage event venues."},
        {"name": "Events", "description": "Manage events hosted at venues."},
        {"name": "Metrics", "description": "Define and submit sustainability metrics."},
        {"name": "Data", "description": "Submit sustainability data for events."},
        {"name": "Reports", "description": "Generate and fetch event impact reports."}
    ]
)

# Restrict CORS in development to the React frontend. For production, change to your deployed frontend domain.
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Auth utils ---

# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against hash."""
    return pwd_context.verify(plain_password, hashed_password)

# PUBLIC_INTERFACE
def get_password_hash(password: str) -> str:
    """Hash a new password string."""
    return pwd_context.hash(password)

# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

# PUBLIC_INTERFACE
def get_user_by_email(db: Session, email: str):
    """Get a user by email address."""
    return db.query(orm_models.User).filter(orm_models.User.email == email).first()

# PUBLIC_INTERFACE
def authenticate_user(db: Session, email: str, password: str):
    """Check credentials and return user if correct."""
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

# PUBLIC_INTERFACE
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Validate JWT and fetch current user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(db, email)
    if user is None:
        raise credentials_exception
    return user

# PUBLIC_INTERFACE
def require_admin(user: orm_models.User = Depends(get_current_user)):
    """Ensure current user is admin."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")
    return user

# --- Health Check ---
@app.get("/", tags=["Health"])
def health_check():
    """Basic health check endpoint."""
    return {"message": "Healthy"}

# ---------- AUTHENTICATION ROUTES ----------

@app.post("/auth/register", response_model=UserRead, tags=["Authentication"], summary="Register a new user")
def register_user(user_create: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user with email and password.
    """
    if get_user_by_email(db, user_create.email):
        raise HTTPException(status_code=400, detail="Email already registered.")
    hashed_password = get_password_hash(user_create.password)
    user_obj = orm_models.User(
        email=user_create.email,
        hashed_password=hashed_password,
        full_name=user_create.full_name,
        role=user_create.role,
    )
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    return user_obj

@app.post("/auth/token", tags=["Authentication"], summary="Login to get JWT access token")
def login_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Authenticate and obtain a JWT access token. Use for API authorization.
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# --- User endpoints (Admin) ---
@app.get("/users/", response_model=List[UserRead], tags=["Users"], dependencies=[Depends(require_admin)], summary="List users")
def list_users(db: Session = Depends(get_db)):
    """
    List all users (admin only).
    """
    return db.query(orm_models.User).all()

@app.get("/users/me", response_model=UserRead, tags=["Users"], summary="Current user info")
def get_my_user_info(current_user: orm_models.User = Depends(get_current_user)):
    """
    Get info about the currently authenticated user.
    """
    return current_user

@app.get("/users/{user_id}", response_model=UserRead, tags=["Users"], dependencies=[Depends(require_admin)], summary="Get user by ID")
def get_user(user_id: int, db: Session = Depends(get_db)):
    """
    Get user details by user ID (admin only).
    """
    user = db.query(orm_models.User).filter(orm_models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return user

@app.delete("/users/{user_id}", tags=["Users"], dependencies=[Depends(require_admin)], summary="Delete user")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    """
    Delete user by ID (admin only).
    """
    user = db.query(orm_models.User).filter(orm_models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    db.delete(user)
    db.commit()
    return {"ok": True, "message": "User deleted."}

# --- Venue endpoints ---

@app.post("/venues/", response_model=VenueRead, tags=["Venues"], summary="Create new venue")
def create_venue(venue: VenueCreate, db: Session = Depends(get_db), current_user: orm_models.User = Depends(get_current_user)):
    """
    Create a new venue. User becomes the owner.
    """
    venue_obj = orm_models.Venue(**venue.dict(), owner_id=current_user.id)
    db.add(venue_obj)
    db.commit()
    db.refresh(venue_obj)
    return venue_obj

@app.get("/venues/", response_model=List[VenueRead], tags=["Venues"], summary="List venues")
def list_venues(db: Session = Depends(get_db)):
    """
    List all venues in the system.
    """
    return db.query(orm_models.Venue).all()

@app.get("/venues/{venue_id}", response_model=VenueRead, tags=["Venues"], summary="Get venue by ID")
def get_venue(venue_id: int, db: Session = Depends(get_db)):
    """
    Get details for a specific venue.
    """
    venue = db.query(orm_models.Venue).filter(orm_models.Venue.id == venue_id).first()
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")
    return venue

@app.put("/venues/{venue_id}", response_model=VenueRead, tags=["Venues"], summary="Update venue")
def update_venue(venue_id: int, venue: VenueCreate, db: Session = Depends(get_db), current_user: orm_models.User = Depends(get_current_user)):
    """
    Update a venue's information. Only owner or admin.
    """
    venue_obj = db.query(orm_models.Venue).filter(orm_models.Venue.id == venue_id).first()
    if not venue_obj:
        raise HTTPException(status_code=404, detail="Venue not found")
    if current_user.role != "admin" and venue_obj.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied (must be owner or admin).")
    for k, v in venue.dict().items():
        setattr(venue_obj, k, v)
    db.commit()
    db.refresh(venue_obj)
    return venue_obj

@app.delete("/venues/{venue_id}", tags=["Venues"], summary="Delete venue")
def delete_venue(venue_id: int, db: Session = Depends(get_db), current_user: orm_models.User = Depends(get_current_user)):
    """
    Delete a venue. Only owner or admin.
    """
    venue = db.query(orm_models.Venue).filter(orm_models.Venue.id == venue_id).first()
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")
    if current_user.role != "admin" and venue.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied (must be owner or admin).")
    db.delete(venue)
    db.commit()
    return {"ok": True, "message": "Venue deleted."}

# --- Event endpoints ---

@app.post("/events/", response_model=EventRead, tags=["Events"], summary="Create event")
def create_event(event: EventCreate, db: Session = Depends(get_db), current_user: orm_models.User = Depends(get_current_user)):
    """
    Create a new event at a specific venue.
    """
    venue = db.query(orm_models.Venue).filter(orm_models.Venue.id == event.venue_id).first()
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")
    if current_user.role != "admin" and venue.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied (must be owner or admin).")
    event_obj = orm_models.Event(**event.dict())
    db.add(event_obj)
    db.commit()
    db.refresh(event_obj)
    return event_obj

@app.get("/events/", response_model=List[EventRead], tags=["Events"], summary="List events")
def list_events(db: Session = Depends(get_db), venue_id: Optional[int] = None):
    """
    List events, optionally filtered by venue.
    """
    query = db.query(orm_models.Event)
    if venue_id:
        query = query.filter(orm_models.Event.venue_id == venue_id)
    return query.all()

@app.get("/events/{event_id}", response_model=EventRead, tags=["Events"], summary="Get event by ID")
def get_event(event_id: int, db: Session = Depends(get_db)):
    """
    Get details for a specific event.
    """
    event = db.query(orm_models.Event).filter(orm_models.Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event

@app.put("/events/{event_id}", response_model=EventRead, tags=["Events"], summary="Update event")
def update_event(event_id: int, event: EventCreate, db: Session = Depends(get_db), current_user: orm_models.User = Depends(get_current_user)):
    """
    Update an event. Only venue owner or admin.
    """
    event_obj = db.query(orm_models.Event).filter(orm_models.Event.id == event_id).first()
    if not event_obj:
        raise HTTPException(status_code=404, detail="Event not found")
    venue = db.query(orm_models.Venue).filter(orm_models.Venue.id == event_obj.venue_id).first()
    if current_user.role != "admin" and venue.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied (must be owner or admin).")
    for k, v in event.dict().items():
        setattr(event_obj, k, v)
    db.commit()
    db.refresh(event_obj)
    return event_obj

@app.delete("/events/{event_id}", tags=["Events"], summary="Delete event")
def delete_event(event_id: int, db: Session = Depends(get_db), current_user: orm_models.User = Depends(get_current_user)):
    """
    Delete an event. Only venue owner or admin.
    """
    event_obj = db.query(orm_models.Event).filter(orm_models.Event.id == event_id).first()
    if not event_obj:
        raise HTTPException(status_code=404, detail="Event not found")
    venue = db.query(orm_models.Venue).filter(orm_models.Venue.id == event_obj.venue_id).first()
    if current_user.role != "admin" and venue.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied (must be owner or admin).")
    db.delete(event_obj)
    db.commit()
    return {"ok": True, "message": "Event deleted."}

# ---------- Sustainability Metric endpoints ----------

@app.post("/metrics/", response_model=SustainabilityMetricRead, tags=["Metrics"], dependencies=[Depends(require_admin)], summary="Create new metric")
def create_metric(metric: SustainabilityMetricCreate, db: Session = Depends(get_db)):
    """
    Define a new sustainability metric (admin only).
    """
    existing = db.query(orm_models.SustainabilityMetric).filter(orm_models.SustainabilityMetric.name == metric.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Metric already exists.")
    metric_obj = orm_models.SustainabilityMetric(**metric.dict())
    db.add(metric_obj)
    db.commit()
    db.refresh(metric_obj)
    return metric_obj

@app.get("/metrics/", response_model=List[SustainabilityMetricRead], tags=["Metrics"], summary="List sustainability metrics")
def list_metrics(db: Session = Depends(get_db)):
    """
    List all defined sustainability metrics.
    """
    return db.query(orm_models.SustainabilityMetric).all()

# ---------- Event Sustainability Data ----------

@app.post("/data/", response_model=EventSustainabilityDataRead, tags=["Data"], summary="Submit event metric")
def submit_event_metric(data: EventSustainabilityDataCreate, db: Session = Depends(get_db), current_user: orm_models.User = Depends(get_current_user)):
    """
    Submit a value for a given sustainability metric for a specific event.
    """
    event = db.query(orm_models.Event).filter(orm_models.Event.id == data.event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    metric = db.query(orm_models.SustainabilityMetric).filter(orm_models.SustainabilityMetric.id == data.metric_id).first()
    if not metric:
        raise HTTPException(status_code=404, detail="Metric not found")
    # Check permission: Only admin or owner of venue for this event
    venue = db.query(orm_models.Venue).filter(orm_models.Venue.id == event.venue_id).first()
    if current_user.role != "admin" and venue.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied (must be owner or admin).")
    # Ensure uniqueness: metric_id+event_id
    existing = db.query(orm_models.EventSustainabilityData)\
        .filter(
            orm_models.EventSustainabilityData.event_id == data.event_id,
            orm_models.EventSustainabilityData.metric_id == data.metric_id
        ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Data for this event/metric already submitted.")
    data_obj = orm_models.EventSustainabilityData(**data.dict())
    db.add(data_obj)
    db.commit()
    db.refresh(data_obj)
    return data_obj

@app.get("/data/", response_model=List[EventSustainabilityDataRead], tags=["Data"], summary="List event metric data")
def list_event_metrics(event_id: Optional[int] = None, db: Session = Depends(get_db)):
    """
    List metric submissions (optionally by event).
    """
    query = db.query(orm_models.EventSustainabilityData)
    if event_id:
        query = query.filter(orm_models.EventSustainabilityData.event_id == event_id)
    return query.all()

# ---------- Impact Reports ----------

@app.post("/reports/", response_model=ImpactReportRead, tags=["Reports"], summary="Generate impact report")
def create_impact_report(report_data: ImpactReportCreate, db: Session = Depends(get_db), current_user: orm_models.User = Depends(get_current_user)):
    """
    Generate an impact report for an event. Only admin or venue owner for that event.
    `report_data` can be summary JSON or generated text.
    """
    event = db.query(orm_models.Event).filter(orm_models.Event.id == report_data.event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    venue = db.query(orm_models.Venue).filter(orm_models.Venue.id == event.venue_id).first()
    if current_user.role != "admin" and venue.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied (must be owner or admin).")
    report_obj = orm_models.ImpactReport(
        event_id=report_data.event_id,
        requested_by=current_user.id,
        report_data=report_data.report_data,
    )
    db.add(report_obj)
    db.commit()
    db.refresh(report_obj)
    return report_obj

@app.get("/reports/", response_model=List[ImpactReportRead], tags=["Reports"], summary="Fetch list of impact reports")
def list_impact_reports(db: Session = Depends(get_db), event_id: Optional[int] = None):
    """
    List all impact reports, optionally filtered by event.
    """
    query = db.query(orm_models.ImpactReport)
    if event_id:
        query = query.filter(orm_models.ImpactReport.event_id == event_id)
    return query.all()

@app.get("/reports/{report_id}", response_model=ImpactReportRead, tags=["Reports"], summary="Fetch individual report")
def get_impact_report(report_id: int, db: Session = Depends(get_db)):
    """
    Retrieve a single impact report by ID.
    """
    report = db.query(orm_models.ImpactReport).filter(orm_models.ImpactReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report

# ---------- OpenAPI schema regeneration utility ----------
@app.get("/docs/openapi.json", tags=["Health"], summary="Get the current OpenAPI schema as JSON")
def get_openapi_schema():
    """Return the current OpenAPI schema for documentation tooling."""
    return app.openapi()
