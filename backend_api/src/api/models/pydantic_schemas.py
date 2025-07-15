"""
Pydantic models for request and response validation. Mirrors ORM but without sensitive/internal fields.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime

# -------- USER SCHEMA --------
# PUBLIC_INTERFACE
class UserBase(BaseModel):
    email: EmailStr = Field(..., description="The user's email address")
    full_name: Optional[str] = Field(None, description="Full name of the user")
    role: Optional[str] = Field('staff', description="Role of the user in the platform")

# PUBLIC_INTERFACE
class UserCreate(UserBase):
    password: str = Field(..., description="Password for the user account")

# PUBLIC_INTERFACE
class UserRead(UserBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True

# -------- VENUE SCHEMA --------
# PUBLIC_INTERFACE
class VenueBase(BaseModel):
    name: str = Field(..., description="Venue name")
    address: Optional[str] = Field(None, description="Venue address")

# PUBLIC_INTERFACE
class VenueCreate(VenueBase):
    pass

# PUBLIC_INTERFACE
class VenueRead(VenueBase):
    id: int
    owner_id: Optional[int]
    created_at: datetime

    class Config:
        orm_mode = True

# -------- EVENT SCHEMA --------
# PUBLIC_INTERFACE
class EventBase(BaseModel):
    name: str
    description: Optional[str]
    start_datetime: datetime
    end_datetime: Optional[datetime]

# PUBLIC_INTERFACE
class EventCreate(EventBase):
    venue_id: int

# PUBLIC_INTERFACE
class EventRead(EventBase):
    id: int
    venue_id: int
    created_at: datetime

    class Config:
        orm_mode = True

# -------- SUSTAINABILITY METRIC SCHEMA --------
# PUBLIC_INTERFACE
class SustainabilityMetricBase(BaseModel):
    name: str
    description: Optional[str]
    unit: str

# PUBLIC_INTERFACE
class SustainabilityMetricCreate(SustainabilityMetricBase):
    pass

# PUBLIC_INTERFACE
class SustainabilityMetricRead(SustainabilityMetricBase):
    id: int

    class Config:
        orm_mode = True

# -------- EVENT SUSTAINABILITY DATA SCHEMA --------
# PUBLIC_INTERFACE
class EventSustainabilityDataBase(BaseModel):
    metric_id: int
    value: float
    reported_at: Optional[datetime]

# PUBLIC_INTERFACE
class EventSustainabilityDataCreate(EventSustainabilityDataBase):
    event_id: int

# PUBLIC_INTERFACE
class EventSustainabilityDataRead(EventSustainabilityDataBase):
    id: int
    event_id: int

    class Config:
        orm_mode = True

# --------- IMPACT REPORT SCHEMA ---------
# PUBLIC_INTERFACE
class ImpactReportBase(BaseModel):
    event_id: int
    report_data: str

# PUBLIC_INTERFACE
class ImpactReportCreate(ImpactReportBase):
    requested_by: int

# PUBLIC_INTERFACE
class ImpactReportRead(ImpactReportBase):
    id: int
    requested_by: int
    generated_at: datetime

    class Config:
        orm_mode = True
