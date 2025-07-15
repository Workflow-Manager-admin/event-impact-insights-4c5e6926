"""
Defines SQLAlchemy ORM models for the event impact SaaS platform.
Models: User, Venue, Event, SustainabilityMetric, EventSustainabilityData, ImpactReport
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
from src.api.database import Base

# PUBLIC_INTERFACE
class User(Base):
    """A user of the platform (admin, staff, etc)."""
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default='staff')  # staff, admin, venue_manager
    created_at = Column(DateTime, default=datetime.utcnow)

    venues = relationship("Venue", back_populates="owner")
    reports = relationship("ImpactReport", back_populates="requested_by_user")

# PUBLIC_INTERFACE
class Venue(Base):
    """A venue using the platform."""
    __tablename__ = 'venues'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    address = Column(String(255), nullable=True)
    owner_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="venues")
    events = relationship("Event", back_populates="venue")

# PUBLIC_INTERFACE
class Event(Base):
    """Represents an individual event."""
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True, index=True)
    venue_id = Column(Integer, ForeignKey('venues.id'), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    start_datetime = Column(DateTime, nullable=False)
    end_datetime = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    venue = relationship("Venue", back_populates="events")
    sustainability_data = relationship("EventSustainabilityData", back_populates="event")
    reports = relationship("ImpactReport", back_populates="event")

# PUBLIC_INTERFACE
class SustainabilityMetric(Base):
    """Definition of tracked sustainability metrics (e.g., energy, waste, water)."""
    __tablename__ = 'sustainability_metrics'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    unit = Column(String(50), nullable=False)

    event_data = relationship("EventSustainabilityData", back_populates="metric")

# PUBLIC_INTERFACE
class EventSustainabilityData(Base):
    """Data values for a given sustainability metric for a specific event."""
    __tablename__ = 'event_sustainability_data'
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey('events.id'), nullable=False)
    metric_id = Column(Integer, ForeignKey('sustainability_metrics.id'), nullable=False)
    value = Column(Float, nullable=False)
    reported_at = Column(DateTime, default=datetime.utcnow)

    event = relationship("Event", back_populates="sustainability_data")
    metric = relationship("SustainabilityMetric", back_populates="event_data")

    __table_args__ = (UniqueConstraint('event_id', 'metric_id', name='_event_metric_uc'),)

# PUBLIC_INTERFACE
class ImpactReport(Base):
    """Impact report generated for an event."""
    __tablename__ = 'impact_reports'
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey('events.id'))
    requested_by = Column(Integer, ForeignKey('users.id'))
    report_data = Column(Text, nullable=False)  # Serialized JSON blob or summary
    generated_at = Column(DateTime, default=datetime.utcnow)

    event = relationship("Event", back_populates="reports")
    requested_by_user = relationship("User", back_populates="reports")
